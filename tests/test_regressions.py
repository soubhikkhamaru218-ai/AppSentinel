"""
AppSentinel // Security & Resilience Regression Tests
Verifies fixes for:
- MobSF server outages and connection errors (no clean bias)
- VirusTotal and urlscan.io rate limits (HTTP 429 -> rate_limited)
- Gemini timeouts / failures (unavailable, no hallucinated text)
- SSRF internal loopback / metadata / private IP protection
- Uploaded file immediate cleanup after scan endpoint execution
- Scan endpoint rate limiting
- Safe CORS origin enforcement
"""

import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import zipfile
import httpx
from fastapi.testclient import TestClient

from backend.main import app, get_allowed_origins, _scan_rate_records
from backend.config import get_settings
from backend.services.mobsf_service import scan_apk_with_mobsf
from backend.services.virustotal_service import check_url as vt_check_url, check_file_hash as vt_check_file_hash
from backend.services.urlscan_service import search_url as urlscan_search_url
from backend.services.url_analyzer import analyze_url
from backend.services.scan_orchestrator import run_scan


class TestSecurityAndResilienceRegressions(unittest.IsolatedAsyncioTestCase):

    # ── 1. MOBSF SERVER OUTAGE / CONNECTION ERROR ────────────────────────────
    def test_mobsf_connection_refused_returns_unavailable(self):
        """When MobSF is offline, it must return status=unavailable without fabricating clean findings."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"PK\x03\x04" + b"\x00" * 200)
            dummy_apk = f.name

        try:
            with patch("httpx.Client.post", side_effect=httpx.ConnectError("Connection refused")):
                res = scan_apk_with_mobsf(
                    apk_filepath=dummy_apk,
                    server_url="http://127.0.0.1:8001",
                    api_key="secret",
                )
                self.assertEqual(res["status"], "unavailable")
                self.assertFalse(res.get("available", False))
                self.assertIn("connection", res.get("reason", "").lower())
                self.assertNotIn("verdict", res)
        finally:
            Path(dummy_apk).unlink(missing_ok=True)

    # ── 2. VIRUSTOTAL RATE LIMIT (HTTP 429) ──────────────────────────────────
    def test_virustotal_rate_limit_handled_without_clean_verdict(self):
        """VirusTotal HTTP 429 must return rate_limited status instead of pretending the target is clean."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("httpx.Client.get", return_value=mock_resp):
            res_url = vt_check_url("https://example.com", api_key="valid-key")
            self.assertTrue(res_url.get("rate_limited"))
            self.assertEqual(res_url.get("status"), "rate_limited")

            res_hash = vt_check_file_hash("a" * 64, api_key="valid-key")
            self.assertTrue(res_hash.get("rate_limited"))
            self.assertEqual(res_hash.get("status"), "rate_limited")

    # ── 3. URLSCAN RATE LIMIT (HTTP 429) ─────────────────────────────────────
    def test_urlscan_rate_limit_handled_without_clean_verdict(self):
        """urlscan.io HTTP 429 must return rate_limited status instead of empty clean verdict."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("httpx.Client.get", return_value=mock_resp):
            res = urlscan_search_url("https://example.com", api_key="valid-key")
            self.assertTrue(res.get("rate_limited"))
            self.assertEqual(res.get("status"), "rate_limited")

    # ── 4. GEMINI FAILURE / TIMEOUT FALLBACK ─────────────────────────────────
    async def test_gemini_error_produces_unavailable_ai_status(self):
        """When Gemini API fails or times out, ai status is unavailable and no text is fabricated."""
        with patch.object(get_settings(), "gemini_api_key", "mock-key"):
            with patch("backend.services.ai_explanation_service.generate_ai_explanation", side_effect=Exception("API Timeout")):
                res = await run_scan(
                    message="URGENT: Your account is blocked. Share your OTP immediately to restore access.",
                    scan_mode="message",
                )
                self.assertEqual(res.ai.status, "unavailable")
                self.assertEqual(res.ai.summary, "")
                self.assertEqual(res.ai.why_it_matters, [])
                # Deterministic verdict is preserved
                self.assertIn(res.verdict.label, ["HIGH_RISK", "SUSPICIOUS"])

    async def test_gemini_timeout_is_bounded_by_orchestrator(self):
        """Slow AI explanation must not prevent deterministic scan results from returning."""
        async def slow_ai(*args, **kwargs):
            import asyncio
            await asyncio.sleep(0.05)

        with patch.object(get_settings(), "gemini_api_key", "mock-key"), \
             patch.object(get_settings(), "ai_total_timeout_seconds", 0.01), \
             patch("backend.services.ai_explanation_service.generate_ai_explanation", side_effect=slow_ai):
            res = await run_scan(
                message="URGENT: Your account is blocked. Share your OTP immediately.",
                scan_mode="message",
            )

            self.assertEqual(res.ai.status, "unavailable")
            self.assertIn("timed out", res.ai.reason)
            self.assertEqual(res.ai.summary, "")
            self.assertIn(res.verdict.label, ["HIGH_RISK", "SUSPICIOUS"])

    # ── 5. SSRF INTERNAL ADDRESS PROTECTION ──────────────────────────────────
    def test_ssrf_internal_address_detection(self):
        """Internal, loopback, link-local, and RFC 1918 IPs must be flagged as internal targets."""
        targets = [
            "http://127.0.0.1:8000/internal",
            "http://localhost:8088/secret",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/admin",
            "http://192.168.1.1/router",
            "http://172.16.0.5/docker",
        ]
        for target in targets:
            url_res = analyze_url(target)
            self.assertIn(
                "internal_network_target",
                url_res.suspicious_keywords_found,
                f"Target {target} should be identified as internal network target",
            )

            # VT and urlscan must skip lookups for internal targets
            vt_res = vt_check_url(target, api_key="any-key")
            self.assertEqual(vt_res.get("status"), "skipped")

            uscan_res = urlscan_search_url(target, api_key="any-key")
            self.assertEqual(uscan_res.get("status"), "skipped")

    # ── 6. UPLOADED FILE IMMEDIATE CLEANUP ───────────────────────────────────
    def test_uploaded_file_cleaned_up_after_scan_endpoint(self):
        """Files uploaded to /api/scan/apk must be deleted from storage/uploads after response."""
        client = TestClient(app)

        # Create a valid minimal APK in-memory
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest package='com.test.cleanup'></manifest>")
            zf.writestr("classes.dex", b"DEX\n035\x00" + b"\x00" * 50)
        apk_bytes = bio.getvalue()

        upload_dir = get_settings().upload_path
        files_before = set(upload_dir.glob("*"))

        response = client.post(
            "/api/scan/apk",
            files={"file": ("cleanup_test.apk", apk_bytes, "application/vnd.android.package-archive")},
            data={"identity": "TestApp"},
        )
        self.assertEqual(response.status_code, 200)

        files_after = set(upload_dir.glob("*"))
        # Verify no residual files were left in the upload directory
        diff = files_after - files_before
        self.assertEqual(len(diff), 0, f"Residual uploaded files found after scan: {diff}")

    async def test_orchestrator_uses_bounded_mobsf_budget(self):
        """APK scans must call MobSF with bounded best-effort timeout settings."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            with zipfile.ZipFile(f.name, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("AndroidManifest.xml", b"<manifest package='com.test.timeout'></manifest>")
                zf.writestr("classes.dex", b"DEX\n035\x00")
            apk_path = Path(f.name)

        try:
            with patch.object(get_settings(), "mobsf_timeout_seconds", 3.0), \
                 patch.object(get_settings(), "mobsf_max_retries", 0), \
                 patch("backend.services.scan_orchestrator.scan_apk_with_mobsf") as mock_mobsf:
                mock_mobsf.return_value = {
                    "source": "mobsf",
                    "status": "unavailable",
                    "reason": "test timeout",
                    "available": False,
                }

                res = await run_scan(apk_path=apk_path, scan_mode="apk")

                self.assertEqual(res.scan_mode, "apk")
                self.assertEqual(mock_mobsf.call_args.kwargs["timeout"], 3.0)
                self.assertEqual(mock_mobsf.call_args.kwargs["max_retries"], 0)
        finally:
            apk_path.unlink(missing_ok=True)


class TestCorsAndMiddleware(unittest.TestCase):

    def test_cors_headers_with_allowed_origin(self):
        """Allowed origin receives proper CORS response headers."""
        client = TestClient(app)
        response = client.get(
            "/api/health",
            headers={"Origin": "http://localhost:8088"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("access-control-allow-origin"), "http://localhost:8088")
        self.assertEqual(response.headers.get("access-control-allow-credentials"), "true")

    def test_production_cors_does_not_auto_allow_dev_ports(self):
        """Production origin list should not implicitly include localhost dev ports."""
        with patch.object(get_settings(), "app_env", "production"), \
             patch.object(get_settings(), "frontend_origin", "https://app.example"), \
             patch.object(get_settings(), "cors_origins", ""):
            origins = get_allowed_origins()

        self.assertEqual(origins, ["https://app.example"])
        self.assertNotIn("http://localhost:3000", origins)

    def test_scan_rate_limit_is_configurable(self):
        """Configured scan rate limit should reject excess scan submissions."""
        client = TestClient(app)
        _scan_rate_records.clear()
        payload = {"message": "hello", "identity": ""}

        with patch.object(get_settings(), "scan_rate_limit_max", 1), \
             patch.object(get_settings(), "scan_rate_limit_window_seconds", 60.0):
            first = client.post("/api/scan/message", json=payload)
            second = client.post("/api/scan/message", json=payload)

        _scan_rate_records.clear()
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)


if __name__ == "__main__":
    unittest.main()
