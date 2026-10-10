"""
AppSentinel // Comprehensive Scenario Test Suite
Covers all critical requirements:
- google.com must NOT become INSUFFICIENT_EVIDENCE
- normal HTTPS domain
- suspicious-looking domain
- message containing urgency
- message requesting OTP
- URL + message correlation
- APK analyzed by Androguard
- APK analyzed by MobSF
- MobSF unavailable must NOT be interpreted as 'clean'
- Gemini unavailable must NOT create fake AI output
- VirusTotal unavailable / not configured
- urlscan unavailable / not configured
- no analyzer evidence
- multiple correlated suspicious signals
"""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import zipfile

from backend.api.schemas import (
    ApkAnalysisResult,
    InputCoverage,
    MessageAnalysisResult,
    UrlAnalysisResult,
)
from backend.services.correlation_engine import correlate
from backend.services.message_analyzer import analyze_message
from backend.services.url_analyzer import analyze_url
from backend.services.mobsf_service import scan_apk_with_mobsf, _normalize_mobsf_report
from backend.services.androguard_service import analyze_apk_file
from backend.config import get_settings
from backend.services.scan_orchestrator import run_scan


class TestComprehensiveScenarios(unittest.IsolatedAsyncioTestCase):

    # ── 1. GOOGLE.COM CRITICAL TEST ──────────────────────────────────────────
    async def test_google_com_must_not_become_insufficient_evidence(self):
        """CRITICAL: google.com must evaluate to LOW_CONCERN, not INSUFFICIENT_EVIDENCE."""
        res = await run_scan(url="https://google.com", scan_mode="url")

        self.assertEqual(res.verdict.label, "LOW_CONCERN")
        self.assertGreaterEqual(res.confidence, 0.85)
        self.assertEqual(res.triggered_rules, [])
        self.assertIn("URL Analyzer", [p.name for p in res.pipeline])
        # Verify positive findings present in URL analysis
        url_data = res.analyzers.get("url", {})
        self.assertIsNone(url_data.get("ssl_valid"))
        self.assertTrue(url_data.get("raw_parse", {}).get("https_scheme"))
        self.assertFalse(url_data.get("raw_parse", {}).get("certificate_validation_performed"))
        self.assertFalse(url_data.get("is_ip_host"))
        self.assertFalse(url_data.get("is_apk_download"))

    # ── 2. NORMAL HTTPS DOMAIN ───────────────────────────────────────────────
    async def test_normal_https_domain(self):
        """Standard valid HTTPS domain evaluates cleanly without triggering threat rules."""
        res = await run_scan(url="https://github.com", scan_mode="url")
        self.assertEqual(res.verdict.label, "LOW_CONCERN")
        self.assertEqual(len(res.triggered_rules), 0)

    # ── 3. SUSPICIOUS LOOKING DOMAIN ─────────────────────────────────────────
    async def test_suspicious_looking_domain(self):
        """Domain with phishing keywords and deceptive TLD triggers R5 and SUSPICIOUS verdict."""
        res = await run_scan(url="https://secure-login-verify-account.xyz/update", scan_mode="url")
        self.assertEqual(res.verdict.label, "SUSPICIOUS")
        self.assertIn("R5", res.triggered_rules)
        self.assertTrue(res.analyzers["url"]["has_suspicious_keywords"])

    # ── 4. MESSAGE CONTAINING URGENCY ────────────────────────────────────────
    def test_message_containing_urgency(self):
        """Message with urgency and threat detected deterministically."""
        msg = "URGENT: Your account access will be terminated within 24 hours. Act now."
        res = analyze_message(msg)
        self.assertTrue(res.has_urgency)
        self.assertTrue(res.has_threat)
        self.assertFalse(res.has_otp_request)
        self.assertFalse(res.has_install_instruction)

    # ── 5. MESSAGE REQUESTING OTP ────────────────────────────────────────────
    def test_message_requesting_otp(self):
        """Message requesting OTP with urgency triggers R4 Credential Harvesting Under Duress."""
        msg = "URGENT: Your debit card is blocked. Reply immediately with your 6-digit OTP code to unfreeze."
        msg_res = analyze_message(msg)
        self.assertTrue(msg_res.has_otp_request)
        self.assertTrue(msg_res.has_urgency)

        corr = correlate(message_result=msg_res)
        self.assertIn("R4", corr["triggered_rules"])
        self.assertIn(corr["verdict"], ["HIGH_RISK", "SUSPICIOUS"])

    # ── 6. URL + MESSAGE CORRELATION ─────────────────────────────────────────
    async def test_url_plus_message_correlation(self):
        """Message and URL correlated against claimed identity triggers R2 (Mismatch) and R5."""
        res = await run_scan(
            message="Your State Bank account is suspended. Verify KYC at link immediately.",
            identity="State Bank",
            url="http://statebank-kyc-verify.net/login",
            scan_mode="full",
        )
        self.assertIn("R2", res.triggered_rules)
        self.assertIn(res.verdict.label, ["HIGH_RISK", "SUSPICIOUS"])

    # ── 7. APK ANALYZED BY ANDROGUARD ────────────────────────────────────────
    def test_apk_analyzed_by_androguard(self):
        """Real APK zip parsed by Androguard extracts hashes, permissions, and metadata."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            with zipfile.ZipFile(f.name, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("AndroidManifest.xml", b"<manifest package='com.sec.test'></manifest>")
                zf.writestr("classes.dex", b"DEX\n035\x00" + b"A" * 50)
            apk_path = Path(f.name)

        try:
            res = analyze_apk_file(apk_path)
            self.assertEqual(res.filename, apk_path.name)
            self.assertTrue(len(res.sha256) == 64)
            self.assertTrue(len(res.md5) == 32)
            self.assertTrue(len(res.sha1) == 40)
        finally:
            if apk_path.exists():
                apk_path.unlink()

    # ── 8. APK ANALYZED BY MOBSF (NORMALIZED STRUCTURE) ──────────────────────
    def test_apk_analyzed_by_mobsf_normalization(self):
        """MobSF output normalization formats findings into exact AppSentinel schema."""
        raw_mobsf = {
            "package_name": "com.fraud.bankapp",
            "security_score": 28,
            "permissions": {
                "android.permission.READ_SMS": {"status": "dangerous"},
                "android.permission.INTERNET": {"status": "normal"},
            },
            "manifest_analysis": {
                "manifest_findings": [
                    {"severity": "high", "title": "Exported Content Provider"},
                    {"severity": "warning", "title": "AllowBackup True"},
                ]
            },
            "trackers": ["Google Firebase", "AppsFlyer"],
            "urls": ["http://phish.attacker-c2.com/exfil"],
        }
        normalized = _normalize_mobsf_report(raw_mobsf, "112233445566778899aabbccddeeff00")

        self.assertEqual(normalized["source"], "mobsf")
        self.assertEqual(normalized["status"], "completed")
        self.assertEqual(normalized["package_name"], "com.fraud.bankapp")
        self.assertEqual(normalized["security_score"], 28)
        self.assertIn("READ_SMS", normalized["dangerous_permissions"])
        self.assertEqual(len(normalized["manifest_findings"]), 2)
        self.assertIn("AppsFlyer", normalized["trackers"])
        self.assertIn("http://phish.attacker-c2.com/exfil", normalized["urls"])

    # ── 9. MOBSF UNAVAILABLE MUST NOT BE INTERPRETED AS CLEAN ────────────────
    def test_mobsf_unavailable_must_not_be_interpreted_as_clean(self):
        """CRITICAL: MobSF unavailable must report status=unavailable and NEVER be treated as clean or safe."""
        # When connection fails:
        res = scan_apk_with_mobsf(
            apk_filepath="nonexistent.apk",
            server_url="http://127.0.0.1:59999",
            api_key="test-key",
            timeout=1.0,
        )
        self.assertNotEqual(res.get("status"), "completed")
        self.assertIn(res.get("status"), ["unavailable", "failed"])
        self.assertFalse(res.get("available", False))
        # Must not fabricate 0 findings or safe verdict
        self.assertNotIn("verdict", res)

    async def test_orchestrator_handles_mobsf_unavailable_without_clean_bias(self):
        """When MobSF is offline, orchestrator accurately logs unavailable in pipeline and adds limitation."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            with zipfile.ZipFile(f.name, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("AndroidManifest.xml", b"<manifest package='com.test'></manifest>")
                zf.writestr("classes.dex", b"DEX\n035\x00")
            apk_path = Path(f.name)

        try:
            with patch("backend.services.scan_orchestrator.scan_apk_with_mobsf") as mock_mobsf:
                mock_mobsf.return_value = {
                    "source": "mobsf",
                    "status": "unavailable",
                    "reason": "MobSF service did not respond (connection refused)",
                    "available": False,
                }
                res = await run_scan(apk_path=apk_path, scan_mode="apk")

                mobsf_step = next((p for p in res.pipeline if p.name == "MobSF"), None)
                self.assertIsNotNone(mobsf_step)
                self.assertEqual(mobsf_step.status, "unavailable")
                self.assertTrue(any("MobSF analysis was unavailable" in lim for lim in res.limitations))
        finally:
            if apk_path.exists():
                apk_path.unlink()

    # ── 10. GEMINI UNAVAILABLE MUST NOT CREATE FAKE AI OUTPUT ────────────────
    async def test_gemini_unavailable_must_not_create_fake_ai_output(self):
        """CRITICAL: When Gemini is unavailable, status is unavailable and no fake AI text is fabricated."""
        with patch.object(get_settings(), "gemini_api_key", ""):
            res = await run_scan(
                message="Meeting tomorrow at 10 AM at the office.",
                scan_mode="message",
            )
            self.assertEqual(res.ai.status, "unavailable")
            self.assertEqual(res.ai.summary, "")
            self.assertEqual(res.ai.why_it_matters, [])
            # The deterministic verdict is still present and valid
            self.assertEqual(res.verdict.label, "LOW_CONCERN")

    # ── 11. VIRUSTOTAL UNAVAILABLE / NOT CONFIGURED ──────────────────────────
    async def test_virustotal_not_configured_graceful(self):
        """When VirusTotal is not configured, pipeline lists not_configured and scan succeeds."""
        with patch.object(get_settings(), "virustotal_api_key", ""):
            res = await run_scan(url="https://google.com", scan_mode="url")
            vt_step = next((p for p in res.pipeline if p.name == "VirusTotal"), None)
            self.assertIsNotNone(vt_step)
            self.assertEqual(vt_step.status, "not_configured")

    # ── 12. URLSCAN UNAVAILABLE / NOT CONFIGURED ─────────────────────────────
    async def test_urlscan_not_configured_graceful(self):
        """When urlscan.io is not configured, pipeline lists not_configured and scan succeeds."""
        with patch.object(get_settings(), "urlscan_api_key", ""):
            res = await run_scan(url="https://google.com", scan_mode="url")
            uscan_step = next((p for p in res.pipeline if p.name == "urlscan.io"), None)
            self.assertIsNotNone(uscan_step)
            self.assertEqual(uscan_step.status, "not_configured")

    # ── 13. NO ANALYZER EVIDENCE ─────────────────────────────────────────────
    async def test_no_analyzer_evidence_yields_insufficient_evidence(self):
        """Empty input yields INSUFFICIENT_EVIDENCE without triggering fake rules."""
        res = await run_scan(message="", identity="", url="", scan_mode="full")
        self.assertEqual(res.verdict.label, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(res.input_coverage.supplied_count, 0)
        self.assertEqual(res.triggered_rules, [])

    # ── 14. MULTIPLE CORRELATED SUSPICIOUS SIGNALS ───────────────────────────
    async def test_multiple_correlated_signals_yields_high_risk(self):
        """Impersonation + coercive install + APK with SMS perms triggers HIGH_RISK."""
        res = await run_scan(
            message="URGENT: State Bank account blocked. Sideload update app from link immediately.",
            identity="State Bank",
            url="http://sbi-unverified-kyc.net/update.apk",
            apk_metadata={
                "filename": "update.apk",
                "package_name": "org.unverified.app",
                "permissions": ["READ_SMS", "RECEIVE_SMS", "REQUEST_INSTALL_PACKAGES"],
                "size": "5.2 MB",
                "hash": "aabbccddeeff",
            },
            scan_mode="full",
        )
        self.assertEqual(res.verdict.label, "HIGH_RISK")
        self.assertGreaterEqual(res.confidence, 0.88)
        self.assertIn("R1", res.triggered_rules)
        self.assertIn("R2", res.triggered_rules)

    async def test_ai_receives_scanner_evidence_without_provider_payload_blobs(self):
        """AI receives normalized scanner evidence without duplicated raw provider bodies."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"placeholder apk bytes")
            apk_path = Path(f.name)

        apk_result = ApkAnalysisResult(
            filename=apk_path.name,
            package_name="com.test.raw",
            sha256="a" * 64,
            permissions=["android.permission.READ_SMS"],
            dangerous_permissions=["android.permission.READ_SMS"],
            certificate_info={"raw_certificate": {"issuer": "CN=Test"}},
            status="completed",
        )
        mobsf_result = {
            "source": "mobsf",
            "status": "completed",
            "security_score": 22,
            "dangerous_permissions": ["READ_SMS"],
            "raw_report": {"appsec": {"score": 22}, "urls": ["https://c2.example/raw"]},
        }
        urlscan_result = {
            "status": "completed",
            "verdict": "malicious",
            "raw_response": {"results": [{"page": {"url": "https://raw.example/update.apk"}}]},
        }

        try:
            with patch.object(get_settings(), "urlscan_api_key", "test-urlscan-key"), \
                 patch("backend.services.scan_orchestrator.analyze_apk_file", return_value=apk_result), \
                 patch("backend.services.scan_orchestrator.scan_apk_with_mobsf", return_value=mobsf_result), \
                 patch("backend.services.scan_orchestrator.urlscan_search", return_value=urlscan_result), \
                 patch(
                     "backend.services.scan_orchestrator.ai_explanation_service.generate_ai_explanation",
                     new_callable=AsyncMock,
                 ) as mock_ai:
                mock_ai.return_value = {
                    "status": "unavailable",
                    "reason": "test",
                    "summary": "",
                    "why_it_matters": [],
                    "technical_to_plain_language": [],
                    "limitations": [],
                    "recommended_actions": [],
                    "avoid_actions": [],
                }

                res = await run_scan(
                    message="Install this APK now",
                    url="https://secure-login-verify.example/update.apk",
                    apk_path=apk_path,
                    scan_mode="full",
                )

                ai_payload = mock_ai.await_args.kwargs["normalized_evidence"]
                raw_outputs = ai_payload["raw_analyzer_outputs"]

                self.assertEqual(raw_outputs["mobsf"]["security_score"], mobsf_result["security_score"])
                self.assertEqual(raw_outputs["mobsf"]["dangerous_permissions"], mobsf_result["dangerous_permissions"])
                self.assertEqual(raw_outputs["urlscan"]["verdict"], urlscan_result["verdict"])
                self.assertNotIn("raw_report", raw_outputs["mobsf"])
                self.assertNotIn("raw_response", raw_outputs["urlscan"])
                self.assertNotIn("raw_report", ai_payload["normalized_evidence"]["mobsf"])
                self.assertNotIn("raw_response", ai_payload["normalized_evidence"]["urlscan"])
                self.assertEqual(raw_outputs["androguard"]["certificate_info"], apk_result.certificate_info)
                self.assertIn("raw_parse", raw_outputs["url_analyzer"])
                self.assertIn("ai_evidence_package", res.schema_output)
        finally:
            if apk_path.exists():
                apk_path.unlink()


if __name__ == "__main__":
    unittest.main()
