"""
AppSentinel // Unit Tests for MobSF and Androguard APK Analysis Layer
Validates technical evidence extraction, signal categorization, and safe degradation.
"""

import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import httpx

from backend.services.mobsf_service import (
    validate_apk_file,
    scan_apk_with_mobsf,
    _normalize_mobsf_report,
)
from backend.services.androguard_service import (
    compute_sha256,
    analyze_apk_file,
    analyze_apk_metadata,
    _is_sms_permission,
    _is_accessibility_permission,
    _is_install_permission,
    _is_dangerous_permission,
    _normalize_permission_name,
)


class TestMobSFService(unittest.TestCase):

    def setUp(self):
        # Create a real temporary .apk file
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
        self.temp_file.write(b"PK\x03\x04" + b"A" * 100)
        self.temp_file.close()
        self.apk_path = Path(self.temp_file.name)

    def tearDown(self):
        if self.apk_path.exists():
            os.remove(self.apk_path)

    def test_validate_apk_file_success(self):
        validated = validate_apk_file(self.apk_path)
        self.assertEqual(validated, self.apk_path.resolve())

    def test_validate_apk_file_nonexistent(self):
        with self.assertRaises(FileNotFoundError):
            validate_apk_file("nonexistent_file_xyz.apk")

    def test_validate_apk_file_wrong_extension(self):
        txt_file = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        txt_file.write(b"sample data")
        txt_file.close()
        try:
            with self.assertRaises(ValueError):
                validate_apk_file(txt_file.name)
        finally:
            os.remove(txt_file.name)

    def test_mobsf_unconfigured_graceful_degradation(self):
        """When MOBSF_API_KEY is not set, must return predictable unavailable result."""
        result = scan_apk_with_mobsf(
            apk_filepath=self.apk_path,
            server_url="http://localhost:8000",
            api_key="",
        )
        self.assertFalse(result["available"])
        self.assertEqual(result["source"], "mobsf")
        self.assertEqual(result["error"], "MobSF is not configured")
        # Ensure no fake verdicts
        self.assertNotIn("verdict", result)

    def test_mobsf_connection_refused(self):
        """When MobSF server is offline, returns connection error safely."""
        result = scan_apk_with_mobsf(
            apk_filepath=self.apk_path,
            server_url="http://127.0.0.1:59999",  # Unused port
            api_key="test-api-key",
            timeout=1.0,
        )
        self.assertFalse(result["available"])
        self.assertEqual(result["source"], "mobsf")
        self.assertIn("error", result)

    def test_normalize_mobsf_report(self):
        """Validates that MobSF report fields are preserved accurately without inventing verdicts."""
        mock_report = {
            "security_score": 45,
            "manifest_analysis": {
                "manifest_findings": [
                    {"severity": "high", "title": "Debuggable App"},
                    {"severity": "warning", "title": "AllowBackup enabled"},
                    {"severity": "info", "title": "Target SDK 33"},
                ]
            },
            "permissions": {"android.permission.INTERNET": {"status": "normal"}},
            "trackers": {"trackers": ["Google Firebase"]},
        }
        normalized = _normalize_mobsf_report(mock_report, "abc123hash")

        self.assertTrue(normalized["available"])
        self.assertEqual(normalized["source"], "mobsf")
        self.assertEqual(normalized["hash"], "abc123hash")
        self.assertEqual(normalized["security_score"], 45)
        self.assertEqual(normalized["manifest_findings_count"], 3)
        self.assertEqual(normalized["findings"]["findings_by_severity"]["high"], 1)
        self.assertEqual(normalized["findings"]["findings_by_severity"]["warning"], 1)
        self.assertEqual(normalized["trackers"], ["Google Firebase"])
        # Ensure no final verdict generated
        self.assertNotIn("verdict", normalized)


class TestAndroguardService(unittest.TestCase):

    def test_permission_normalization(self):
        self.assertEqual(_normalize_permission_name("android.permission.READ_SMS"), "READ_SMS")
        self.assertEqual(_normalize_permission_name("READ_SMS"), "READ_SMS")
        self.assertEqual(_normalize_permission_name("com.custom.PERMISSION"), "PERMISSION")

    def test_sms_permission_detection(self):
        self.assertTrue(_is_sms_permission("android.permission.READ_SMS"))
        self.assertTrue(_is_sms_permission("RECEIVE_SMS"))
        self.assertTrue(_is_sms_permission("SEND_SMS"))
        # Must not match arbitrary substrings
        self.assertFalse(_is_sms_permission("android.permission.COSMOS"))
        self.assertFalse(_is_sms_permission("ASMS_RECEIVER"))
        self.assertFalse(_is_sms_permission("android.permission.INTERNET"))

    def test_accessibility_detection(self):
        self.assertTrue(_is_accessibility_permission("android.permission.BIND_ACCESSIBILITY_SERVICE"))
        self.assertTrue(_is_accessibility_permission("BIND_ACCESSIBILITY_SERVICE"))
        # Must not match generic substring "ACCESSIBILITY"
        self.assertFalse(_is_accessibility_permission("android.permission.ACCESS_NETWORK_STATE"))
        self.assertFalse(_is_accessibility_permission("android.permission.ACCESSIBILITY_SETTINGS"))

    def test_install_packages_detection(self):
        self.assertTrue(_is_install_permission("android.permission.REQUEST_INSTALL_PACKAGES"))
        self.assertTrue(_is_install_permission("INSTALL_PACKAGES"))
        self.assertFalse(_is_install_permission("android.permission.CAMERA"))

    def test_dangerous_permissions_categorization(self):
        self.assertTrue(_is_dangerous_permission("android.permission.READ_PHONE_STATE"))
        self.assertTrue(_is_dangerous_permission("android.permission.SYSTEM_ALERT_WINDOW"))
        self.assertTrue(_is_dangerous_permission("android.permission.CAMERA"))
        self.assertFalse(_is_dangerous_permission("android.permission.INTERNET"))
        self.assertFalse(_is_dangerous_permission("android.permission.VIBRATE"))

    def test_streaming_sha256(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"AppSentinel Streaming Hash Verification Test")
            tname = f.name
        try:
            p = Path(tname)
            digest = compute_sha256(p)
            self.assertEqual(len(digest), 64)
            import hashlib
            expected = hashlib.sha256(b"AppSentinel Streaming Hash Verification Test").hexdigest()
            self.assertEqual(digest, expected)
        finally:
            os.remove(tname)

    def test_analyze_apk_metadata(self):
        result = analyze_apk_metadata(
            filename="sample.apk",
            file_hash="test_sha256",
            package_name="com.test.sample",
            permissions=[
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
            ],
            size="12.5 MB",
        )
        self.assertEqual(result.filename, "sample.apk")
        self.assertEqual(result.package_name, "com.test.sample")
        self.assertTrue(result.has_sms_permissions)
        self.assertTrue(result.has_accessibility_service)
        self.assertFalse(result.has_install_packages)
        self.assertIn("android.permission.READ_SMS", result.dangerous_permissions)
        # Ensure no final verdict generated
        self.assertFalse(hasattr(result, "verdict"))


if __name__ == "__main__":
    unittest.main()
