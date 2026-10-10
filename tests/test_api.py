"""
AppSentinel // Integration Tests: Full REST API & Database Lifecycle
Tests all endpoints from ingestion to correlation, database lookup, and cleanup.
"""

import io
import zipfile
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.database import init_db

client = TestClient(app)


class TestFullApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_message_scan_persists_but_history_endpoints_are_disabled(self):
        # 1. Submit message scan
        payload = {
            "message": "URGENT: Your SBI account is blocked. Complete KYC immediately at link.",
            "identity": "SBI",
        }
        res = client.post("/api/scan/message", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        scan_id = data["scan_id"]
        self.assertTrue(scan_id.startswith("AS-"))
        self.assertIn("verdict", data)
        self.assertIn("confidence", data)
        self.assertIn("evidence_chain", data)
        self.assertIn("explanation", data)

        # 2. Historical scan endpoints are disabled until authentication and
        # per-user authorization exist.
        hist = client.get("/api/scans")
        self.assertEqual(hist.status_code, 403)
        self.assertIn("disabled", hist.json()["detail"])

        single = client.get(f"/api/scans/{scan_id}")
        self.assertEqual(single.status_code, 403)

        deleted = client.delete(f"/api/scans/{scan_id}")
        self.assertEqual(deleted.status_code, 403)

    def test_url_scan_api(self):
        payload = {
            "url": "http://statebank-kyc-verify.net/patch.apk",
            "identity": "State Bank",
            "context_message": "Urgent update required",
        }
        res = client.post("/api/scan/url", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["scan_mode"], "url")
        self.assertIn("url_analysis", data["schema_output"])
        self.assertTrue(data["schema_output"]["url_analysis"]["is_apk_download"])

    def test_full_scan_api(self):
        payload = {
            "message": "URGENT: State bank account blocked. Download patch.apk",
            "identity": "State Bank",
            "url": "http://statebank-kyc-verify.net/patch.apk",
            "apk_filename": "patch.apk",
            "apk_hash": "e3b0c44298fc1c14",
            "apk_package_name": "com.quicksupport.remote",
            "apk_permissions": ["READ_SMS", "RECEIVE_SMS", "BIND_ACCESSIBILITY_SERVICE"],
            "apk_size": "15.2 MB",
        }
        res = client.post("/api/scan/full", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["scan_mode"], "full")
        verdict_val = data["verdict"]["label"] if isinstance(data["verdict"], dict) else data["verdict"]
        self.assertEqual(verdict_val, "HIGH_RISK")
        self.assertIn("R1", data["triggered_rules"])
        self.assertIn("R2", data["triggered_rules"])


if __name__ == "__main__":
    unittest.main()
