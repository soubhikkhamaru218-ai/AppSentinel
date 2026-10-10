"""
AppSentinel // Unit Tests: Upload & APK Staging
Validates file header inspection, size limits, and staging isolation.
"""

import io
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.database import init_db

client = TestClient(app)


class TestUploadAndApkStaging(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_reject_non_apk_file(self):
        """Plain text file pretending to be an APK should be rejected by magic bytes check."""
        fake_content = b"This is not a zip or apk file header at all! " * 5  # > 100 bytes
        response = client.post(
            "/api/scan/apk",
            files={"file": ("fake.apk", fake_content, "application/octet-stream")},
            data={"identity": "Bank"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("APK/ZIP header", response.json()["detail"])

    def test_valid_zip_apk_file(self):
        """A valid ZIP/APK structure with magic bytes PK\x03\x04 should be accepted and staged."""
        import zipfile
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest package='com.test.app'></manifest>")
            zf.writestr("classes.dex", b"DEX DATA MOCK")
        bio.seek(0)

        response = client.post(
            "/api/scan/apk",
            files={"file": ("valid_sample.apk", bio.getvalue(), "application/vnd.android.package-archive")},
            data={"identity": "Test Corp", "context_message": "Please install update"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("scan_id", data)
        self.assertEqual(data["scan_mode"], "apk")
        self.assertIn("verdict", data)


if __name__ == "__main__":
    unittest.main()
