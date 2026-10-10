"""
AppSentinel // Unit Tests: Upload & APK Staging
Validates file header inspection, size limits, and staging isolation.
"""

import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.config import get_settings
from backend.main import app
from backend.models.database import init_db
from backend.services.file_service import stage_apk, FileServiceError

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


class ChunkedUpload:
    def __init__(self, data: bytes, filename: str = "../../evil.apk", content_type: str = "application/octet-stream"):
        self._data = data
        self._pos = 0
        self.filename = filename
        self.content_type = content_type

    async def read(self, size: int = -1) -> bytes:
        if self._pos >= len(self._data):
            return b""
        if size is None or size < 0:
            size = len(self._data) - self._pos
        chunk = self._data[self._pos:self._pos + size]
        self._pos += len(chunk)
        return chunk


class TestStreamingUploadStaging(unittest.IsolatedAsyncioTestCase):

    async def test_stage_apk_uses_server_filename_and_incremental_hash(self):
        payload = b"PK\x03\x04" + b"A" * 256

        with tempfile.TemporaryDirectory() as td, \
             patch.object(get_settings(), "upload_dir", td), \
             patch.object(get_settings(), "upload_chunk_size_bytes", 8), \
             patch.object(get_settings(), "max_apk_size_mb", 1):
            staged = await stage_apk(ChunkedUpload(payload, filename="../../client_supplied.apk"))
            staged_path = Path(staged["filepath"])

            try:
                self.assertTrue(staged_path.exists())
                self.assertEqual(staged_path.parent, Path(td))
                self.assertNotIn("client_supplied", staged_path.name)
                self.assertEqual(staged_path.suffix, ".apk")
                self.assertEqual(staged["filename"], "client_supplied.apk")
                self.assertEqual(staged["size_bytes"], len(payload))

                import hashlib
                self.assertEqual(staged["sha256"], hashlib.sha256(payload).hexdigest())
            finally:
                staged_path.unlink(missing_ok=True)

    async def test_stage_apk_removes_partial_file_when_size_limit_exceeded(self):
        payload = b"PK\x03\x04" + b"B" * 512

        with tempfile.TemporaryDirectory() as td, \
             patch.object(get_settings(), "upload_dir", td), \
             patch.object(get_settings(), "upload_chunk_size_bytes", 32), \
             patch.object(get_settings(), "max_apk_size_mb", 0):
            with self.assertRaises(FileServiceError):
                await stage_apk(ChunkedUpload(payload))

            self.assertEqual(list(Path(td).glob("*")), [])


if __name__ == "__main__":
    unittest.main()
