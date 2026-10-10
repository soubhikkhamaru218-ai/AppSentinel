"""
AppSentinel // File Service
Safe APK staging: MIME validation, SHA-256 fingerprinting, size checks.
NEVER executes or installs uploaded files.
"""

import hashlib
from pathlib import Path
from uuid import uuid4

from fastapi import UploadFile

from backend.config import get_settings
from backend.utils.logging_config import logger


# Valid APK magic bytes (PK zip header)
APK_MAGIC = b"PK\x03\x04"

# Allowed MIME types for APK uploads
ALLOWED_MIMES = {
    "application/vnd.android.package-archive",
    "application/octet-stream",
    "application/java-archive",
    "application/zip",
}


class FileServiceError(Exception):
    """Raised when file validation or staging fails."""
    pass


async def stage_apk(upload: UploadFile) -> dict:
    """
    Safely stage an uploaded APK file:
    1. Validate file size
    2. Check MIME type
    3. Verify magic bytes (PK zip header)
    4. Save to secure upload directory
    5. Compute SHA-256 hash
    6. Return metadata

    Returns dict with: filepath, filename, size_bytes, size_mb, sha256
    Raises FileServiceError on validation failure.
    """
    settings = get_settings()
    original_filename = Path(upload.filename or "unknown.apk").name or "unknown.apk"

    logger.info("FILE_SERVICE: Staging APK upload filename_supplied=%s", bool(upload.filename))

    # --- 1. Check MIME type metadata, but rely on file bytes for acceptance ---
    content_type = upload.content_type or ""
    if content_type not in ALLOWED_MIMES:
        logger.warning("FILE_SERVICE: Unexpected MIME type: %s", content_type)
        # Don't reject outright — some clients send wrong MIME. Check magic bytes.

    # --- 2. Stream to a server-controlled path while hashing incrementally ---
    upload_dir = settings.upload_path
    safe_filename = f"{uuid4().hex}.apk"
    filepath = upload_dir / safe_filename
    hasher = hashlib.sha256()
    size_bytes = 0
    first_bytes = b""
    chunk_size = max(1, int(settings.upload_chunk_size_bytes))

    try:
        with open(filepath, "xb") as staged:
            while True:
                chunk = await upload.read(chunk_size)
                if not chunk:
                    break

                size_bytes += len(chunk)
                if size_bytes > settings.max_apk_size_bytes:
                    size_mb = round(size_bytes / (1024 * 1024), 2)
                    raise FileServiceError(
                        f"File too large: {size_mb}MB exceeds limit of {settings.max_apk_size_mb}MB"
                    )

                if len(first_bytes) < len(APK_MAGIC):
                    needed = len(APK_MAGIC) - len(first_bytes)
                    first_bytes += chunk[:needed]

                hasher.update(chunk)
                staged.write(chunk)

        if size_bytes < 100:
            raise FileServiceError("File too small to be a valid APK")

        if first_bytes[:4] != APK_MAGIC:
            raise FileServiceError(
                "Invalid file: does not have APK/ZIP header. "
                "Ensure you are uploading a valid .apk file."
            )

    except FileServiceError:
        filepath.unlink(missing_ok=True)
        raise
    except Exception as e:
        filepath.unlink(missing_ok=True)
        logger.warning("FILE_SERVICE: Upload staging failed: %s", e)
        raise FileServiceError("Failed to safely stage uploaded APK") from e

    file_hash = hasher.hexdigest()
    size_mb = round(size_bytes / (1024 * 1024), 2)

    logger.info(
        "FILE_SERVICE: Staged APK server_name=%s size=%sMB sha256_prefix=%s",
        safe_filename,
        size_mb,
        file_hash[:16],
    )

    return {
        "filepath": str(filepath),
        "filename": original_filename,
        "stored_filename": safe_filename,
        "size_bytes": size_bytes,
        "size_mb": f"{size_mb} MB",
        "sha256": file_hash,
    }


def cleanup_file(filepath: str):
    """Remove a staged file after analysis is complete."""
    try:
        p = Path(filepath)
        if p.exists():
            p.unlink()
            logger.info(f"FILE_SERVICE: Cleaned up '{p.name}'")
    except Exception as e:
        logger.warning(f"FILE_SERVICE: Cleanup failed — {e}")
