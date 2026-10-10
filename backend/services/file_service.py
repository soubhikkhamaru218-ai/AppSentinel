"""
AppSentinel // File Service
Safe APK staging: MIME validation, SHA-256 fingerprinting, size checks.
NEVER executes or installs uploaded files.
"""

import shutil
from pathlib import Path

from fastapi import UploadFile

from backend.config import get_settings
from backend.utils.hashing import sha256_file
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
    filename = upload.filename or "unknown.apk"

    logger.info(f"FILE_SERVICE: Staging '{filename}'")

    # --- 1. Read file content ---
    content = await upload.read()
    size_bytes = len(content)
    size_mb = round(size_bytes / (1024 * 1024), 2)

    # --- 2. Check size ---
    if size_bytes > settings.max_apk_size_bytes:
        raise FileServiceError(
            f"File too large: {size_mb}MB exceeds limit of {settings.max_apk_size_mb}MB"
        )

    if size_bytes < 100:
        raise FileServiceError("File too small to be a valid APK")

    # --- 3. Check MIME type ---
    content_type = upload.content_type or ""
    if content_type not in ALLOWED_MIMES:
        logger.warning(f"FILE_SERVICE: Unexpected MIME type: {content_type}")
        # Don't reject outright — some clients send wrong MIME. Check magic bytes.

    # --- 4. Check magic bytes ---
    if not content[:4] == APK_MAGIC:
        raise FileServiceError(
            "Invalid file: does not have APK/ZIP header. "
            "Ensure you are uploading a valid .apk file."
        )

    # --- 5. Save to upload directory ---
    upload_dir = settings.upload_path
    # Use hash-based filename to avoid collisions
    import hashlib
    temp_hash = hashlib.sha256(content[:1024]).hexdigest()[:12]
    safe_filename = f"{temp_hash}_{filename}"
    filepath = upload_dir / safe_filename

    with open(filepath, "wb") as f:
        f.write(content)

    # --- 6. Compute full SHA-256 ---
    file_hash = sha256_file(filepath)

    logger.info(
        f"FILE_SERVICE: Staged '{filename}' — "
        f"{size_mb}MB, SHA256={file_hash[:16]}..."
    )

    return {
        "filepath": str(filepath),
        "filename": filename,
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
