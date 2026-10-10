"""
AppSentinel // Hashing Utilities
Safe SHA-256 fingerprinting for APK files.
"""

import hashlib
from pathlib import Path


def sha256_file(filepath: Path, chunk_size: int = 8192) -> str:
    """
    Compute the full SHA-256 hash of a file.
    Reads in chunks to handle large APKs without loading into memory.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()
