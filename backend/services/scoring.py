"""
AppSentinel // Scoring Module
Calculates risk scores and coverage metrics for scan results.
"""

from backend.utils.logging_config import logger


def calculate_coverage(
    has_message: bool,
    has_identity: bool,
    has_url: bool,
    has_apk: bool,
) -> dict:
    """
    Calculate evidence coverage — how many of the 4 vectors are provided.
    """
    vectors = {
        "message": has_message,
        "identity": has_identity,
        "url": has_url,
        "apk": has_apk,
    }

    provided = sum(1 for v in vectors.values() if v)

    return {
        "vector_count": provided,
        "total_vectors": 4,
        "coverage_ratio": round(provided / 4, 2),
        "vectors": vectors,
    }


def adjust_confidence(
    base_confidence: float,
    vector_count: int,
    findings_count: int,
) -> float:
    """
    Adjust confidence based on evidence coverage.
    More vectors = higher confidence in the verdict.
    """
    # Coverage bonus: 0-4% boost per vector
    coverage_bonus = min(vector_count * 0.01, 0.04)

    # Findings penalty if low signals with high coverage
    if vector_count >= 3 and findings_count == 0:
        coverage_bonus -= 0.05  # Slightly reduce confidence

    adjusted = base_confidence + coverage_bonus
    return round(max(0.0, min(1.0, adjusted)), 2)
