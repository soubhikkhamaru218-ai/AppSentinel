"""
AppSentinel // Identity Consistency Analyzer
Cross-checks claimed brand/organization against technical indicators.
Conservative approach — flags inconsistencies, doesn't assert fraud.
"""

import re
from backend.api.schemas import MessageAnalysisResult, UrlAnalysisResult, ApkAnalysisResult
from backend.utils.logging_config import logger


# Known official domains for common organizations
KNOWN_OFFICIAL_DOMAINS = {
    "state bank": ["sbi.co.in", "onlinesbi.com", "onlinesbi.sbi"],
    "sbi": ["sbi.co.in", "onlinesbi.com"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotak.com", "kotak811.com"],
    "rbi": ["rbi.org.in"],
    "reserve bank": ["rbi.org.in"],
    "income tax": ["incometax.gov.in", "incometaxindia.gov.in"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "google pay": ["pay.google.com"],
    "gpay": ["pay.google.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "india post": ["indiapost.gov.in"],
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
    "aadhaar": ["uidai.gov.in"],
    "epfo": ["epfindia.gov.in"],
}


def check_identity_consistency(
    claimed_identity: str,
    message_result: MessageAnalysisResult | None = None,
    url_result: UrlAnalysisResult | None = None,
    apk_result: ApkAnalysisResult | None = None,
) -> dict:
    """
    Check whether the claimed identity is consistent with technical evidence.

    Returns a dict with:
        - is_consistent: bool
        - issues: list of inconsistency descriptions
        - domain_match: bool | None
        - package_match: bool | None
        - detected_vs_claimed: str
    """
    if not claimed_identity or not claimed_identity.strip():
        return {
            "is_consistent": None,  # Can't check without a claim
            "issues": [],
            "domain_match": None,
            "package_match": None,
            "detected_vs_claimed": "No identity claim provided",
        }

    identity_lower = claimed_identity.lower().strip()
    identity_clean = re.sub(r"[^a-z0-9]", "", identity_lower)
    issues = []

    logger.info(f"IDENTITY_ANALYZER: Checking consistency for '{claimed_identity}'")

    domain_match = None
    package_match = None

    # --- Check URL domain vs. claimed identity ---
    if url_result and url_result.domain:
        domain = url_result.domain.lower()
        official_domains = KNOWN_OFFICIAL_DOMAINS.get(identity_lower, [])

        if official_domains:
            # We know the official domains for this org
            domain_match = any(domain.endswith(od) for od in official_domains)
            if not domain_match:
                issues.append(
                    f"Domain '{domain}' does not match known official domains for "
                    f"'{claimed_identity}': {', '.join(official_domains)}"
                )
        else:
            # Unknown org — check if identity appears in the domain
            domain_match = identity_clean in domain.replace(".", "").replace("-", "")
            if not domain_match:
                issues.append(
                    f"Domain '{domain}' does not contain the claimed identity "
                    f"'{claimed_identity}'"
                )

    # --- Check APK package name vs. claimed identity ---
    if apk_result and apk_result.package_name:
        pkg = apk_result.package_name.lower()
        package_match = identity_clean in pkg.replace(".", "").replace("_", "")
        if not package_match:
            issues.append(
                f"APK package '{apk_result.package_name}' does not match "
                f"claimed identity '{claimed_identity}'"
            )

    # --- Check message-detected identity vs. claimed identity ---
    if message_result and message_result.detected_identity:
        detected = message_result.detected_identity.lower()
        if identity_clean not in detected.replace(" ", "") and detected.replace(" ", "") not in identity_clean:
            issues.append(
                f"Message mentions '{message_result.detected_identity}' "
                f"but claim is '{claimed_identity}'"
            )

    is_consistent = len(issues) == 0

    result = {
        "is_consistent": is_consistent,
        "issues": issues,
        "domain_match": domain_match,
        "package_match": package_match,
        "detected_vs_claimed": (
            "Consistent" if is_consistent
            else f"{len(issues)} inconsistencies found"
        ),
    }

    logger.info(
        f"IDENTITY_ANALYZER: Done — consistent={is_consistent}, "
        f"issues={len(issues)}"
    )

    return result
