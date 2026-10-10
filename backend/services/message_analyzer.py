"""
AppSentinel // Message Analyzer Service
Deterministic NLP extractor for scam/phishing signal detection.
Uses keyword & pattern matching — no external API calls needed.
"""

import re
from backend.api.schemas import MessageAnalysisResult
from backend.utils.logging_config import logger


# ─── SIGNAL DICTIONARIES ────────────────────────────────────────────────────

URGENCY_KEYWORDS = [
    "immediately", "urgent", "today", "act now", "deadline",
    "last warning", "24 hours", "asap", "right away", "within hours",
    "time-sensitive", "expires", "hurry", "limited time", "don't delay",
    "final notice", "respond now", "without delay",
]

THREAT_KEYWORDS = [
    "blocked", "suspended", "legal action", "penalty", "deactivated",
    "freeze", "terminated", "disabled", "restricted", "shut down",
    "will be closed", "permanently", "arrest", "warrant", "prosecution",
    "non-compliance", "violation", "seized",
]

CREDENTIAL_KEYWORDS = [
    "otp", "password", "pin", "cvv", "verification code", "passcode",
    "security code", "one-time password", "login credentials", "aadhaar",
    "pan number", "bank details", "card number", "account number",
    "social security", "ssn", "mpin", "upi pin",
]

FINANCIAL_KEYWORDS = [
    "payment", "transfer", "fee", "refund", "upi", "pay", "amount",
    "transaction", "balance", "withdraw", "deposit", "credit",
    "debit", "billing", "invoice", "remittance", "settlement",
]

INSTALL_KEYWORDS = [
    "apk", "install app", "download app", "security patch", "sideload",
    "install this", "download and install", "update app", "new version",
    "click to download", "application update", "install now",
    "download the attachment", "run the installer",
]

# Organizations commonly impersonated
IMPERSONATION_PATTERNS = [
    r"(state\s*bank|sbi)", r"(hdfc|icici|axis|kotak)", r"(reserve\s*bank|rbi)",
    r"(income\s*tax|it\s*department)", r"(customs|police|court)",
    r"(amazon|flipkart|paypal|paytm|phonepe|gpay|google\s*pay)",
    r"(whatsapp|telegram|instagram|facebook|meta)",
    r"(microsoft|apple|google)", r"(fedex|dhl|bluedart|india\s*post)",
    r"(electricity|gas\s*board|water\s*board|bsnl|jio|airtel|vi)",
    r"(uidai|aadhaar)", r"(epfo|pf\s*office)", r"(irctc|passport)",
]


def analyze_message(text: str) -> MessageAnalysisResult:
    """
    Analyze a message for scam/phishing indicators.
    Pure deterministic — no API calls, no ML.
    """
    if not text or not text.strip():
        return MessageAnalysisResult()

    lower_text = text.lower()
    logger.info(f"MESSAGE_ANALYZER: Processing {len(text)} chars")

    # Detect signals
    urgency_found = [kw for kw in URGENCY_KEYWORDS if kw in lower_text]
    threat_found = [kw for kw in THREAT_KEYWORDS if kw in lower_text]
    cred_found = [kw for kw in CREDENTIAL_KEYWORDS if kw in lower_text]
    financial_found = [kw for kw in FINANCIAL_KEYWORDS if kw in lower_text]
    install_found = [kw for kw in INSTALL_KEYWORDS if kw in lower_text]

    # Detect claimed identity
    detected_identity = ""
    for pattern in IMPERSONATION_PATTERNS:
        match = re.search(pattern, lower_text, re.IGNORECASE)
        if match:
            detected_identity = match.group(0).strip().title()
            break

    indicator_count = sum([
        len(urgency_found), len(threat_found), len(cred_found),
        len(financial_found), len(install_found),
    ])

    result = MessageAnalysisResult(
        original_text=text,
        has_urgency=bool(urgency_found),
        has_threat=bool(threat_found),
        has_otp_request=bool(cred_found),
        has_financial=bool(financial_found),
        has_install_instruction=bool(install_found),
        detected_identity=detected_identity,
        urgency_keywords=urgency_found[:5],  # Cap at 5 for display
        threat_keywords=threat_found[:5],
        indicator_count=indicator_count,
    )

    logger.info(
        f"MESSAGE_ANALYZER: Completed — {indicator_count} indicators, "
        f"urgency={result.has_urgency}, threat={result.has_threat}, "
        f"otp={result.has_otp_request}, install={result.has_install_instruction}"
    )

    return result
