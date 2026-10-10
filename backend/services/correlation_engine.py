"""
AppSentinel // Deterministic Correlation Engine
Implements Rules R1 through R7 with transparent audit trails and metadata.
This is the authoritative security decision maker for AppSentinel.
"""

from typing import Any, Dict, List, Optional, Tuple

from backend.api.schemas import (
    ApkAnalysisResult,
    EvidenceNode,
    MessageAnalysisResult,
    MobSfAnalysisResult,
    TriggeredRuleDetail,
    UrlAnalysisResult,
)
from backend.utils.logging_config import logger


# ─── RULE METADATA REGISTRY ─────────────────────────────────────────────────
RULE_METADATA: Dict[str, Dict[str, Any]] = {
    "R1": {
        "id": "R1",
        "name": "APK Installation Coercion",
        "description": "Message instructs APK installation and an APK with high-privilege capabilities is present.",
        "severity": "critical",
        "required_evidence": ["message.has_install_instruction", "apk.dangerous_permissions"],
    },
    "R2": {
        "id": "R2",
        "name": "Infrastructure Mismatch",
        "description": "Claimed identity contradicts URL hosting infrastructure.",
        "severity": "critical",
        "required_evidence": ["claimed_identity", "url.domain", "identity_check.domain_match == False"],
    },
    "R3": {
        "id": "R3",
        "name": "Package Identity Mismatch",
        "description": "Claimed identity contradicts APK package namespace or application label.",
        "severity": "critical",
        "required_evidence": ["claimed_identity", "apk.package_name", "identity_check.package_match == False"],
    },
    "R4": {
        "id": "R4",
        "name": "Credential Harvesting Under Duress",
        "description": "Message requests OTP or credentials while employing urgency or threat language.",
        "severity": "critical",
        "required_evidence": ["message.has_otp_request", "message.has_urgency|message.has_threat"],
    },
    "R5": {
        "id": "R5",
        "name": "Suspicious Domain Indicators",
        "description": "URL contains deceptive keywords, raw IP address hostname, or direct APK download link.",
        "severity": "warning",
        "required_evidence": ["url.has_suspicious_keywords|url.is_ip_host|url.is_apk_download"],
    },
    "R6": {
        "id": "R6",
        "name": "Financial Coercion Signals",
        "description": "Message combines financial transaction demands with urgency or threat language.",
        "severity": "warning",
        "required_evidence": ["message.has_financial", "message.has_urgency|message.has_threat"],
    },
    "R7": {
        "id": "R7",
        "name": "Untrusted / Self-Signed Package Signature",
        "description": "APK package uses a self-signed or debug certificate while requesting sensitive permissions.",
        "severity": "warning",
        "required_evidence": ["apk.certificate_info.self_signed", "apk.dangerous_permissions"],
    },
}


def correlate(
    message_result: Optional[MessageAnalysisResult] = None,
    url_result: Optional[UrlAnalysisResult] = None,
    apk_result: Optional[ApkAnalysisResult] = None,
    mobsf_result: Optional[Dict[str, Any]] = None,
    identity_check: Optional[Dict[str, Any]] = None,
    claimed_identity: str = "",
) -> Dict[str, Any]:
    """
    Run the AppSentinel deterministic correlation engine (Rules R1–R7).
    Authoritative source of truth for security verdict, confidence, and evidence chain.
    """
    logger.info("CORRELATION_ENGINE: Starting rule evaluation")

    rules: List[str] = []
    triggered_rule_details: List[TriggeredRuleDetail] = []
    chain: List[EvidenceNode] = []
    findings: List[str] = []
    findings_count = 0

    mr = message_result or MessageAnalysisResult()
    ur = url_result or UrlAnalysisResult()
    ar = apk_result or ApkAnalysisResult()
    ic = identity_check or {}
    mb = mobsf_result or {}

    # Check whether any substantive input was provided
    has_message_input = bool(
        bool(mr.original_text and mr.original_text.strip())
        or mr.indicator_count > 0
        or mr.has_urgency
        or mr.has_threat
        or mr.has_otp_request
        or mr.has_financial
        or mr.has_install_instruction
        or mr.detected_identity
    )
    has_url_input = bool(ur.domain and ur.domain != "INVALID")
    has_apk_input = bool(ar.filename or ar.package_name)
    has_identity_input = bool(claimed_identity.strip())

    has_any_analyzed_input = has_message_input or has_url_input or has_apk_input or has_identity_input

    # Incorporate MobSF security findings into evidence chain and findings
    if mb.get("status") == "completed":
        mobsf_findings_list = mb.get("security_findings") or []
        for mf in mobsf_findings_list[:5]:
            title = mf.get("title") or mf.get("finding") or "MobSF Security Issue"
            desc = mf.get("description") or mf.get("desc") or ""
            sev = (mf.get("severity") or "warning").lower()
            findings_count += 1
            chain.append(EvidenceNode(
                node=f"MobSF: {title}",
                desc=desc,
                rule="MOBSF",
                severity=sev if sev in ["low", "warning", "critical", "high", "info"] else "warning",
            ))
            findings.append(f"MobSF static finding ({sev}): {title}")

    # ══════════════════════════════════════════════════════════════════
    # R1: APK Installation Coercion
    # IF message instructs APK install AND an APK with dangerous capabilities exists
    # ══════════════════════════════════════════════════════════════════
    if mr.has_install_instruction and (ar.filename or ar.package_name):
        dangerous = ar.dangerous_permissions or []
        mobsf_dangerous = mb.get("dangerous_permissions") or []
        combined_dangerous = list(set(dangerous + mobsf_dangerous))

        if combined_dangerous or ar.has_sms_permissions or ar.has_accessibility_service or ar.has_install_packages:
            rules.append("R1")
            findings_count += 2
            exact = f"Message instructs APK installation. Package '{ar.filename or ar.package_name}' requests capabilities: {', '.join(combined_dangerous[:5]) or 'high-privilege'}"
            reason = "Legitimate services do not coerce users into sideloading sensitive APKs via instant message."
            triggered_rule_details.append(TriggeredRuleDetail(
                id="R1",
                name=RULE_METADATA["R1"]["name"],
                evidence_source="Message Analyzer & APK Analyzer",
                exact_evidence=exact,
                reason=reason,
                severity="critical",
            ))
            chain.append(EvidenceNode(
                node="APK Installation Coercion",
                desc=exact,
                rule="R1",
                severity="critical",
            ))
            findings.append("APK installation coercion detected via message instruction and sideloaded package")

    # ══════════════════════════════════════════════════════════════════
    # R2: Infrastructure Mismatch (Identity vs Domain)
    # IF claimed identity does NOT match URL domain infrastructure
    # ══════════════════════════════════════════════════════════════════
    if claimed_identity and ur.domain and ur.domain != "INVALID":
        if ic.get("domain_match") is False:
            rules.append("R2")
            findings_count += 2
            issue_desc = ic.get("issues", ["Domain does not match known official infrastructure"])[0] if ic.get("issues") else "Domain mismatch"
            exact = f"Claimed '{claimed_identity}' but destination infrastructure is '{ur.domain}'. {issue_desc}"
            reason = "Official organizations operate exclusively on verified, registered domain infrastructure."
            triggered_rule_details.append(TriggeredRuleDetail(
                id="R2",
                name=RULE_METADATA["R2"]["name"],
                evidence_source="Identity Analyzer & URL Analyzer",
                exact_evidence=exact,
                reason=reason,
                severity="critical",
            ))
            chain.append(EvidenceNode(
                node="Infrastructure Mismatch",
                desc=exact,
                rule="R2",
                severity="critical",
            ))
            findings.append(f"Infrastructure mismatch: claimed '{claimed_identity}' vs host '{ur.domain}'")

    # ══════════════════════════════════════════════════════════════════
    # R3: Package Identity Mismatch (Identity vs APK package name)
    # IF claimed identity does NOT match APK package namespace
    # ══════════════════════════════════════════════════════════════════
    if claimed_identity and ar.package_name:
        if ic.get("package_match") is False:
            rules.append("R3")
            findings_count += 2
            exact = f"Claims identity '{claimed_identity}' but APK package namespace is '{ar.package_name}'"
            reason = "Unofficial application package namespace indicates counterfeit or unverified software."
            triggered_rule_details.append(TriggeredRuleDetail(
                id="R3",
                name=RULE_METADATA["R3"]["name"],
                evidence_source="Identity Analyzer & Androguard",
                exact_evidence=exact,
                reason=reason,
                severity="critical",
            ))
            chain.append(EvidenceNode(
                node="Package Mismatch",
                desc=exact,
                rule="R3",
                severity="critical",
            ))
            findings.append(f"Package namespace mismatch: claimed '{claimed_identity}' vs package '{ar.package_name}'")

    # ══════════════════════════════════════════════════════════════════
    # R4: Credential Harvesting Under Duress
    # IF message requests OTP/password AND uses urgency/threat language
    # ══════════════════════════════════════════════════════════════════
    if mr.has_otp_request and (mr.has_urgency or mr.has_threat):
        rules.append("R4")
        findings_count += 2
        urgency_desc = []
        if mr.has_urgency:
            urgency_desc.append(f"Urgency keywords: {', '.join(mr.urgency_keywords[:3])}")
        if mr.has_threat:
            urgency_desc.append(f"Threat keywords: {', '.join(mr.threat_keywords[:3])}")
        exact = f"OTP/credential solicitation under pressure. {'; '.join(urgency_desc)}"
        reason = "Social engineering attack exploiting artificial time pressure to intercept one-time verification tokens."
        triggered_rule_details.append(TriggeredRuleDetail(
            id="R4",
            name=RULE_METADATA["R4"]["name"],
            evidence_source="Message Analyzer",
            exact_evidence=exact,
            reason=reason,
            severity="critical",
        ))
        chain.append(EvidenceNode(
            node="Credential Harvesting Under Duress",
            desc=exact,
            rule="R4",
            severity="critical",
        ))
        findings.append("Credential extraction attempt combined with artificial urgency or intimidation")

    # ══════════════════════════════════════════════════════════════════
    # R5: Suspicious Domain Indicators
    # IF URL domain contains phishing keywords or raw IP or APK download
    # ══════════════════════════════════════════════════════════════════
    if ur.domain and (ur.has_suspicious_keywords or ur.is_ip_host or ur.is_apk_download):
        rules.append("R5")
        findings_count += 1
        desc_parts = []
        if ur.has_suspicious_keywords:
            desc_parts.append(f"Deceptive keywords in domain: {', '.join(ur.suspicious_keywords_found[:5])}")
        if ur.is_ip_host:
            desc_parts.append(f"URL uses raw IP address instead of domain ({ur.domain})")
        if ur.is_apk_download:
            desc_parts.append("URL directly links to executable APK binary download")
        exact = ". ".join(desc_parts)
        reason = "Phishing campaigns frequently register deceptive subdomains or distribute APKs directly."
        triggered_rule_details.append(TriggeredRuleDetail(
            id="R5",
            name=RULE_METADATA["R5"]["name"],
            evidence_source="URL Analyzer",
            exact_evidence=exact,
            reason=reason,
            severity="warning",
        ))
        chain.append(EvidenceNode(
            node="Suspicious Domain Indicators",
            desc=exact,
            rule="R5",
            severity="warning",
        ))
        findings.append(exact)

    # ══════════════════════════════════════════════════════════════════
    # R6: Financial Coercion
    # IF message contains financial keywords + urgency/threat
    # ══════════════════════════════════════════════════════════════════
    if mr.has_financial and (mr.has_urgency or mr.has_threat):
        rules.append("R6")
        findings_count += 1
        exact = "Message combines financial transfer/settlement demands with urgent pressure or penalties"
        reason = "Scammers create artificial deadlines to induce impulsive financial transactions."
        triggered_rule_details.append(TriggeredRuleDetail(
            id="R6",
            name=RULE_METADATA["R6"]["name"],
            evidence_source="Message Analyzer",
            exact_evidence=exact,
            reason=reason,
            severity="warning",
        ))
        chain.append(EvidenceNode(
            node="Financial Coercion Signals",
            desc=exact,
            rule="R6",
            severity="warning",
        ))
        findings.append("Financial pressure tactics combined with urgency or threat language")

    # ══════════════════════════════════════════════════════════════════
    # R7: Untrusted / Self-Signed Package Signature
    # IF APK is self-signed or missing official signing while requesting sensitive capabilities
    # ══════════════════════════════════════════════════════════════════
    is_self_signed = bool(ar.certificate_info and ar.certificate_info.get("self_signed") is True)
    has_no_sig = bool(ar.certificate_info and ar.certificate_info.get("has_signature") is False)
    if (is_self_signed or has_no_sig) and (ar.dangerous_permissions or ar.has_sms_permissions or ar.has_accessibility_service):
        rules.append("R7")
        findings_count += 1
        exact = f"APK package '{ar.filename or ar.package_name}' uses a self-signed or debug certificate while requesting sensitive capabilities."
        reason = "Legitimate applications distributed to public users are signed with recognized organization certificates."
        triggered_rule_details.append(TriggeredRuleDetail(
            id="R7",
            name=RULE_METADATA["R7"]["name"],
            evidence_source="Androguard Certificate Inspection",
            exact_evidence=exact,
            reason=reason,
            severity="warning",
        ))
        chain.append(EvidenceNode(
            node="Untrusted Signing Certificate",
            desc=exact,
            rule="R7",
            severity="warning",
        ))
        findings.append("Self-signed or unverified certificate detected on application with sensitive permissions")

    # ══════════════════════════════════════════════════════════════════
    # VERDICT CALCULATION
    # ══════════════════════════════════════════════════════════════════
    verdict, confidence, severity, explanation, actions = _calculate_verdict(
        rules=rules,
        has_any_analyzed_input=has_any_analyzed_input,
        claimed_identity=claimed_identity,
        mr=mr,
        ur=ur,
        ar=ar,
        findings=findings,
    )

    logger.info(
        f"CORRELATION_ENGINE: Verdict={verdict} confidence={confidence} "
        f"rules={rules} findings={findings_count}"
    )

    return {
        "verdict": verdict,
        "confidence": confidence,
        "severity": severity,
        "triggered_rules": rules,
        "triggered_rule_details": triggered_rule_details,
        "evidence_chain": chain,
        "findings": findings,
        "explanation": explanation,
        "actions": actions,
        "findings_count": findings_count,
    }


def _calculate_verdict(
    rules: List[str],
    has_any_analyzed_input: bool,
    claimed_identity: str,
    mr: MessageAnalysisResult,
    ur: UrlAnalysisResult,
    ar: ApkAnalysisResult,
    findings: List[str],
) -> Tuple[str, float, str, str, List[str]]:
    """
    Authoritative verdict calculation:
    - HIGH_RISK: Correlated multi-vector attack (R1 + R2/R3/R4 or R2/R3 + R4).
    - SUSPICIOUS: Individual high-concern rules (R2, R3, R4, R1 alone, R5+R6, R5, R6, R7).
    - INSUFFICIENT_EVIDENCE: System could not obtain enough usable evidence to assess (e.g. empty input).
    - LOW_CONCERN: Evidence analyzed, and no suspicious indicators were detected.
    """
    identity_label = claimed_identity or "the claimed sender"

    # ── CASE 1: No usable input provided ─────────────────────────────
    if not has_any_analyzed_input:
        return (
            "INSUFFICIENT_EVIDENCE",
            0.50,
            "info",
            "The system could not obtain enough usable evidence to make a meaningful assessment. Please supply a suspicious message, URL, claimed identity, or APK file.",
            [
                "Provide a suspicious link, message text, or APK file for analysis.",
                "Ensure inputs are complete and uncorrupted.",
            ],
        )

    # ── CASE 2: HIGH_RISK — Multi-vector attack (R1 + R2/R3/R4) ──────
    if "R1" in rules and ("R2" in rules or "R3" in rules or "R4" in rules):
        return (
            "HIGH_RISK",
            0.92,
            "high",
            (
                f"Multi-vector attack detected: Impersonation of '{identity_label}' "
                f"combined with APK sideload coercion and credential harvesting. "
                f"Infrastructure and package signatures contradict the claimed identity."
            ),
            [
                "DO NOT click the link or install the APK.",
                "Delete the APK from your device immediately.",
                "Never provide OTPs or passwords via third-party forms.",
                f"Contact '{identity_label}' directly via their official app or website.",
                "Report this incident to your local cybercrime portal.",
            ],
        )

    # ── CASE 3: HIGH_RISK — Identity mismatch + credential harvesting ─
    if ("R2" in rules or "R3" in rules) and "R4" in rules:
        return (
            "HIGH_RISK",
            0.89,
            "high",
            (
                f"Strong impersonation attack: '{identity_label}' is contradicted by "
                f"technical infrastructure while actively requesting credentials under duress."
            ),
            [
                "DO NOT provide any credentials or OTPs.",
                "Avoid clicking any links in the message.",
                f"Verify independently with '{identity_label}' via official channels.",
                "Report the sender as phishing.",
            ],
        )

    # ── CASE 4: SUSPICIOUS — Infrastructure mismatch or credential duress
    if "R2" in rules or "R3" in rules or "R4" in rules:
        return (
            "SUSPICIOUS",
            0.84,
            "medium",
            (
                f"Strong phishing/social engineering signals detected. "
                f"Infrastructure or package identity does not match claimed identity '{identity_label}'. "
                f"Exercise extreme caution."
            ),
            [
                "Avoid clicking the link.",
                f"Verify via official channels of '{identity_label}'.",
                "Report the sender as phishing.",
                "Do not disclose credentials.",
            ],
        )

    # ── CASE 5: SUSPICIOUS — Suspicious domain + financial coercion ──
    if "R5" in rules and "R6" in rules:
        return (
            "SUSPICIOUS",
            0.78,
            "medium",
            (
                "Suspicious domain combined with financial pressure tactics. "
                "This pattern is commonly associated with scams."
            ),
            [
                "Do not make any payments through the provided link.",
                "Verify the request through official channels.",
                "Report the suspicious domain.",
            ],
        )

    # ── CASE 6: SUSPICIOUS — APK install coercion alone ──────────────
    if "R1" in rules:
        return (
            "SUSPICIOUS",
            0.80,
            "medium",
            (
                "Message instructs APK installation with dangerous capabilities. "
                "Legitimate organizations rarely distribute apps via direct APK links."
            ),
            [
                "Do NOT install the APK.",
                "Only install apps from Google Play Store or official verified sources.",
                f"Contact '{identity_label}' directly to verify.",
            ],
        )

    # ── CASE 7: SUSPICIOUS — Single suspicious domain, financial, or cert rule
    if "R5" in rules or "R6" in rules or "R7" in rules:
        return (
            "SUSPICIOUS",
            0.70,
            "medium",
            (
                "Some suspicious indicators detected in the available evidence. "
                "The request exhibits characteristics commonly associated with scam campaigns."
            ),
            [
                "Exercise caution before clicking or proceeding.",
                "Do not disclose sensitive information.",
                "Verify through official channels.",
            ],
        )

    # ── CASE 8: LOW_CONCERN ──────────────────────────────────────────
    # Evidence was provided, analyzed, and NO suspicious indicators were found.
    # For a clean URL like https://google.com, confidence is high (0.91)
    confidence = 0.91 if (ur.domain and ur.ssl_valid and not ur.has_suspicious_keywords) else 0.85
    explanation = (
        "No suspicious indicators were detected in the available evidence. "
        "The request appears consistent with standard communication patterns."
    )
    actions = [
        "Proceed with standard precautions.",
        "Keep device and browser security protections enabled.",
        "When in doubt, access services directly via official bookmarks.",
    ]

    return ("LOW_CONCERN", confidence, "low", explanation, actions)
