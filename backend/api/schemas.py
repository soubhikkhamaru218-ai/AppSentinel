"""
AppSentinel // API Request & Response Schemas
Pydantic models that define the unified contract between frontend and backend.
"""

from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


# ─── REQUEST SCHEMAS ────────────────────────────────────────────────────────


class MessageScanRequest(BaseModel):
    """POST /api/scan/message"""
    message: str = Field(..., min_length=1, max_length=10000, description="The suspicious message text")
    identity: str = Field(default="", max_length=255, description="Claimed sender identity (e.g. 'State Bank')")


class UrlScanRequest(BaseModel):
    """POST /api/scan/url"""
    url: str = Field(..., min_length=5, max_length=2048, description="The suspicious URL to analyze")
    identity: str = Field(default="", max_length=255, description="Claimed sender identity")
    context_message: str = Field(default="", max_length=10000, description="Optional context message")


class ApkScanRequest(BaseModel):
    """
    POST /api/scan/apk (metadata sent as form fields alongside the file upload)
    """
    identity: str = Field(default="", max_length=255)
    context_message: str = Field(default="", max_length=10000)


class FullScanRequest(BaseModel):
    """POST /api/scan/full — multi-vector scan with all evidence at once."""
    message: str = Field(default="", max_length=10000)
    identity: str = Field(default="", max_length=255)
    url: str = Field(default="", max_length=2048)
    apk_filename: str = Field(default="")
    apk_hash: str = Field(default="")
    apk_package_name: str = Field(default="")
    apk_permissions: list[str] = Field(default_factory=list)
    apk_size: str = Field(default="")


# ─── COMPONENT EVIDENCE SCHEMAS ──────────────────────────────────────────────


class EvidenceNode(BaseModel):
    """A single node in the correlation evidence chain."""
    node: str = Field(..., description="Short label, e.g. 'APK Installation Coercion'")
    desc: str = Field(..., description="Detailed finding description")
    rule: str = Field(default="", description="Rule reference, e.g. 'R1'")
    severity: str = Field(default="info", description="info | warning | critical")


class TriggeredRuleDetail(BaseModel):
    """Rich metadata for a rule that fired in the correlation engine."""
    id: str = Field(..., description="Rule ID e.g. 'R1'")
    name: str = Field(..., description="Rule name")
    evidence_source: str = Field(..., description="Analyzer or input where evidence originated")
    exact_evidence: str = Field(..., description="The concrete evidence string or finding")
    reason: str = Field(..., description="Why this evidence indicates risk")
    severity: str = Field(default="warning", description="critical | warning | info")


class MessageAnalysisResult(BaseModel):
    """Output of the message analyzer service."""
    status: str = Field(default="completed", description="completed | skipped | unavailable | failed")
    reason: Optional[str] = None
    original_text: str = ""
    has_urgency: bool = False
    has_threat: bool = False
    has_otp_request: bool = False
    has_financial: bool = False
    has_install_instruction: bool = False
    detected_identity: str = ""
    urgency_keywords: list[str] = Field(default_factory=list)
    threat_keywords: list[str] = Field(default_factory=list)
    indicator_count: int = 0


class UrlAnalysisResult(BaseModel):
    """Output of the URL analyzer service."""
    status: str = Field(default="completed", description="completed | skipped | unavailable | failed")
    reason: Optional[str] = None
    original_url: str = ""
    domain: str = ""
    scheme: str = ""
    is_ip_host: bool = False
    has_suspicious_keywords: bool = False
    suspicious_keywords_found: list[str] = Field(default_factory=list)
    path_depth: int = 0
    is_apk_download: bool = False
    domain_age_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    positive_indicators: list[str] = Field(default_factory=list)
    # External provider results
    virustotal_score: Optional[int] = None
    virustotal_malicious: Optional[int] = None
    urlscan_verdict: Optional[str] = None
    raw_parse: dict[str, Any] = Field(default_factory=dict)


class ApkAnalysisResult(BaseModel):
    """Output of the Androguard APK analyzer service."""
    status: str = Field(default="completed", description="completed | skipped | unavailable | failed")
    reason: Optional[str] = None
    filename: str = ""
    size_bytes: int = 0
    size_mb: str = ""
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    package_name: str = ""
    app_name: Optional[str] = None
    min_sdk_version: Optional[str] = None
    target_sdk_version: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    permissions: list[str] = Field(default_factory=list)
    declared_permissions: list[str] = Field(default_factory=list)
    dangerous_permissions: list[str] = Field(default_factory=list)
    activities: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    receivers: list[str] = Field(default_factory=list)
    providers: list[str] = Field(default_factory=list)
    exported_components: list[str] = Field(default_factory=list)
    has_sms_permissions: bool = False
    has_accessibility_service: bool = False
    has_install_packages: bool = False
    has_network_capabilities: bool = False
    certificate_info: dict = Field(default_factory=dict)
    mobsf_available: bool = False
    mobsf_findings: Optional[dict] = None


class MobSfAnalysisResult(BaseModel):
    """Normalized technical evidence from MobSF static analysis."""
    source: str = "mobsf"
    status: str = Field(default="completed", description="completed | unavailable | failed | skipped | not_configured")
    reason: Optional[str] = None
    package_name: str = ""
    sha256: str = ""
    security_score: Optional[int] = None
    manifest_findings_count: int = 0
    permissions: list[str] = Field(default_factory=list)
    dangerous_permissions: list[str] = Field(default_factory=list)
    security_findings: list[dict] = Field(default_factory=list)
    certificate_findings: list[dict] = Field(default_factory=list)
    manifest_findings: list[dict] = Field(default_factory=list)
    code_findings: list[dict] = Field(default_factory=list)
    network_findings: list[dict] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    trackers: list[dict] = Field(default_factory=list)
    exported_components: list[str] = Field(default_factory=list)
    risk_indicators: list[str] = Field(default_factory=list)
    raw_report: dict[str, Any] = Field(default_factory=dict)


# ─── COVERAGE & PIPELINE MODELS ─────────────────────────────────────────────


class InputCoverage(BaseModel):
    """Tracks which input vectors were supplied by the user."""
    message: bool = False
    identity: bool = False
    url: bool = False
    apk: bool = False
    supplied_count: int = 0
    total_count: int = 4
    summary: str = "0 of 4 supplied"


class PipelineStep(BaseModel):
    """Execution status of an individual analyzer or engine step."""
    name: str
    status: str  # completed | unavailable | failed | skipped | not_configured
    reason: Optional[str] = None


class VerdictDetail(BaseModel):
    """Deterministic verdict specification."""
    label: str  # LOW_CONCERN | SUSPICIOUS | HIGH_RISK | INSUFFICIENT_EVIDENCE
    confidence: float
    severity: str  # low | medium | high | info


class CorrelationOutput(BaseModel):
    """Output bundle from the deterministic correlation engine."""
    triggered_rules: list[TriggeredRuleDetail] = Field(default_factory=list)
    evidence_chain: list[EvidenceNode] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)


class ActionsBlock(BaseModel):
    """Actionable recommendations for the user."""
    recommended: list[str] = Field(default_factory=list)
    avoid: list[str] = Field(default_factory=list)


# ─── AI EXPLANATION SCHEMAS ──────────────────────────────────────────────────


class AIFinding(BaseModel):
    """A single human-readable finding card."""
    finding: str = Field(..., description="Short finding title")
    explanation: str = Field(..., description="Plain-language explanation of this finding")
    severity: str = Field(default="info", description="high | medium | low | info")
    evidence_source: str = Field(default="", description="androguard | mobsf | url_analyzer | message_analyzer | correlation")


class AIExplanationResult(BaseModel):
    """Backward-compatible rich AI output object."""
    ai_available: bool = Field(default=False)
    headline: str = ""
    summary: str = ""
    what_we_found: list[AIFinding] = Field(default_factory=list)
    why_it_matters: str = ""
    why_this_result: str = ""
    precautions: list[str] = Field(default_factory=list)
    what_not_to_do: list[str] = Field(default_factory=list)
    confidence_explanation: str = ""
    limitations: list[str] = Field(default_factory=list)


class AIOutput(BaseModel):
    """Unified AI explanation block matching the requested contract."""
    status: str = Field(default="completed", description="completed | unavailable | failed")
    reason: Optional[str] = None
    summary: str = ""
    why_it_matters: list[str] = Field(default_factory=list)
    technical_to_plain_language: list[dict] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    avoid_actions: list[str] = Field(default_factory=list)


# ─── UNIFIED SCAN RESPONSE SCHEMA ────────────────────────────────────────────


class ScanResponse(BaseModel):
    """The authoritative unified response for any scan type."""
    scan_id: str
    timestamp: str
    scan_mode: str  # "message", "url", "apk", "full"

    # Authoritative deterministic verdict
    verdict: VerdictDetail
    confidence: float

    # Input and Analyzer Coverage separation
    input_coverage: InputCoverage
    analyzers: Dict[str, Any] = Field(default_factory=dict)
    pipeline: list[PipelineStep] = Field(default_factory=list)

    # Correlation results
    correlation: CorrelationOutput = Field(default_factory=CorrelationOutput)

    # Plain-language explanation from AI or deterministic fallback note
    ai: AIOutput = Field(default_factory=AIOutput)

    # Limitations & Actions
    limitations: list[str] = Field(default_factory=list)
    actions: ActionsBlock = Field(default_factory=ActionsBlock)

    # ── Legacy / Backward-compatibility fields ──
    vector_count: int = 0
    findings_count: int = 0
    triggered_rules: list[str] = Field(default_factory=list)
    inputs: dict = Field(default_factory=dict)
    evidence_chain: list[EvidenceNode] = Field(default_factory=list)
    explanation: str = ""
    ai_explanation: Optional[AIExplanationResult] = None
    schema_output: dict = Field(default_factory=dict)


class HealthResponse(BaseModel):
    """GET /api/health"""
    status: str = "ok"
    version: str = "1.0.0"
    engine: str = "AppSentinel Correlation Engine"
    services: dict = Field(default_factory=dict)


class ScanHistoryItem(BaseModel):
    """Single item in scan history list."""
    scan_id: str
    created_at: str
    scan_mode: str
    verdict: str
    confidence: float
    identity: str


class ScanHistoryResponse(BaseModel):
    """GET /api/scans"""
    total: int
    scans: list[ScanHistoryItem]
