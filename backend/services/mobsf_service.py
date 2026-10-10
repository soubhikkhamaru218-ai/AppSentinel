"""
AppSentinel // MobSF (Mobile Security Framework) Service
Communicates with an external or local MobSF REST API instance
to retrieve static analysis telemetry and security metrics.

Follows strict security and architecture controls:
- Degrades gracefully when MobSF is offline, unreachable, or unconfigured.
- Never hardcodes API keys or secrets; loads from AppSentinel settings.
- Never logs API keys or sensitive user payload data.
- Never fabricates security scores, findings, or threat verdicts.
- Provides technical evidence only (no final malicious/safe verdicts).
- Explicitly reports status: completed, unavailable, failed, skipped, not_configured.
"""

import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Union
import httpx

from backend.api.schemas import MobSfAnalysisResult
from backend.config import get_settings
from backend.utils.logging_config import logger


def validate_apk_file(filepath: Union[str, Path]) -> Path:
    """
    Validate that the specified path points to an accessible APK file.
    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not a regular file, empty, or does not have .apk extension.
        PermissionError: If the file cannot be read.
    """
    if not filepath:
        raise ValueError("APK filepath must not be empty.")

    path = Path(filepath).resolve()

    if not path.exists():
        raise FileNotFoundError(f"APK file not found: {path.name}")

    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path.name}")

    if path.suffix.lower() != ".apk":
        raise ValueError(f"File must have a .apk extension, got: {path.suffix}")

    if not os.access(path, os.R_OK):
        raise PermissionError(f"APK file is not readable: {path.name}")

    try:
        if path.stat().st_size == 0:
            raise ValueError(f"APK file is empty (0 bytes): {path.name}")
    except OSError as e:
        raise PermissionError(f"Cannot access file stat for {path.name}: {e}")

    return path


def scan_apk_with_mobsf(
    apk_filepath: Union[str, Path],
    server_url: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: float = 60.0,
    max_retries: int = 2,
    poll_interval: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Upload and analyze an APK file using the MobSF REST API.

    Execution Flow:
    1. Read configuration (MOBSF_URL, MOBSF_API_KEY).
    2. Validate APK path on disk.
    3. Stream upload APK to `POST /api/v1/upload`.
    4. Trigger static analysis scan via `POST /api/v1/scan`.
    5. Retrieve detailed scan report via `POST /api/v1/report_json` (with retry/wait).
    6. Normalize technical evidence into standard schema.
    """
    settings = get_settings()
    configured_url = (server_url or settings.mobsf_url or "").rstrip("/")
    configured_key = settings.mobsf_api_key if api_key is None else api_key
    poll_interval_seconds = (
        settings.mobsf_poll_interval_seconds if poll_interval is None else poll_interval
    )
    deadline = time.monotonic() + max(1.0, timeout)

    # Check configuration
    if not configured_url or not configured_key:
        logger.info("MOBSF: Service URL or API key not configured; reporting status=not_configured")
        return {
            "source": "mobsf",
            "status": "not_configured",
            "reason": "MobSF URL or API key not configured",
            "available": False,  # backward compatibility
            "error": "MobSF is not configured",
        }

    # Validate file
    try:
        safe_path = validate_apk_file(apk_filepath)
    except (FileNotFoundError, ValueError, PermissionError) as e:
        logger.warning(f"MOBSF: Pre-upload validation failed for file: {e}")
        return {
            "source": "mobsf",
            "status": "failed",
            "reason": f"Invalid APK file: {e}",
            "available": False,
            "error": f"Invalid APK file: {e}",
        }

    logger.info(f"MOBSF: Initiating upload and analysis for '{safe_path.name}' at '{configured_url}'")

    headers = {
        "Authorization": configured_key,
        "X-Mobsf-Api-Key": configured_key,
    }

    client_timeout = httpx.Timeout(timeout, connect=min(10.0, max(1.0, timeout)))

    try:
        with httpx.Client(base_url=configured_url, timeout=client_timeout) as client:
            # ── 1. Upload APK ────────────────────────────────────────────────
            with open(safe_path, "rb") as file_stream:
                files = {
                    "file": (
                        safe_path.name,
                        file_stream,
                        "application/vnd.android.package-archive",
                    )
                }
                upload_resp = client.post("/api/v1/upload", files=files, headers=headers)

            if upload_resp.status_code == 401 or upload_resp.status_code == 403:
                logger.warning(f"MOBSF: Authentication failed (HTTP {upload_resp.status_code})")
                return {
                    "source": "mobsf",
                    "status": "failed",
                    "reason": f"MobSF authentication failed (HTTP {upload_resp.status_code})",
                    "available": False,
                    "error": "MobSF API key invalid or unauthorized",
                }

            if upload_resp.status_code != 200:
                logger.warning(f"MOBSF: Upload rejected with HTTP status {upload_resp.status_code}")
                return {
                    "source": "mobsf",
                    "status": "failed",
                    "reason": f"MobSF upload rejected (HTTP {upload_resp.status_code})",
                    "available": False,
                    "error": f"MobSF upload rejected (HTTP {upload_resp.status_code})",
                }

            try:
                upload_data = upload_resp.json()
            except Exception as json_err:
                logger.warning(f"MOBSF: Malformed upload response JSON: {json_err}")
                return {
                    "source": "mobsf",
                    "status": "failed",
                    "reason": "MobSF upload returned malformed JSON",
                    "available": False,
                    "error": "MobSF upload returned malformed JSON",
                }

            apk_hash = upload_data.get("hash")
            if not apk_hash:
                logger.warning("MOBSF: Upload response missing hash identifier")
                return {
                    "source": "mobsf",
                    "status": "failed",
                    "reason": "MobSF upload missing hash identifier",
                    "available": False,
                    "error": "MobSF upload missing hash identifier",
                }

            logger.info(f"MOBSF: Upload successful, scan hash='{apk_hash[:12]}...'")

            # ── 2. Request Static Analysis Scan ──────────────────────────────
            scan_payload = {"hash": apk_hash}
            scan_resp = client.post("/api/v1/scan", data=scan_payload, headers=headers)

            if scan_resp.status_code != 200:
                logger.warning(f"MOBSF: Scan initiation failed with HTTP status {scan_resp.status_code}")
                return {
                    "source": "mobsf",
                    "status": "failed",
                    "reason": f"MobSF scan initiation failed (HTTP {scan_resp.status_code})",
                    "available": False,
                    "error": f"MobSF scan initiation failed (HTTP {scan_resp.status_code})",
                }

            # ── 3. Retrieve JSON Report with bounded polling ─────────────────
            report_data = {}
            last_report_status: Optional[int] = None
            last_report_error: Optional[str] = None
            poll_attempts = max(1, max_retries + 1)

            for attempt in range(poll_attempts):
                if time.monotonic() >= deadline:
                    logger.warning("MOBSF: Report polling deadline expired before attempt %s", attempt + 1)
                    return {
                        "source": "mobsf",
                        "status": "timed_out",
                        "reason": f"MobSF report was not available before the {timeout:.0f}s deadline",
                        "available": False,
                        "error": "MobSF report polling timed out",
                        "hash": apk_hash,
                    }

                report_resp = client.post("/api/v1/report_json", data=scan_payload, headers=headers)
                last_report_status = report_resp.status_code

                if report_resp.status_code == 401 or report_resp.status_code == 403:
                    logger.warning("MOBSF: Report authentication failed (HTTP %s)", report_resp.status_code)
                    return {
                        "source": "mobsf",
                        "status": "failed",
                        "reason": f"MobSF report authentication failed (HTTP {report_resp.status_code})",
                        "available": False,
                        "error": "MobSF API key invalid or unauthorized",
                        "hash": apk_hash,
                    }

                if report_resp.status_code == 200:
                    try:
                        parsed_report = report_resp.json()
                    except Exception as json_err:
                        logger.warning("MOBSF: Malformed report JSON: %s", json_err)
                        return {
                            "source": "mobsf",
                            "status": "failed",
                            "reason": "MobSF report returned malformed JSON",
                            "available": False,
                            "error": "MobSF report returned malformed JSON",
                            "hash": apk_hash,
                        }

                    if parsed_report and isinstance(parsed_report, dict):
                        report_data = parsed_report
                        break

                    last_report_error = "MobSF report endpoint returned an empty report"
                elif report_resp.status_code in {202, 204, 404}:
                    last_report_error = f"MobSF report not ready or not found (HTTP {report_resp.status_code})"
                elif report_resp.status_code >= 500:
                    last_report_error = f"MobSF report service error (HTTP {report_resp.status_code})"
                else:
                    last_report_error = f"MobSF report request failed (HTTP {report_resp.status_code})"
                    logger.warning("MOBSF: %s", last_report_error)
                    return {
                        "source": "mobsf",
                        "status": "failed",
                        "reason": last_report_error,
                        "available": False,
                        "error": last_report_error,
                        "hash": apk_hash,
                    }

                if attempt < poll_attempts - 1:
                    sleep_for = min(max(0.1, poll_interval_seconds), max(0.0, deadline - time.monotonic()))
                    if sleep_for > 0:
                        time.sleep(sleep_for)

            if not report_data:
                reason = last_report_error or "MobSF report was unavailable after polling"
                status_value = "timed_out" if time.monotonic() >= deadline else "unavailable"
                logger.warning("MOBSF: %s", reason)
                return {
                    "source": "mobsf",
                    "status": status_value,
                    "reason": reason,
                    "available": False,
                    "error": reason,
                    "hash": apk_hash,
                    "report_http_status": last_report_status,
                }

            # ── 4. Normalize Technical Evidence ──────────────────────────────
            normalized = _normalize_mobsf_report(report_data, apk_hash)
            return normalized

    except (httpx.ConnectError, httpx.ConnectTimeout) as conn_err:
        logger.warning(f"MOBSF: Connection failed to {configured_url}: {conn_err}")
        return {
            "source": "mobsf",
            "status": "unavailable",
            "reason": f"MobSF service did not respond (connection refused or timeout at {configured_url})",
            "available": False,
            "error": "MobSF server connection refused or host unreachable",
        }
    except httpx.ReadTimeout:
        logger.warning("MOBSF: Request timed out during static analysis")
        return {
            "source": "mobsf",
            "status": "unavailable",
            "reason": f"MobSF request timed out during analysis (timeout={timeout}s)",
            "available": False,
            "error": "MobSF request timed out during analysis",
        }
    except httpx.HTTPStatusError as http_err:
        logger.warning(f"MOBSF: HTTP error {http_err.response.status_code}")
        return {
            "source": "mobsf",
            "status": "failed",
            "reason": f"MobSF HTTP error {http_err.response.status_code}",
            "available": False,
            "error": f"MobSF returned HTTP error {http_err.response.status_code}",
        }
    except Exception as exc:
        logger.warning(f"MOBSF: Unexpected error: {exc}")
        return {
            "source": "mobsf",
            "status": "failed",
            "reason": f"Unexpected MobSF communication error: {str(exc)}",
            "available": False,
            "error": "Unexpected error communicating with MobSF",
        }


def _normalize_mobsf_report(report: Dict[str, Any], apk_hash: str) -> Dict[str, Any]:
    """
    Extract and normalize MobSF report fields into AppSentinel's normalized evidence schema:
    {
      "source": "mobsf",
      "status": "completed",
      "package_name": "...",
      "sha256": "...",
      "permissions": [],
      "dangerous_permissions": [],
      "security_findings": [],
      "certificate_findings": [],
      "manifest_findings": [],
      "code_findings": [],
      "network_findings": [],
      "urls": [],
      "trackers": [],
      "exported_components": [],
      "risk_indicators": []
    }
    Only includes fields actually returned by MobSF. Never invent values.
    """
    package_name = report.get("package_name") or report.get("app_name") or ""

    # Security score
    raw_score = report.get("security_score")
    security_score: Optional[int] = None
    if isinstance(raw_score, (int, float)):
        security_score = int(raw_score)

    # Permissions
    raw_permissions = report.get("permissions") or {}
    permissions_list: List[str] = []
    dangerous_permissions_list: List[str] = []

    if isinstance(raw_permissions, dict):
        for perm_name, perm_info in raw_permissions.items():
            clean_name = perm_name.split(".")[-1]
            permissions_list.append(clean_name)
            if isinstance(perm_info, dict) and perm_info.get("status") == "dangerous":
                dangerous_permissions_list.append(clean_name)
    elif isinstance(raw_permissions, list):
        for item in raw_permissions:
            if isinstance(item, str):
                permissions_list.append(item.split(".")[-1])
            elif isinstance(item, dict):
                p_name = item.get("name", "") or item.get("permission", "")
                if p_name:
                    clean = p_name.split(".")[-1]
                    permissions_list.append(clean)
                    if item.get("status") == "dangerous":
                        dangerous_permissions_list.append(clean)

    # Manifest findings
    manifest_analysis = report.get("manifest_analysis") or {}
    raw_manifest_findings = manifest_analysis.get("manifest_findings") or []
    manifest_findings: List[Dict[str, Any]] = []

    if isinstance(raw_manifest_findings, list):
        for item in raw_manifest_findings:
            if isinstance(item, dict):
                manifest_findings.append({
                    "title": item.get("title", ""),
                    "severity": str(item.get("severity", "info")).lower(),
                    "description": item.get("description", ""),
                })
    elif isinstance(raw_manifest_findings, dict):
        for _, item in raw_manifest_findings.items():
            if isinstance(item, dict):
                manifest_findings.append({
                    "title": item.get("title", ""),
                    "severity": str(item.get("severity", "info")).lower(),
                    "description": item.get("description", ""),
                })

    # Code findings
    code_analysis = report.get("code_analysis") or {}
    code_findings: List[Dict[str, Any]] = []
    if isinstance(code_analysis, dict):
        for finding_key, finding_val in code_analysis.items():
            if isinstance(finding_val, dict):
                code_findings.append({
                    "issue": finding_key,
                    "severity": str(finding_val.get("metadata", {}).get("severity", "info")).lower() if isinstance(finding_val.get("metadata"), dict) else "info",
                    "description": finding_val.get("metadata", {}).get("description", "") if isinstance(finding_val.get("metadata"), dict) else "",
                })
            elif isinstance(finding_val, list):
                for sub in finding_val:
                    if isinstance(sub, dict):
                        code_findings.append({
                            "issue": finding_key,
                            "severity": str(sub.get("severity", "info")).lower(),
                            "description": sub.get("description", ""),
                        })

    # Certificate findings
    cert_analysis = report.get("certificate_analysis") or {}
    certificate_findings: List[Dict[str, Any]] = []
    if isinstance(cert_analysis, dict):
        cert_findings = cert_analysis.get("certificate_findings") or []
        if isinstance(cert_findings, list):
            for cf in cert_findings:
                if isinstance(cf, list) and len(cf) >= 3:
                    certificate_findings.append({"severity": str(cf[0]).lower(), "title": str(cf[1]), "description": str(cf[2])})
                elif isinstance(cf, dict):
                    certificate_findings.append(cf)

    # Network findings
    network_security = report.get("network_security") or {}
    network_findings: List[Dict[str, Any]] = []
    if isinstance(network_security, dict):
        network_findings_raw = network_security.get("network_findings") or []
        if isinstance(network_findings_raw, list):
            for nf in network_findings_raw:
                if isinstance(nf, dict):
                    network_findings.append({
                        "scope": nf.get("scope", ""),
                        "severity": str(nf.get("severity", "info")).lower(),
                        "description": nf.get("description", ""),
                    })

    # URLs
    urls_extracted: List[str] = []
    raw_urls = report.get("urls") or []
    if isinstance(raw_urls, list):
        for u in raw_urls:
            if isinstance(u, str):
                urls_extracted.append(u)
            elif isinstance(u, dict) and "url" in u:
                urls_extracted.append(u["url"])

    # Trackers
    raw_trackers = report.get("trackers") or {}
    trackers_list: List[Any] = []
    if isinstance(raw_trackers, dict):
        raw_t_list = raw_trackers.get("trackers") or []
        if isinstance(raw_t_list, list):
            for t in raw_t_list:
                if isinstance(t, dict):
                    trackers_list.append(t.get("name", "") or t)
                elif isinstance(t, str):
                    trackers_list.append(t)
    elif isinstance(raw_trackers, list):
        for t in raw_trackers:
            if isinstance(t, dict):
                trackers_list.append(t.get("name", "") or t)
            elif isinstance(t, str):
                trackers_list.append(t)

    # Exported components
    exported_components: List[str] = []
    for comp_key in ["exported_activities", "exported_services", "exported_receivers", "exported_providers"]:
        raw_comps = report.get(comp_key) or []
        if isinstance(raw_comps, list):
            for c in raw_comps:
                if isinstance(c, str):
                    exported_components.append(f"{comp_key.replace('exported_', '').upper()}: {c.split('.')[-1]}")

    # Risk indicators summary
    risk_indicators: List[str] = []
    if security_score is not None and security_score < 40:
        risk_indicators.append(f"MobSF security score low: {security_score}/100")
    if dangerous_permissions_list:
        risk_indicators.append(f"{len(dangerous_permissions_list)} dangerous permissions identified by MobSF")
    if len(manifest_findings) > 0:
        high_manifest = [f for f in manifest_findings if f.get("severity") == "high"]
        if high_manifest:
            risk_indicators.append(f"{len(high_manifest)} high-severity manifest issues flagged by MobSF")

    # Combine security findings
    security_findings = manifest_findings[:15] + code_findings[:15]

    logger.info(
        f"MOBSF: Scan normalized for hash {apk_hash[:12]}... "
        f"Score: {security_score}, Permissions: {len(permissions_list)}, "
        f"Manifest findings: {len(manifest_findings)}"
    )

    return {
        "source": "mobsf",
        "status": "completed",
        "package_name": package_name,
        "sha256": apk_hash,
        "security_score": security_score,
        "manifest_findings_count": len(manifest_findings),
        "permissions": permissions_list,
        "dangerous_permissions": dangerous_permissions_list,
        "security_findings": security_findings,
        "certificate_findings": certificate_findings,
        "manifest_findings": manifest_findings[:20],
        "code_findings": code_findings[:20],
        "network_findings": network_findings[:10],
        "urls": urls_extracted[:25],
        "trackers": trackers_list,
        "exported_components": exported_components[:25],
        "risk_indicators": risk_indicators,
        "raw_report": report,
        # Backward compatibility fields:
        "available": True,
        "hash": apk_hash,
        "findings": {
            "findings_by_severity": {
                "high": len([f for f in security_findings if f.get("severity") == "high"]),
                "warning": len([f for f in security_findings if f.get("severity") in ["warning", "medium"]]),
                "info": len([f for f in security_findings if f.get("severity") == "info"]),
            }
        },
    }


def check_mobsf_status() -> Dict[str, Any]:
    """Check if MobSF REST service is running and accessible."""
    settings = get_settings()
    configured_url = (settings.mobsf_url or "").rstrip("/")
    if not configured_url:
        return {
            "running": False,
            "status": "not_configured",
            "url": configured_url,
            "message": "MobSF URL not configured",
        }

    try:
        with httpx.Client(timeout=1.5) as client:
            resp = client.get(f"{configured_url}/api/v1/upload")
            return {
                "running": True,
                "status": "online",
                "url": configured_url,
                "message": "MobSF REST API is active and reachable",
            }
    except Exception as e:
        return {
            "running": False,
            "status": "offline",
            "url": configured_url,
            "message": f"MobSF service is offline on {configured_url} ({type(e).__name__}). Androguard handles APK static analysis.",
        }
