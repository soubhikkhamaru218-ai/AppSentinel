"""
AppSentinel // urlscan.io Service
Integrates with urlscan.io Community API for URL threat scans.
Gracefully degrades when API key is omitted or service is unreachable.
"""

from typing import Optional, Dict, Any
import httpx

from backend.config import get_settings
from backend.utils.logging_config import logger


def search_url(url: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Search historical urlscan.io scans for a URL without creating a new scan.
    """
    settings = get_settings()
    key = api_key or settings.urlscan_api_key
    if not key or key.startswith("github_"):
        return None

    from urllib.parse import urlparse
    import ipaddress
    parsed_target = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed_target.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal", "mobsf", "backend"):
        logger.info(f"URLSCAN: Skipping internal/private target '{host}' (SSRF protection).")
        return {"status": "skipped", "reason": "Internal/private destination skipped for SSRF protection"}
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            logger.info(f"URLSCAN: Skipping private IP target '{host}' (SSRF protection).")
            return {"status": "skipped", "reason": "Private IP target skipped for SSRF protection"}
    except ValueError:
        pass

    try:
        headers = {"API-Key": key, "Accept": "application/json"}
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(
                f"https://urlscan.io/api/v1/search/?q=page.url:{url}",
                headers=headers,
            )
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                if results:
                    primary = results[0]
                    verdict_data = primary.get("verdicts", {}).get("overall", {})
                    return {
                        "verdict": verdict_data.get("verdict", "unknown"),
                        "score": verdict_data.get("score", 0),
                        "malicious": verdict_data.get("malicious", False),
                        "has_verdict": verdict_data.get("hasVerdicts", False),
                        "categories": verdict_data.get("categories", []),
                        "result_url": primary.get("result", ""),
                        "raw_response": data,
                    }
                return {"results_found": 0, "raw_response": data}
            elif resp.status_code == 429:
                logger.warning("URLSCAN: API rate limit exceeded (HTTP 429).")
                return {"rate_limited": True, "status": "rate_limited", "reason": "urlscan.io API rate limit exceeded"}
            elif resp.status_code in (401, 403):
                logger.warning(f"URLSCAN: API authentication failed (HTTP {resp.status_code}).")
                return {"unauthorized": True, "status": "failed", "reason": "Invalid or unauthorized urlscan.io API key"}
            else:
                logger.warning(f"URLSCAN: API responded with status {resp.status_code}")
    except Exception as e:
        logger.warning(f"URLSCAN: Lookup failed: {e}")
    return None


def submit_scan(url: str, api_key: Optional[str] = None, visibility: str = "unlisted") -> Optional[Dict[str, Any]]:
    """
    Submit a URL to urlscan.io for asynchronous scanning.
    Default visibility is 'unlisted' for privacy.
    """
    settings = get_settings()
    key = api_key or settings.urlscan_api_key
    if not key:
        return None

    try:
        headers = {"API-Key": key, "Content-Type": "application/json"}
        payload = {"url": url, "visibility": visibility}
        with httpx.Client(timeout=10.0) as client:
            resp = client.post("https://urlscan.io/api/v1/scan/", json=payload, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.warning(f"URLSCAN: Submit failed: {e}")
    return None
