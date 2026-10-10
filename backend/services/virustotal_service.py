"""
AppSentinel // VirusTotal Service
Integrates with VirusTotal v3 REST API for URL and File Hash intelligence.
Degrades gracefully when API key is omitted or quota is exceeded.
"""

import base64
from typing import Optional, Dict, Any
import httpx

from backend.config import get_settings
from backend.utils.logging_config import logger


def check_url(url: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Query VirusTotal v3 for URL reputation.
    Safe: does not download payload.
    """
    settings = get_settings()
    key = api_key or settings.virustotal_api_key
    if not key:
        logger.debug("VIRUSTOTAL: API key not configured, skipping lookup.")
        return None

    from urllib.parse import urlparse
    import ipaddress
    parsed_target = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed_target.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal", "mobsf", "backend"):
        logger.info(f"VIRUSTOTAL: Skipping internal/private target '{host}' (SSRF protection).")
        return {"status": "skipped", "reason": "Internal/private destination skipped for SSRF protection"}
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            logger.info(f"VIRUSTOTAL: Skipping private IP target '{host}' (SSRF protection).")
            return {"status": "skipped", "reason": "Private IP target skipped for SSRF protection"}
    except ValueError:
        pass

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": key, "Accept": "application/json"}
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = sum(stats.values()) if stats else 0
                reputation = data.get("reputation", 0)

                logger.info(f"VIRUSTOTAL: URL scanned -> malicious: {malicious}/{total}")
                return {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total": total,
                    "reputation": reputation,
                    "categories": data.get("categories", {}),
                }
            elif resp.status_code == 404:
                logger.info("VIRUSTOTAL: URL not found in VT database.")
                return {"malicious": 0, "total": 0, "not_found": True}
            elif resp.status_code == 429:
                logger.warning("VIRUSTOTAL: API quota or rate limit exceeded (HTTP 429).")
                return {"rate_limited": True, "status": "rate_limited", "reason": "VirusTotal API rate limit / quota exceeded"}
            elif resp.status_code in (401, 403):
                logger.warning(f"VIRUSTOTAL: API authentication failed (HTTP {resp.status_code}).")
                return {"unauthorized": True, "status": "failed", "reason": "Invalid or unauthorized VirusTotal API key"}
            else:
                logger.warning(f"VIRUSTOTAL: API responded with HTTP {resp.status_code}")
                return None
    except Exception as e:
        logger.warning(f"VIRUSTOTAL: Request failed: {e}")
        return None


def check_file_hash(sha256_hash: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Query VirusTotal v3 for file reputation using SHA-256 hash.
    Safe: queries hash only, does not upload binary.
    """
    settings = get_settings()
    key = api_key or settings.virustotal_api_key
    if not key or not sha256_hash:
        return None

    try:
        headers = {"x-apikey": key, "Accept": "application/json"}
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(f"https://www.virustotal.com/api/v3/files/{sha256_hash}", headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                return {
                    "malicious": malicious,
                    "total": total,
                    "meaningful_name": data.get("meaningful_name", ""),
                    "type_description": data.get("type_description", ""),
                }
            elif resp.status_code == 404:
                return {"malicious": 0, "total": 0, "not_found": True}
            elif resp.status_code == 429:
                logger.warning("VIRUSTOTAL: Hash lookup rate limit exceeded (HTTP 429).")
                return {"rate_limited": True, "status": "rate_limited", "reason": "VirusTotal API rate limit / quota exceeded"}
            elif resp.status_code in (401, 403):
                logger.warning(f"VIRUSTOTAL: Hash lookup authentication failed (HTTP {resp.status_code}).")
                return {"unauthorized": True, "status": "failed", "reason": "Invalid or unauthorized VirusTotal API key"}
    except Exception as e:
        logger.warning(f"VIRUSTOTAL: Hash lookup failed: {e}")
    return None
