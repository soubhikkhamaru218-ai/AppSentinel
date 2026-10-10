"""
AppSentinel // URL Analyzer Service
Safe URL parsing + optional VirusTotal & urlscan.io integration.
Never visits or executes URLs — static analysis only.
"""

import re
from urllib.parse import urlparse
from typing import List, Optional

import httpx

from backend.api.schemas import UrlAnalysisResult
from backend.config import get_settings
from backend.utils.logging_config import logger


# Keywords commonly found in phishing domains
SUSPICIOUS_DOMAIN_KEYWORDS = [
    "verify", "kyc", "patch", "reschedule", "portal", "login",
    "secure-", "update", "confirm", "validate", "authenticate",
    "account-", "banking", "support-", "helpdesk", "recovery",
    "unlock", "restore", "reactivate", "suspended",
]

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".online", ".site", ".icu",
    ".buzz", ".fun", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".work", ".click", ".link", ".info",
]


def analyze_url(url: str) -> UrlAnalysisResult:
    """
    Analyze a URL for phishing/scam indicators.
    Performs only safe, static parsing — never visits the URL.
    """
    if not url or not url.strip():
        return UrlAnalysisResult(
            status="skipped",
            reason="No URL provided",
        )

    logger.info(f"URL_ANALYZER: Parsing URL ({len(url)} chars)")

    # Normalize
    raw_url = url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = f"https://{raw_url}"

    try:
        parsed = urlparse(raw_url)
    except Exception as e:
        logger.warning(f"URL_ANALYZER: Failed to parse URL: {e}")
        return UrlAnalysisResult(
            original_url=url,
            domain="INVALID",
            status="failed",
            reason=f"Failed to parse URL syntax: {str(e)}",
        )

    domain = parsed.hostname or ""
    scheme = parsed.scheme or "unknown"
    path = parsed.path or "/"
    path_depth = len([p for p in path.split("/") if p])

    if not domain:
        return UrlAnalysisResult(
            original_url=url,
            domain="INVALID",
            status="failed",
            reason="No valid hostname found in URL",
        )

    # Check if host is an IP address
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))

    # SSRF Protection: Identify internal, loopback, or private host targets
    import ipaddress
    is_internal_target = False
    if domain.lower() in ("localhost", "0.0.0.0", "127.0.0.1", "::1", "host.docker.internal", "mobsf", "backend"):
        is_internal_target = True
    else:
        try:
            ip_obj = ipaddress.ip_address(domain)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                is_internal_target = True
        except ValueError:
            pass

    # Find suspicious keywords in domain and path
    suspicious_found = [
        kw for kw in SUSPICIOUS_DOMAIN_KEYWORDS
        if kw in domain.lower() or kw in path.lower()
    ]
    if is_internal_target:
        suspicious_found.append("internal_network_target")

    # Check TLD
    has_suspicious_tld = any(domain.lower().endswith(tld) for tld in SUSPICIOUS_TLDS)
    if has_suspicious_tld:
        suspicious_found.append(f"suspicious_tld:{domain.split('.')[-1]}")

    # Check if URL points to APK download
    is_apk_download = path.lower().endswith(".apk") or ".apk" in raw_url.lower()

    # Positive evidence (when clean)
    positive_indicators: List[str] = []
    if scheme == "https":
        positive_indicators.append("HTTPS encryption protocol enabled")
    if not is_ip:
        positive_indicators.append("Hostname resolves to standard domain name (not raw IP)")
    if not suspicious_found:
        positive_indicators.append("No suspicious phishing keywords detected in domain or path")
    if not is_apk_download:
        positive_indicators.append("URL does not direct to an APK binary download")

    result = UrlAnalysisResult(
        original_url=url,
        domain=domain,
        scheme=scheme,
        is_ip_host=is_ip,
        has_suspicious_keywords=bool(suspicious_found),
        suspicious_keywords_found=suspicious_found[:10],
        path_depth=path_depth,
        is_apk_download=is_apk_download,
        ssl_valid=scheme == "https",
        positive_indicators=positive_indicators,
        status="completed",
        raw_parse={
            "submitted_url": url,
            "normalized_url": raw_url,
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "hostname": domain,
            "path": parsed.path,
            "query_present": bool(parsed.query),
            "fragment_present": bool(parsed.fragment),
            "path_depth": path_depth,
            "is_internal_target": is_internal_target,
            "suspicious_tld": has_suspicious_tld,
        },
    )

    logger.info(
        f"URL_ANALYZER: domain='{domain}' scheme={scheme} "
        f"suspicious_keywords={len(suspicious_found)} ip_host={is_ip} "
        f"apk_download={is_apk_download}"
    )

    # Try VirusTotal lookup if API key is available (skip internal targets for SSRF protection)
    settings = get_settings()
    if settings.virustotal_api_key and not is_internal_target:
        vt_result = _check_virustotal(raw_url, settings.virustotal_api_key)
        if vt_result:
            result.virustotal_score = vt_result.get("score")
            result.virustotal_malicious = vt_result.get("malicious")

    # Try urlscan.io lookup if API key is available (skip internal targets for SSRF protection)
    if settings.urlscan_api_key and not is_internal_target:
        uscan_result = _check_urlscan(raw_url, settings.urlscan_api_key)
        if uscan_result:
            result.urlscan_verdict = uscan_result.get("verdict")

    return result


def _check_virustotal(url: str, api_key: str) -> dict | None:
    """Query VirusTotal URL report API."""
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            logger.info(f"URL_ANALYZER: VirusTotal — {malicious}/{total} engines flagged")
            return {"score": total, "malicious": malicious}
        else:
            logger.warning(f"URL_ANALYZER: VirusTotal returned {resp.status_code}")
    except Exception as e:
        logger.warning(f"URL_ANALYZER: VirusTotal lookup failed — {e}")
    return None


def _check_urlscan(url: str, api_key: str) -> dict | None:
    """Query urlscan.io search API for previous scans of this URL."""
    try:
        headers = {"API-Key": api_key}
        resp = httpx.get(
            f"https://urlscan.io/api/v1/search/?q=page.url:{url}",
            headers=headers,
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if results:
                verdict = results[0].get("verdicts", {}).get("overall", {}).get("verdict", "unknown")
                logger.info(f"URL_ANALYZER: urlscan.io — verdict: {verdict}")
                return {"verdict": verdict}
        else:
            logger.warning(f"URL_ANALYZER: urlscan.io returned {resp.status_code}")
    except Exception as e:
        logger.warning(f"URL_ANALYZER: urlscan.io lookup failed — {e}")
    return None
