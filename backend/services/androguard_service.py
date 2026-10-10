"""
AppSentinel // Androguard APK Static Analysis Service
Primary local APK parser providing deep static inspection of Android packages.

Follows strict security and architecture controls:
- Uses Androguard library (androguard.core.apk.APK) as the primary manifest and binary parser.
- Treats permissions and capabilities strictly as objective technical evidence, NEVER as final malware/scam verdicts.
- Accurately detects SMS, Accessibility Service, Package Installation, and Network capabilities.
- Extracts package name, application label, SDK versions, activities, services, receivers,
  providers, exported components, certificates, and cryptographic hashes (SHA-256, MD5, SHA-1).
- Does not execute or install uploaded APKs; treats all input as untrusted.
"""

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import zipfile

from androguard.core.apk import APK

from backend.api.schemas import ApkAnalysisResult
from backend.utils.logging_config import logger


# ─── RISK SIGNAL CATALOGUES (CAPABILITIES, NOT VERDICTS) ────────────────────
DANGEROUS_PERMISSIONS: Set[str] = {
    # SMS / Messaging
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH", "BROADCAST_SMS",
    # Telephony / Call Logs
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS", "ANSWER_PHONE_CALLS",
    # Contacts & Accounts
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    # Calendar
    "READ_CALENDAR", "WRITE_CALENDAR",
    # Accessibility & Screen Overlays
    "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW",
    # Sideloading & Package Installation
    "REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES", "DELETE_PACKAGES", "BIND_DEVICE_ADMIN",
    # System Configuration & Notifications
    "WRITE_SETTINGS", "CHANGE_WIFI_STATE", "ACCESS_NOTIFICATION_POLICY", "BIND_NOTIFICATION_LISTENER_SERVICE",
    # Media & Hardware Sensors
    "CAMERA", "RECORD_AUDIO",
    # Storage Access
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
    # Precise Geolocation
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
}

SMS_PERMISSIONS: Set[str] = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH", "BROADCAST_SMS",
}

INSTALL_PERMISSIONS: Set[str] = {
    "REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES",
}

NETWORK_PERMISSIONS: Set[str] = {
    "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE",
}


# ─── UTILITY HELPERS ────────────────────────────────────────────────────────
def compute_hashes(filepath: Path) -> Tuple[str, str, str]:
    """Calculate SHA-256, MD5, and SHA-1 digests using streaming 64KB blocks."""
    sha256_hasher = hashlib.sha256()
    md5_hasher = hashlib.md5()
    sha1_hasher = hashlib.sha1()

    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256_hasher.update(chunk)
            md5_hasher.update(chunk)
            sha1_hasher.update(chunk)

    return sha256_hasher.hexdigest(), md5_hasher.hexdigest(), sha1_hasher.hexdigest()


def compute_sha256(filepath: Path) -> str:
    """Calculate the SHA-256 digest of a file using streaming 64KB blocks."""
    sha256, _, _ = compute_hashes(filepath)
    return sha256


def _normalize_permission_name(perm: str) -> str:
    """Normalize full Android permission strings (e.g. 'android.permission.READ_SMS' -> 'READ_SMS')."""
    if not perm:
        return ""
    clean = perm.strip()
    if clean.startswith("android.permission."):
        return clean.replace("android.permission.", "").strip()
    return clean.split(".")[-1].strip()


def _is_sms_permission(perm: str) -> bool:
    norm = _normalize_permission_name(perm).upper()
    return norm in SMS_PERMISSIONS or perm.strip() in {f"android.permission.{p}" for p in SMS_PERMISSIONS}


def _is_accessibility_permission(perm: str) -> bool:
    norm = _normalize_permission_name(perm).upper()
    return norm == "BIND_ACCESSIBILITY_SERVICE" or perm.strip() == "android.permission.BIND_ACCESSIBILITY_SERVICE"


def _is_install_permission(perm: str) -> bool:
    norm = _normalize_permission_name(perm).upper()
    return norm in INSTALL_PERMISSIONS or perm.strip() in {f"android.permission.{p}" for p in INSTALL_PERMISSIONS}


def _is_network_permission(perm: str) -> bool:
    norm = _normalize_permission_name(perm).upper()
    return norm in NETWORK_PERMISSIONS or perm.strip() in {f"android.permission.{p}" for p in NETWORK_PERMISSIONS}


def _is_dangerous_permission(perm: str) -> bool:
    norm = _normalize_permission_name(perm).upper()
    return norm in DANGEROUS_PERMISSIONS or perm.strip() in {f"android.permission.{p}" for p in DANGEROUS_PERMISSIONS}


def _inspect_accessibility_service(apk: APK) -> bool:
    """Inspect declared manifest <service> elements for AccessibilityService declarations."""
    try:
        manifest_xml = apk.get_android_manifest_xml()
        if manifest_xml is not None:
            for service in manifest_xml.iter("service"):
                for attr_key, attr_val in service.attrib.items():
                    if "permission" in attr_key.lower() and "BIND_ACCESSIBILITY_SERVICE" in attr_val:
                        return True
                for action in service.iter("action"):
                    for attr_key, attr_val in action.attrib.items():
                        if "name" in attr_key.lower() and attr_val == "android.accessibilityservice.AccessibilityService":
                            return True
    except Exception as e:
        logger.debug(f"ANDROGUARD: Accessibility service manifest check note: {e}")
    return False


def _extract_exported_components(apk: APK) -> List[str]:
    """Identify components in the manifest explicitly exported to other apps."""
    exported = []
    try:
        manifest_xml = apk.get_android_manifest_xml()
        if manifest_xml is not None:
            for tag in ["activity", "service", "receiver", "provider"]:
                for el in manifest_xml.iter(tag):
                    name = None
                    is_exported = False
                    for k, v in el.attrib.items():
                        if "name" in k.lower():
                            name = v
                        if "exported" in k.lower() and str(v).lower() == "true":
                            is_exported = True
                    # If intent filter exists without explicit exported=false on older SDKs, it may be exported
                    if is_exported and name:
                        short_name = name.split(".")[-1]
                        exported.append(f"{tag.upper()}: {short_name}")
    except Exception as e:
        logger.debug(f"ANDROGUARD: Exported components check note: {e}")
    return exported[:25]


def _extract_certificate_info(apk: APK) -> Dict[str, Any]:
    """Safely extract X.509 certificate and signing evidence using Androguard."""
    info: Dict[str, Any] = {
        "has_signature": False,
        "certificate_count": 0,
        "certificates": [],
        "signatures": {"v1": False, "v2": False, "v3": False},
        "self_signed": False,
    }

    try:
        info["signatures"]["v1"] = bool(apk.get_certificates_v1())
        info["signatures"]["v2"] = bool(apk.get_certificates_v2())
        info["signatures"]["v3"] = bool(apk.get_certificates_v3())

        certs = apk.get_certificates()
        if certs:
            info["has_signature"] = True
            info["certificate_count"] = len(certs)

            for cert in certs:
                cert_entry: Dict[str, Any] = {}
                try:
                    if hasattr(cert, "subject"):
                        cert_entry["subject"] = cert.subject.human_friendly if hasattr(cert.subject, "human_friendly") else str(cert.subject)
                    if hasattr(cert, "issuer"):
                        cert_entry["issuer"] = cert.issuer.human_friendly if hasattr(cert.issuer, "human_friendly") else str(cert.issuer)
                    if hasattr(cert, "serial_number"):
                        sn = cert.serial_number
                        cert_entry["serial_number"] = hex(sn) if isinstance(sn, int) else str(sn)
                    if hasattr(cert, "not_valid_before"):
                        cert_entry["valid_from"] = str(cert.not_valid_before)
                    if hasattr(cert, "not_valid_after"):
                        cert_entry["valid_to"] = str(cert.not_valid_after)
                    if hasattr(cert, "sha256_fingerprint"):
                        cert_entry["sha256_fingerprint"] = cert.sha256_fingerprint
                    if hasattr(cert, "sha1_fingerprint"):
                        cert_entry["sha1_fingerprint"] = cert.sha1_fingerprint
                    if hasattr(cert, "self_signed"):
                        cert_entry["self_signed"] = cert.self_signed
                        if cert.self_signed:
                            info["self_signed"] = True
                except Exception as ce:
                    logger.debug(f"ANDROGUARD: Certificate field extraction note: {ce}")

                info["certificates"].append(cert_entry)

            if info["certificates"]:
                primary = info["certificates"][0]
                info["issuer"] = primary.get("issuer", "")
                info["subject"] = primary.get("subject", "")
                info["serial"] = primary.get("serial_number", "")
                info["valid_from"] = primary.get("valid_from", "")
                info["valid_to"] = primary.get("valid_to", "")
                info["sha256_fingerprint"] = primary.get("sha256_fingerprint", "")
                info["self_signed"] = primary.get("self_signed", False)

    except Exception as e:
        logger.warning(f"ANDROGUARD: Certificate analysis encountered an issue: {e}")
        info["extraction_error"] = str(e)

    return info


def _validate_apk_zip(filepath: Path) -> Tuple[bool, str]:
    """Pre-flight check to verify file is a regular ZIP archive containing Android artifacts."""
    if not zipfile.is_zipfile(filepath):
        return False, "Not a valid ZIP/APK archive"

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            names = set(zf.namelist())
            has_manifest = "AndroidManifest.xml" in names
            has_dex = any(n.endswith(".dex") for n in names)
            if not has_manifest and not has_dex:
                return False, "Archive does not contain Android manifest or DEX bytecode"
            return True, ""
    except zipfile.BadZipFile as e:
        return False, f"Malformed ZIP archive: {e}"
    except Exception as e:
        return False, f"ZIP inspection error: {e}"


# ─── PRIMARY ANALYSIS PIPELINE ──────────────────────────────────────────────
def analyze_apk_file(filepath: Union[str, Path]) -> ApkAnalysisResult:
    """
    Perform deep static analysis on an Android APK package using Androguard.
    Treats permissions as technical capabilities, not malware proof.
    """
    path = Path(filepath).resolve()
    if not path.exists() or not path.is_file():
        logger.error(f"ANDROGUARD: Target file does not exist: {path.name}")
        return ApkAnalysisResult(
            filename=path.name,
            status="failed",
            reason=f"Target APK file not found: {path.name}",
        )

    size_bytes = path.stat().st_size
    size_mb = f"{round(size_bytes / (1024 * 1024), 2)} MB"
    file_sha256, file_md5, file_sha1 = compute_hashes(path)

    logger.info(f"ANDROGUARD: Commencing analysis of '{path.name}' ({size_mb}, SHA256={file_sha256[:12]}...)")

    result = ApkAnalysisResult(
        filename=path.name,
        size_bytes=size_bytes,
        size_mb=size_mb,
        sha256=file_sha256,
        md5=file_md5,
        sha1=file_sha1,
        status="completed",
    )

    # Pre-flight ZIP sanity check
    is_valid_zip, zip_err = _validate_apk_zip(path)
    if not is_valid_zip:
        logger.warning(f"ANDROGUARD: Pre-flight ZIP check failed for '{path.name}': {zip_err}")
        result.status = "failed"
        result.reason = zip_err
        result.certificate_info = {"preflight_error": zip_err, "has_signature": False}
        return result

    # Primary analysis using Androguard
    try:
        apk = APK(str(path))
        if not apk.is_valid_APK():
            logger.warning(f"ANDROGUARD: Androguard reported APK as invalid for '{path.name}'")

        # 1. Package Name and Metadata
        result.package_name = apk.get_package() or ""
        try:
            result.app_name = apk.get_app_name() or None
        except Exception:
            result.app_name = None

        result.min_sdk_version = str(apk.get_min_sdk_version()) if apk.get_min_sdk_version() is not None else None
        result.target_sdk_version = str(apk.get_target_sdk_version()) if apk.get_target_sdk_version() is not None else None
        result.version_name = str(apk.get_androidversion_name()) if apk.get_androidversion_name() is not None else None
        result.version_code = str(apk.get_androidversion_code()) if apk.get_androidversion_code() is not None else None

        # 2. Permissions (Requested & Declared)
        raw_perms: List[str] = list(apk.get_permissions() or [])
        declared: List[str] = list(apk.get_declared_permissions() or [])
        all_perms: List[str] = sorted(list(set(raw_perms)))

        result.permissions = all_perms
        result.declared_permissions = declared

        # 3. Categorize Capabilities
        result.dangerous_permissions = [p for p in all_perms if _is_dangerous_permission(p)]
        result.has_sms_permissions = any(_is_sms_permission(p) for p in all_perms)

        has_acc_perm = any(_is_accessibility_permission(p) for p in all_perms)
        has_acc_service = _inspect_accessibility_service(apk)
        result.has_accessibility_service = has_acc_perm or has_acc_service

        result.has_install_packages = any(_is_install_permission(p) for p in all_perms)
        result.has_network_capabilities = any(_is_network_permission(p) for p in all_perms)

        # 4. Activities, Services, Receivers, Providers
        try:
            result.activities = list(apk.get_activities() or [])[:50]
            result.services = list(apk.get_services() or [])[:50]
            result.receivers = list(apk.get_receivers() or [])[:50]
            result.providers = list(apk.get_providers() or [])[:50]
            result.exported_components = _extract_exported_components(apk)
        except Exception as ce:
            logger.debug(f"ANDROGUARD: Component extraction note: {ce}")

        # 5. Certificates and Signatures
        result.certificate_info = _extract_certificate_info(apk)

        logger.info(
            f"ANDROGUARD: Completed static analysis for '{path.name}' — "
            f"Package: '{result.package_name}', "
            f"Label: '{result.app_name or 'N/A'}', "
            f"Permissions: {len(result.permissions)} (Dangerous: {len(result.dangerous_permissions)}), "
            f"SMS: {result.has_sms_permissions}, "
            f"Accessibility: {result.has_accessibility_service}, "
            f"Installer: {result.has_install_packages}, "
            f"Signatures: {result.certificate_info.get('has_signature', False)}"
        )

    except Exception as e:
        logger.warning(f"ANDROGUARD: Analysis error on '{path.name}': {e}")
        if not result.certificate_info:
            result.certificate_info = {}
        result.certificate_info["analysis_error"] = str(e)
        result.status = "failed"
        result.reason = f"Androguard parser error: {str(e)}"

    return result


def analyze_apk_metadata(
    filename: str,
    file_hash: str,
    package_name: str,
    permissions: List[str],
    size: str,
) -> ApkAnalysisResult:
    """Construct standardized APK technical evidence from pre-parsed metadata."""
    logger.info(f"ANDROGUARD: Processing pre-parsed metadata for '{filename}'")

    perms = sorted(list(set(permissions or [])))
    dangerous = [p for p in perms if _is_dangerous_permission(p)]

    return ApkAnalysisResult(
        filename=filename,
        size_mb=size,
        sha256=file_hash,
        package_name=package_name,
        permissions=perms,
        dangerous_permissions=dangerous,
        has_sms_permissions=any(_is_sms_permission(p) for p in perms),
        has_accessibility_service=any(_is_accessibility_permission(p) for p in perms),
        has_install_packages=any(_is_install_permission(p) for p in perms),
        has_network_capabilities=any(_is_network_permission(p) for p in perms),
        certificate_info={"pre_parsed": True},
        status="completed",
    )
