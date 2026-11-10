"""Reads an Android app file statically. The app is never installed or run."""
import json
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzers.link_qr import BRANDS, brand_hits
from engine.fusion import make

log = logging.getLogger("sentra")
try:  # androguard logs thousands of debug lines per app; keep the server quiet
    from loguru import logger as _loguru
    _loguru.disable("androguard")
except Exception:
    pass

P = "android.permission."
SMS = {P + "READ_SMS", P + "RECEIVE_SMS"}
OVERLAY = P + "SYSTEM_ALERT_WINDOW"
CALL_CONTROL = {P + "PROCESS_OUTGOING_CALLS", P + "MODIFY_PHONE_STATE"}
INSTALLER = P + "REQUEST_INSTALL_PACKAGES"
DANGEROUS = {P + x for x in (
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "READ_CALL_LOG",
    "CALL_PHONE", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_PHONE_STATE",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "READ_PHONE_NUMBERS")}
PAYLOAD_EXT = (".apk", ".jar")


def read_apk(path):
    """Extract facts from an app file. Every fact is read defensively, so a
    damaged file degrades gracefully instead of crashing the check."""
    try:
        from androguard.core.apk import APK
    except ImportError:
        from androguard.core.bytecodes.apk import APK
    apk = APK(str(path))

    def safe(fn, default):
        try:
            return fn()
        except Exception:
            return default

    manifest = safe(lambda: apk.get_android_manifest_axml().get_xml(), b"")
    if isinstance(manifest, bytes):
        manifest = manifest.decode("utf-8", "ignore")
    certs = safe(apk.get_certificates, [])
    subjects = [safe(lambda c=c: c.subject.human_friendly, "") for c in certs]
    files = safe(apk.get_files, [])
    payload = [f for f in files
               if f.lower().endswith(PAYLOAD_EXT)
               or (f.lower().endswith(".dex") and not re.match(r"^classes\d*\.dex$", f))]
    prios = [int(x) for x in re.findall(r'android:priority="?(-?\d+)', manifest)]
    sms_receiver = "SMS_RECEIVED" in manifest
    return {
        "name": safe(apk.get_app_name, "") or "",
        "package": safe(apk.get_package, "") or "",
        "permissions": set(safe(apk.get_permissions, [])),
        "manifest": manifest,
        "has_launcher": bool(safe(apk.get_main_activities, [1])),
        "signed": bool(safe(apk.is_signed, True)),
        "debug_cert": any("android debug" in s.lower() for s in subjects),
        "payload_files": payload[:5],
        "sms_priority": max(prios) if (sms_receiver and prios) else 0,
    }


def signals_from_facts(f):
    perms = set(f.get("permissions", ()))
    manifest = f.get("manifest", "")
    out = []

    def add(sid, strength, evidence):
        out.append(make(sid, strength, evidence))

    has_sms = bool(perms & SMS)
    if has_sms and OVERLAY in perms:
        add("app_sms_plus_overlay", 1.0, "can read SMS and draw over other apps")
    if has_sms:
        add("app_sms_read", 1.0, "reads incoming text messages")
    if f.get("sms_priority", 0) >= 999:
        add("app_sms_interceptor", 1.0, "intercepts incoming SMS with top priority")
    if "BIND_ACCESSIBILITY_SERVICE" in manifest:
        add("app_accessibility_service", 1.0, "registers an accessibility service")
    if "BIND_DEVICE_ADMIN" in manifest:
        add("app_device_admin", 1.0, "requests device-administrator rights")
    if perms & CALL_CONTROL:
        add("app_call_forwarding", 0.8, "can intercept or redirect calls")
    if not f.get("has_launcher", True):
        add("app_hides_icon", 0.7, "no launcher entry, so it will not appear in your app list")
    if f.get("payload_files"):
        add("app_embedded_payload", 1.0, "contains hidden files: " + ", ".join(f["payload_files"][:2]))
    if INSTALLER in perms:
        add("app_installer_permission", 1.0, "can install other apps")
    if f.get("debug_cert"):
        add("app_debug_certificate", 1.0, "signed with a developer debug certificate")
    if not f.get("signed", True):
        add("app_unverified_signer", 1.0, "no valid publisher signature")

    n = len(perms & DANGEROUS)
    if n >= 8:
        add("app_excess_permissions", 1.0, f"{n} sensitive permissions")
    elif n >= 5:
        add("app_excess_permissions", 0.7, f"{n} sensitive permissions")

    # Name imitates a brand: compare the package with the brand's official app IDs.
    name_tokens = list({*re.findall(r"[a-z0-9]+", f.get("name", "").lower()),
                        re.sub(r"[^a-z0-9]", "", f.get("name", "").lower())})
    pkg = f.get("package", "")
    for brand, (kind, tok, prio, b) in brand_hits(name_tokens).items():
        official = b.get("packages") or []
        if pkg in official:
            continue
        if official:
            add("app_name_mimics_bank", 0.9, f"app name imitates {brand}")
            add("app_package_mismatch", 1.0,
                f"named like {brand} but its package is {pkg}, not {official[0]}")
        elif not any(t in pkg.lower() for t in b["tokens"]):
            add("app_name_mimics_bank", 0.9, f"app name imitates {brand}")
            add("app_package_mismatch", 0.8, f"named like {brand} but its package is {pkg}")
        break
    return out


def analyze(path):
    return signals_from_facts(read_apk(path))
