import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine.fusion import make
from analyzers.link_qr import brand_hits

P = "android.permission."
SMS = {P + "READ_SMS", P + "RECEIVE_SMS"}
OVERLAY = P + "SYSTEM_ALERT_WINDOW"
CALL_CONTROL = {P + "PROCESS_OUTGOING_CALLS", P + "MODIFY_PHONE_STATE"}
DANGEROUS = {P + x for x in (
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "READ_CALL_LOG",
    "CALL_PHONE", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_PHONE_STATE",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "READ_PHONE_NUMBERS")}


def read_apk(path):
    try:
        from androguard.core.apk import APK
    except ImportError:
        from androguard.core.bytecodes.apk import APK  # type: ignore
    apk = APK(str(path))
    manifest = apk.get_android_manifest_axml().get_xml()  # type: ignore
    if isinstance(manifest, bytes):
        manifest = manifest.decode("utf-8", "ignore")
    try:
        signed = bool(apk.is_signed())
    except Exception:
        signed = True  # unknown: do not penalise
    return {  
        "name": apk.get_app_name() or "",
        "package": apk.get_package() or "",
        "permissions": set(apk.get_permissions()),
        "manifest": manifest,
        "has_launcher": bool(apk.get_main_activities()),
        "signed": signed,
    }


def signals_from_facts(f):
    perms = f["permissions"]
    manifest = f.get("manifest", "")
    out = []

    def add(sid, strength, evidence):
        out.append(make(sid, strength, evidence))

    has_sms = bool(perms & SMS)
    if has_sms and OVERLAY in perms:
        add("app_sms_plus_overlay", 1.0, "can read SMS and draw over other apps")
    if has_sms:
        add("app_sms_read", 1.0, "reads incoming text messages")
    if "BIND_ACCESSIBILITY_SERVICE" in manifest:
        add("app_accessibility_service", 1.0, "registers an accessibility service")
    if "BIND_DEVICE_ADMIN" in manifest:
        add("app_device_admin", 1.0, "requests device-administrator rights")
    if perms & CALL_CONTROL:
        add("app_call_forwarding", 0.8, "can intercept or redirect calls")
    if not f.get("has_launcher", True):
        add("app_hides_icon", 0.7, "no launcher entry, so it will not appear in your app list")

    n = len(perms & DANGEROUS)
    if n >= 8:
        add("app_excess_permissions", 1.0, f"{n} sensitive permissions")
    elif n >= 5:
        add("app_excess_permissions", 0.7, f"{n} sensitive permissions")

    if not f.get("signed", True):
        add("app_unverified_signer", 1.0, "no valid publisher signature")

    # Name imitates a brand, but the package identity does not carry it.
    name_tokens = list({*re.findall(r"[a-z0-9]+", f["name"].lower()),
                        re.sub(r"[^a-z0-9]", "", f["name"].lower())})
    pkg = f["package"].lower()
    for brand, (kind, tok, prio, b) in brand_hits(name_tokens).items():
        if not any(t in pkg for t in b["tokens"]):
            add("app_name_mimics_bank", 0.9, f"app name imitates {brand}")
            add("app_package_mismatch", 1.0,
                f"named like {brand} but its package is {f['package']}")
            break
    return out


def analyze(path):
    return signals_from_facts(read_apk(path))