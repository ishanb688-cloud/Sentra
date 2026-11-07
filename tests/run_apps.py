import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzers.app_file import signals_from_facts, analyze
from engine.fusion import fuse

P = "android.permission."

apps = {
    "fake KYC banking app": {
        "name": "SBI KYC Update", "package": "com.update.kyc.service",
        "permissions": {P + "READ_SMS", P + "RECEIVE_SMS", P + "SYSTEM_ALERT_WINDOW",
                        P + "READ_CONTACTS", P + "CALL_PHONE", P + "READ_PHONE_STATE"},
        "manifest": "BIND_ACCESSIBILITY_SERVICE", "has_launcher": True, "signed": False,
    },
    "RTO challan dropper": {
        "name": "Parivahan e-Challan", "package": "com.pay.fine.app",
        "permissions": {P + "READ_SMS", P + "SYSTEM_ALERT_WINDOW"},
        "manifest": "", "has_launcher": False, "signed": True,
    },
    "ordinary notes app": {
        "name": "Daily Notes", "package": "com.example.dailynotes",
        "permissions": {P + "READ_EXTERNAL_STORAGE", P + "WRITE_EXTERNAL_STORAGE"},
        "manifest": "", "has_launcher": True, "signed": True,
    },
    "genuine-style bank app": {
        "name": "SBI YONO", "package": "com.sbi.lotusintouch",
        "permissions": {P + "READ_SMS", P + "CAMERA", P + "ACCESS_FINE_LOCATION"},
        "manifest": "", "has_launcher": True, "signed": True,
    },
}

if len(sys.argv) > 1:
    sigs = analyze(sys.argv[1])
    r = fuse(sigs)
    print(f"{sys.argv[1]}  risk={r['risk']}  level={r['level']}  chain={r['chain']}")
    for s in sigs:
        print(f"   {s['id']:26} {s['strength']:<4} {s['evidence']}")
else:
    for name, facts in apps.items():
        sigs = signals_from_facts(facts)
        r = fuse(sigs)
        print(f"{name:24} risk={r['risk']:<6} level={r['level']:<13} chain={r['chain']}")
        for s in sigs:
            print(f"   {s['id']:26} {s['strength']:<4} {s['evidence']}")