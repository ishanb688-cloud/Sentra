import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine.fusion import make

# Warnings that genuine banks include; remove them so they never trigger a signal.
WARNING = re.compile(r"\b(do not|don't|dont|never)\s+(share|disclose|reveal|give)\b[^.\n]*", re.I)

URL = re.compile(
    r"https?://\S+|www\.\S+|\b\S+\.(?:com|in|xyz|top|apk|co|net|org)/\S*"
    r"|\b(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co|goo\.gl|shorturl\.at)/\S+",
    re.I,
)

ACTION_WORDS = re.compile(
    r"\b(click|tap|call|install|download|share|send|pay|reply|update|verify|visit|open|enter)\b", re.I
)

MASKED_ACCOUNT = re.compile(r"(a/c|acct|account|card)[^.\n]{0,15}(x{2,}|\*{2,})\s?\d{3,4}", re.I)

# signal id -> list of (pattern, strength). The best match wins.
RULES = {
    "msg_otp_request": [
        (r"\b(share|send|tell|give|provide|forward|read out|enter|confirm)\b[^.\n]{0,25}\b(otp|pin|cvv|password|passcode)\b", 1.0),
    ],
    "msg_install_request": [
        (r"\b(install|download)\b[^.\n]{0,30}\b(app|apk|file|application)\b", 1.0),
        (r"\.apk\b", 0.9),
    ],
    "msg_secrecy_isolation": [
        (r"\b(do not|don't|dont)\s+(tell|inform)\s+(anyone|anybody|family|your family)\b", 1.0),
        (r"\bstay on (the )?(line|call)\b", 0.8),
    ],
    "msg_kyc_update": [
        (r"\bkyc\b[^.\n]{0,40}\b(update|expire|expired|pending|verify|incomplete)\b", 1.0),
        (r"\b(update|verify|complete)\b[^.\n]{0,20}\b(kyc|pan|aadhaar|aadhar)\b", 0.9),
    ],
    "msg_payment_demand": [
        (r"\b(pay|deposit|transfer|send)\b[^.\n]{0,25}(₹|rs\.?|inr)\s?\d", 1.0),
        (r"\b(fee|charge|penalty|fine)\b[^.\n]{0,25}\b(pay|due|pending)\b", 0.7),
    ],
    "msg_threat_block": [
        (r"\bwill be (blocked|suspended|deactivated|frozen|closed|cancelled)\b", 1.0),
        (r"\b(legal action|arrest|police case|fir)\b", 1.0),
        (r"\baccount (is )?(blocked|suspended|frozen)\b", 0.6),
    ],
    "msg_authority_claim": [
        (r"\b(calling from|i am from|bank officer|customer care executive|dear customer)\b", 1.0),
        (r"\b(rto|echallan|challan|parivahan)\b", 0.8),
        (r"\b(package|parcel|courier)\b[^.\n]{0,20}\b(held|stuck|pending|undelivered|returned)\b", 0.8),
        (r"\b(sbi|hdfc|icici|axis|kotak|pnb|bank of baroda|rbi|paytm|phonepe|income tax|police|cbi|customs|trai|uidai|india post|bluedart|dtdc|delhivery)\b", 0.6),
    ],
    "msg_reward_lure": [
        (r"\b(you have won|lottery|lucky winner|claim your (prize|reward|gift))\b", 1.0),
        (r"\b(refund|cashback|reward points)\b[^.\n]{0,30}\b(claim|credit|expire|pending)\b", 0.7),
    ],
    "msg_deadline_pressure": [
        (r"\bwithin\s+\d+\s*(hours|hrs|minutes|mins)\b", 1.0),
        (r"\b(immediately|urgent|last chance|today only|expires today)\b", 0.8),
    ],
    "msg_unknown_shortlink": [
        (r"\b(bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co|goo\.gl|shorturl\.at)/\S+", 1.0),
    ],
}

COMPILED = {sid: [(re.compile(p, re.I), s) for p, s in rules] for sid, rules in RULES.items()}


def analyze(text):
    clean = WARNING.sub(" ", text)
    signals = []

    for sid, rules in COMPILED.items():
        best = None
        for pattern, strength in rules:
            m = pattern.search(clean)
            if m and (best is None or strength > best[0]):
                best = (strength, m.group(0).strip()[:80])
        if best:
            signals.append(make(sid, best[0], best[1]))

    # Dampeners: only when there is no link and nothing serious was found.
    has_link = bool(URL.search(clean))
    serious = {"credential_theft", "device_takeover", "financial_redirect", "urgency"}
    if not has_link and not any(s["category"] in serious for s in signals):
        if MASKED_ACCOUNT.search(text):
            signals.append(make("known_sender_format", 1.0, "masked account number, no link"))
        if not ACTION_WORDS.search(clean):
            signals.append(make("no_action_requested", 1.0, "no action requested"))

    return signals