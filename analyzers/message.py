"""Reads message wording and turns it into signals."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzers.urls import find_urls
from engine.fusion import make

# Warnings that genuine banks include; removed so they never trigger a signal.
WARNING = re.compile(r"\b(do not|don't|dont|never)\s+(share|disclose|reveal|give)\b[^.\n]*", re.I)
# Genuine alerts tell you to call a toll-free helpline if a payment was not yours.
# Scams give a mobile number or a link instead, so only the toll-free form is ignored.
DISPUTE_SAFE = re.compile(
    r"\bif (?:this was |it was )?not (?:you|done by you)[,:]?\s*(?:please\s+)?call\s+(?:our\s+)?(?:toll[- ]free\s+)?(?:number\s+)?(?:1800|1860)(?:[\s\-]?\d+)*(?:\s+(?:immediately|now|at once))?",
    re.I)
ACTION_WORDS = re.compile(
    r"\b(click|tap|call|install|download|share|send|pay|reply|update|verify|visit|open|enter)\b", re.I)
MASKED_ACCOUNT = re.compile(r"(a/c|acct|account|card)[^.\n]{0,15}(x{2,}|\*{2,})\s?\d{3,4}", re.I)
# Sharing a delivery OTP face-to-face at the doorstep is materially different from
# asking someone to disclose a banking OTP over a call or message.
IN_PERSON_DELIVERY_OTP = re.compile(
    r"\b(share|give|tell|provide)\b[^.\n]{0,35}\b(delivery\s+)?otp\b"
    r"[^.\n]{0,80}\b(with|to)\s+(the\s+)?(delivery\s+)?agent\b"
    r"[^.\n]{0,45}\b(at your doorstep|when the agent arrives|in person)\b", re.I)
SHORT = r"(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co|goo\.gl|shorturl\.at|tiny\.cc|ow\.ly)/\S+"

# signal id -> list of (pattern, strength). The strongest match wins.
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
        # Allow natural wording between the payment verb and amount, e.g. "pay a refundable
        # registration fee of ₹499", while requiring an explicit payment/fee context.
        (r"\b(pay(?!\s+balance\b)|deposit|transfer|send)\b[^.\n]{0,90}(₹|rs\.?|inr)\s?\d", 1.0),
        (r"\b(pay|deposit|transfer|send)\s+(rs\.?\s?|inr\s?|₹\s?)?\d{3,}\b", 0.8),
        (r"\b(fee|charge|penalty|fine)\b[^.\n]{0,25}\b(pay|due|pending)\b", 0.7),
    ],
    "msg_threat_block": [
        (r"\bwill be (blocked|suspended|deactivated|frozen|closed|cancelled|disconnected|terminated|cut|disabled|barred|locked)\b", 1.0),
        (r"\b(legal action|arrest|police case|fir)\b", 1.0),
        (r"\b(band|block|suspend)\s+ho\s+(jayega|jaega|jayegi|jaayega)\b", 1.0),
        (r"\b(illegal activity|money laundering|digital arrest|case (has been )?(registered|filed) against you)\b", 1.0),
        (r"\baccount (is )?(blocked|suspended|frozen)\b", 0.6),
    ],
    "msg_authority_claim": [
        (r"\b(calling from|i am from|bank officer|customer care executive)\b", 1.0),
        (r"\bdear (customer|user|sir|madam|account holder)\b", 0.5),
        (r"\b(rto|echallan|challan|parivahan)\b", 0.8),
        (r"\b(package|parcel|courier|delivery|order)\b[^.\n]{0,55}\b(held|stuck|pending|undelivered|returned|failed|could not be delivered|delivery failed)\b", 0.8),
        (r"\b(incorrect|incomplete|wrong) address\b|\baddress\b[^.\n]{0,20}\b(incorrect|incomplete|wrong)\b|\b(address details|delivery details)\b[^.\n]{0,35}\b(update|verify|confirm)\b", 0.7),
        (r"\b(sbi|hdfc|icici|axis|kotak|pnb|bank of baroda|rbi|paytm|phonepe|income tax|police|cbi|customs|trai|uidai|india post|bluedart|dtdc|delhivery)\b", 0.6),
    ],
    "msg_reward_lure": [
        (r"\b(you have won|lottery|lucky winner|claim your (prize|reward|gift))\b", 1.0),
        (r"\b(refund|cashback|reward points)\b[^.\n]{0,30}\b(claim|credit|expire|pending)\b", 0.7),
    ],
    "msg_deadline_pressure": [
        (r"\bwithin\s+\d+\s*(hours|hrs|minutes|mins)\b", 1.0),
        (r"\b(immediately|urgent(ly)?|last chance|today only|expires today)\b", 0.8),
    ],
    "msg_unknown_shortlink": [(r"\b" + SHORT, 1.0)],
    "msg_wrong_transfer": [
        (r"\b(by mistake|wrongly|wrong number|wrong account)\b.{0,80}\b(return|send back|refund|transfer back|give back)\b", 1.0),
        (r"\b(return|send back|refund|give back)\b[^.\n]{0,50}\b(amount|money|payment)\b[^.\n]{0,40}\b(by mistake|wrongly)\b", 1.0),
    ],
    "msg_job_lure": [
        # Require both a recruitment context and an upfront-fee/deposit request.
        # Ordinary job adverts and interview invitations must not trigger this signal.
        (r"(?=.*\b(job|position|role|internship|recruitment|work from home|shortlisted|interview|employee id)\b)(?=.*\b(registration fee|joining fee|security deposit|processing fee|onboarding fee|refundable fee|employee id generation|pay.{0,35}(fee|deposit))\b).+", 1.0),
        (r"\bjoining (fee|kit|charges?)\b", 0.8),
    ],
    "msg_job_fee": [
        # A fee/deposit explicitly tied to recruitment is a high-confidence fraud indicator.
        (r"(?=.*\b(job|position|role|internship|recruitment|work from home|shortlisted|interview|employee id)\b)(?=.*\b(registration fee|joining fee|security deposit|processing fee|onboarding fee|refundable fee|employee id generation|pay.{0,45}(fee|deposit))\b).+", 1.0),
    ],
    "msg_investment_lure": [
        # High-return guarantees tied to an investment or crypto offer are a strong scam pattern.
        (r"(?=.*\b(invest|investment|crypto|trading plan)\b)(?=.*\b(guaranteed|assured|fixed)\s+returns?\b).+", 1.0),
        (r"(?=.*\b(invest|investment|crypto|trading plan)\b)(?=.*\b(double|triple)\s+(your\s+)?money\b).+", 1.0),
    ],
    "msg_card_charge_impersonation": [
        # Banks use published toll-free numbers for disputes; unsolicited mobile helplines are suspicious.
        (r"\b(credit card|debit card|card|account)\b[^\n]{0,65}\b(charged|debited|transaction|purchase)\b[^\n]{0,100}\b(if not (you|authori[sz]ed)|not you)\b[^\n]{0,55}\b(call|contact)\b[^\n]{0,35}\b[6-9]\d{9}\b", 1.0),
    ],
    "msg_family_impersonation": [
        (r"\bmy phone (broke|is broken|got (broken|damaged|lost))\b", 0.8),
        (r"\bthis is my new (phone )?number\b", 0.8),
        (r"\b(hi|hello)\s+(mom|mum|dad|mummy|papa)\b", 0.7),
    ],
}
COMPILED = {sid: [(re.compile(p, re.I), s) for p, s in rules] for sid, rules in RULES.items()}


def analyze(text):
    text = text or ""
    clean = IN_PERSON_DELIVERY_OTP.sub(" ", DISPUTE_SAFE.sub(" ", WARNING.sub(" ", text)))
    signals = []
    for sid, rules in COMPILED.items():
        best = None
        for pattern, strength in rules:
            m = pattern.search(clean)
            if m and (best is None or strength > best[0]):
                best = (strength, m.group(0).strip()[:80])
        if best:
            signals.append(make(sid, best[0], best[1]))

    # Reassuring signs apply only when there is no link and nothing serious was found.
    has_link = bool(find_urls(text))
    serious = {"credential_theft", "device_takeover", "financial_redirect", "urgency"}
    if not has_link and not any(s["category"] in serious for s in signals):
        if MASKED_ACCOUNT.search(text or ""):
            signals.append(make("known_sender_format", 1.0, "masked account number, no link"))
        if not ACTION_WORDS.search(clean):
            signals.append(make("no_action_requested", 1.0, "no action requested"))
    return signals
