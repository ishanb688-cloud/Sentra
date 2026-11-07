import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzers.pipeline import scan as analyze
from engine.fusion import fuse

messages = {
    "genuine bank debit alert":
        "Rs 2,500.00 debited from A/c XX1234 on 06-11-26. If not you, call 1800-000-000. Do not share OTP with anyone. -SBI",
    "fake KYC scam":
        "Dear customer, your SBI account will be blocked today. Update your KYC immediately: http://sbi-kyc-update.xyz/login and share the OTP you receive.",
    "courier fee scam":
        "Your package is held. Pay Rs 49 customs fee within 24 hours to release: bit.ly/3xYz",
    "fake challan app":
        "RTO Challan pending. Download the app from the link to pay: http://rto-echallan.apk",
    "friend message":
        "Hey are you coming for dinner tonight? Call me when you reach.",
    "genuine bill reminder":
        "HDFC Bank: Your credit card bill of Rs 12,400 is due on 10-Nov. Pay via the HDFC app or netbanking. Ignore if already paid.",
}

for name, text in messages.items():
    sigs = analyze(text)
    r = fuse(sigs)
    print(f"{name:26} risk={r['risk']:<6} level={r['level']:<13} chain={r['chain']}")
    print("   signals:", ", ".join(s["id"] for s in sigs) or "none")