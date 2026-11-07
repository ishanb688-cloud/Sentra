import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzers.link_qr import analyze
from engine.fusion import fuse

cases = {
    "keyword domain + login": ("http://sbi-kyc-update.xyz/login", None),
    "official bank page": ("https://www.sbi.co.in/web/personal-banking", None),
    "brand in subdomain": ("https://sbi.co.in.secure-verify.com/login", None),
    "typo domain": ("http://hdfcbnak.com/netbanking", None),
    "homoglyph domain": ("https://amaz0n.in/refund", None),
    "raw IP": ("http://192.168.4.7/kyc", None),
    "punycode": ("https://xn--amazon-9ve.in/offer", None),
    "shortener": ("bit.ly/3xYz", None),
    "apk link": ("http://rto-echallan.apk", "RTO Challan pending, download to pay"),
    "UPI receive trick": ("upi://pay?pa=9876543210@ybl&pn=Ramesh&am=5000",
                          "You have won Rs 5000 cashback, scan to receive"),
    "UPI payee mismatch": ("upi://pay?pa=rajesh1234@okaxis&pn=Rajesh%20K&am=499",
                           "Pay Rs 499 for your Amazon order"),
}

for name, (text, ctx) in cases.items():
    sigs = analyze(text, ctx)
    r = fuse(sigs)
    print(f"{name:24} risk={r['risk']:<6} level={r['level']}")
    for s in sigs:
        print(f"   {s['id']:26} {s['strength']:<4} {s['evidence']}")