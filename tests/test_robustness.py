"""Garbage in must never crash the analyzers."""
from analyzers.pipeline import scan
from engine.fusion import fuse

NASTY = ["", " ", "\x00\x01\x02", "http://[::1", "http://:80", "http://a:99999999/x", "upi://pay?pa=%%&pn=%zz",
         "upi://pay?", "https://" + "a" * 500 + ".com", "x" * 100000, "💥" * 500, "http://", "www.", "@@@@",
         "bit.ly/", "http://user:pass@@host", "http://xn--/", "\u202e\u202erevo", "a.b.c.d.e.f.g.h.i.j.k.com",
         "upi://pay?pa=" + "a" * 5000 + "@ybl", "((((((((((", "%s%s%s%d"]


def test_analyzers_survive_malformed_input():
    for text in NASTY:
        result = fuse(scan(text))
        assert result["level"]


def test_same_message_gets_the_same_score_every_time():
    text = "Dear customer, your SBI account will be blocked. Update KYC at sbi-kyc-update.com/login and share the OTP."
    assert len({fuse(scan(text))["risk"] for _ in range(30)}) == 1
