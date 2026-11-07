from analyzers.link_qr import analyze


def ids(text, ctx=None):
    return {s["id"] for s in analyze(text, ctx)}


def test_official_page_is_clean():
    assert ids("https://www.sbi.co.in/web/personal-banking") == {"official_domain_match"}


def test_lookalike_brand_domain():
    assert "link_lookalike_brand" in ids("http://sbi-kyc-update.xyz/login")


def test_punycode_domain():
    assert "link_punycode" in ids("https://xn--amazon-9ve.in/offer")


def test_upi_receive_trick():
    found = ids("upi://pay?pa=9876543210@ybl&pn=Ramesh&am=5000",
                "You have won Rs 5000 cashback, scan to receive")
    assert "qr_pay_not_receive" in found