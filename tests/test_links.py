from analyzers.link_qr import analyze


def ids(text, ctx=None):
    return {s["id"] for s in analyze(text, ctx)}


def test_official_page_is_clean():
    assert ids("https://www.sbi.co.in/web/personal-banking") == {"official_domain_match"}


def test_official_page_without_scheme_is_clean_too():
    assert ids("www.sbi.co.in/web/personal-banking") == {"official_domain_match"}


def test_lookalike_brand_domain_with_bare_address():
    assert "link_lookalike_brand" in ids("sbi-kyc-update.com/login")


def test_hyphenated_multi_word_brand_is_caught():
    assert "link_lookalike_brand" in ids("www.income-tax-refund.in/claim")


def test_punycode_domain():
    assert "link_punycode" in ids("https://xn--amazon-9ve.in/offer")


def test_cloud_hosting_domain_is_neutral():
    assert ids("https://bucket.s3.amazonaws.com/file") == set()


def test_at_sign_trick_is_flagged():
    assert "link_odd_host" in ids("http://sbi.co.in@secure-login.ru/verify")


def test_upi_receive_trick():
    found = ids("upi://pay?pa=9876543210@ybl&pn=Ramesh&am=5000", "You have won Rs 5000 cashback, scan to receive")
    assert "qr_pay_not_receive" in found


def test_business_name_on_personal_number_is_flagged():
    assert "qr_name_handle_mismatch" in ids("upi://pay?pa=9876501234@ybl&pn=Amazon%20Refund%20Desk")


def test_ordinary_merchant_qr_is_clean():
    assert ids("upi://pay?pa=freshmart@okaxis&pn=Fresh%20Mart&am=250") == set()


def test_no_redirect_signal_is_ever_produced():
    assert "link_redirect_chain" not in ids("bit.ly/abc https://a.b.c.d.e.example.com/x")


def test_refund_named_payee_is_flagged_even_without_a_message():
    assert "qr_pay_not_receive" in ids("upi://pay?pa=9876501234@ybl&pn=Amazon%20Refund%20Desk&am=4999")


def test_ordinary_names_are_not_mistaken_for_refund_names():
    assert "qr_pay_not_receive" not in ids("upi://pay?pa=anil.sharma@ybl&pn=Anil%20Sharma&tn=Rent")
