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


def test_paytm_brand_prefix_kyc_domain_is_flagged():
    assert "link_lookalike_brand" in ids("https://paytmbank-kyc.in/upload")



def test_misleading_paytm_bank_kyc_domain_is_flagged_with_evidence():
    signals = analyze("https://paytmbank-kyc.in/login")
    hit = next(s for s in signals if s["id"] == "link_lookalike_brand")
    assert "Paytm" in hit["evidence"] and "paytmbank-kyc.in" in hit["evidence"]


def test_legitimate_domain_containing_brand_as_unrelated_text_is_not_flagged():
    assert "link_lookalike_brand" not in ids("https://paytm-community.example.com/") 


def test_misleading_subdomain_does_not_hide_real_domain():
    found = ids("https://paytm.com.attacker.example/login")
    assert "link_brand_in_subdomain" in found or "link_lookalike_brand" in found


def test_encoded_brand_host_is_decoded_before_brand_check():
    assert "link_lookalike_brand" in ids("https://%70aytmbank-kyc.in/login")


def test_encoded_credential_path_is_decoded_before_check():
    assert "link_credential_form" in ids("https://example.net/%6cogin")


def test_raw_ip_url_is_flagged():
    assert "link_odd_host" in ids("http://192.0.2.45/login")


def test_shortened_url_is_flagged():
    assert "link_shortener" in ids("https://bit.ly/abc123")


def test_unsafe_schemes_are_flagged_not_silently_ignored():
    assert "link_odd_host" in ids("javascript:alert(1)")
    assert "link_odd_host" in ids("file:///etc/passwd")
    assert "link_odd_host" in ids("data:text/html,<script>alert(1)</script>")
