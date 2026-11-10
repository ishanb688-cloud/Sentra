from analyzers.urls import find_urls


def test_bare_domains_are_found():
    assert find_urls("visit example.com now") == ["example.com"]
    assert find_urls("see www.example.com/path") == ["www.example.com/path"]
    assert find_urls("go to hdfc-bank-verify.in/login") == ["hdfc-bank-verify.in/login"]


def test_scheme_and_shortened_links_are_found():
    assert find_urls("open https://x.example.org/a?b=1.") == ["https://x.example.org/a?b=1"]
    assert find_urls("pay: bit.ly/3x and tinyurl.com/abc") == ["bit.ly/3x", "tinyurl.com/abc"]


def test_emails_amounts_and_abbreviations_are_not_links():
    assert find_urls("mail me at someone@gmail.com") == []
    assert find_urls("Rs.5000 paid, e.g. today at 5 p.m.") == []
    assert find_urls("A/c XX1234 debited Rs 1,200.00 on 07-11-26") == []


def test_upi_payloads_are_not_treated_as_web_links():
    assert find_urls("upi://pay?pa=a@ybl&pn=X&am=5") == []


def test_government_and_country_domains():
    assert find_urls("see parivahan.gov.in/x") == ["parivahan.gov.in/x"]
    assert find_urls("see sbi.co.in") == ["sbi.co.in"]
