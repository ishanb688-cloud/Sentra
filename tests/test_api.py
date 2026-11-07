from fastapi.testclient import TestClient

from server import app

client = TestClient(app)

KYC = ("Dear customer, your SBI account will be blocked today. Update your KYC "
       "immediately: http://sbi-kyc-update.xyz/login and share the OTP you receive.")
GENUINE = ("Rs 2,500.00 debited from A/c XX1234 on 06-11-26. If not you, call "
           "1800-000-000. Do not share OTP with anyone. -SBI")


def post(text="", files=None):
    return client.post("/api/scan", data={"text": text}, files=files)


def test_health():
    assert client.get("/api/health").json() == {"status": "ok"}


def test_scam_is_critical_with_chain():
    r = post(KYC).json()
    assert r["level"] == "Critical"
    assert r["chain"] == "fake_kyc"


def test_genuine_alert_is_low():
    assert post(GENUINE).json()["level"] == "Low signals"


def test_empty_input_does_not_crash():
    r = post("")
    assert r.status_code == 200
    assert r.json()["level"] == "Low signals"


def test_very_long_text_is_handled():
    assert post("hello " * 5000).status_code == 200


def test_fake_app_file_is_skipped_with_a_note():
    r = post("", files={"apk": ("evil.apk", b"not a zip", "application/octet-stream")})
    assert r.status_code == 200
    assert r.json()["notes"]


def test_security_headers_are_present():
    h = client.get("/api/health").headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"


def test_result_always_carries_the_disclaimer():
    assert "cannot guarantee" in post(KYC).json()["disclaimer"]