from pathlib import Path


WEB = Path(__file__).resolve().parents[1] / "web" / "index.html"


def test_qr_upload_checks_file_size_and_pixel_dimensions_before_canvas_resize():
    source = WEB.read_text(encoding="utf-8")
    assert "20*1024*1024" in source
    assert "width*height>40000000" in source
    assert "cv.width=Math.max" in source


def test_qr_camera_failure_has_upload_fallback_message():
    source = WEB.read_text(encoding="utf-8")
    assert "navigator.mediaDevices.getUserMedia" in source
    assert "upload a QR photo instead" in source


def test_repeatable_demo_examples_are_present():
    source = WEB.read_text(encoding="utf-8")
    for example in ("Fake bank KYC", "Genuine bank alert", "Parcel fee", "Fake challan app"):
        assert example in source
    assert "Fake refund QR" in source
    assert "Shop QR" in source


def test_frontend_does_not_claim_qr_payee_identity_is_verified():
    source = WEB.read_text(encoding="utf-8")
    assert "NOT VERIFIED" in source
    assert "cannot query the bank or confirm the account holder" in source
