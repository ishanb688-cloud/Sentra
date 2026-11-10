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
    assert "identity not verified" in source
    assert "not bank-verified" in source
    assert "Sentra never sends money or approves the payment" in source


def test_camera_and_photo_share_native_and_jsqr_decoder():
    source = WEB.read_text(encoding="utf-8")
    assert "function makeQRDetector()" in source
    assert "async function decodeQRCanvas()" in source
    assert "const data=await decodeQRCanvas()" in source
    assert "const decoded=await decodeQRCanvas()" in source
    assert "qrFrameBusy" in source


def test_file_picker_uses_native_show_picker_with_click_fallback():
    source = WEB.read_text(encoding="utf-8")
    assert 'typeof input.showPicker==="function"' in source
    assert "input.click()" in source


def test_qr_scanner_has_phonepe_style_live_viewfinder_and_torch():
    source = WEB.read_text(encoding="utf-8")
    assert 'class="scan-live"' in source
    assert 'class="scan-line"' in source
    assert 'id="torchBtn"' in source
    assert "async function toggleTorch()" in source
    assert "performance.now()-lastScanAt>140" in source


def test_qr_results_show_upi_payee_and_explicit_user_initiated_handoff():
    source = WEB.read_text(encoding="utf-8")
    assert "function qrResultCard(t)" in source
    assert "UPI payment request" in source
    assert "Payee name not provided" in source
    assert "Continue in UPI app" in source
    assert "pay.onclick=()=>{window.location.href=t}" in source
    assert "This only opens a UPI app. Sentra never sends money" in source


def test_qr_photo_upload_retries_full_image_and_quadrants():
    source = WEB.read_text(encoding="utf-8")
    assert "const maxSide=Math.max(width,height),base=Math.min(1,2000/maxSide)" in source
    assert "for(const [sx,sy] of [[0,0],[width/2,0],[0,height/2],[width/2,height/2]])" in source
    assert '["attemptBoth","dontInvert","onlyInvert"]' in source


def test_qr_details_are_not_rendered_for_non_qr_checks():
    source = WEB.read_text(encoding="utf-8")
    assert "const qc=qrPayload?qrResultCard(qrPayload):null" in source
