from analyzers.app_file import signals_from_facts

P = "android.permission."


def ids(**kw):
    base = {"name": "Notes", "package": "com.example.notes", "permissions": set(), "manifest": "",
            "has_launcher": True, "signed": True}
    return {s["id"] for s in signals_from_facts({**base, **kw})}


def test_ordinary_app_is_clean():
    assert ids() == set()


def test_genuine_bank_app_reading_sms_is_not_a_warning_chain():
    f = ids(name="SBI YONO", package="com.sbi.lotusintouch", permissions={P + "READ_SMS", P + "CAMERA"})
    assert f == {"app_sms_read"}


def test_lookalike_package_of_a_known_bank_is_caught():
    f = ids(name="HDFC Rewards", package="com.snapwork.hdfc.rewards", permissions={P + "READ_SMS"})
    assert {"app_name_mimics_bank", "app_package_mismatch"} <= f


def test_sms_plus_overlay_and_interception():
    f = ids(permissions={P + "READ_SMS", P + "SYSTEM_ALERT_WINDOW"}, sms_priority=1000)
    assert {"app_sms_plus_overlay", "app_sms_interceptor"} <= f


def test_hidden_payload_debug_certificate_and_installer():
    f = ids(permissions={P + "REQUEST_INSTALL_PACKAGES"}, payload_files=["assets/x.apk"], debug_cert=True)
    assert {"app_embedded_payload", "app_debug_certificate", "app_installer_permission"} <= f


def test_hidden_icon_and_unsigned():
    assert {"app_hides_icon", "app_unverified_signer"} <= ids(has_launcher=False, signed=False)
