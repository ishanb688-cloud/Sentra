import io
import tempfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import server

client = TestClient(server.app)

KYC = ("Dear customer, your SBI account will be blocked today. Update your KYC "
       "immediately: http://sbi-kyc-update.xyz/login and share the OTP you receive.")
GENUINE = ("Rs 2,500.00 debited from A/c XX1234 on 06-11-26. If not you, call "
           "1800-000-000. Do not share OTP with anyone. -SBI")


@pytest.fixture(autouse=True)
def fresh_limiter():
    server.LIMITER.hits.clear()
    server.LIMITER.limit = 1000
    yield
    server.LIMITER.limit = 30


def post(text="", files=None):
    return client.post("/api/scan", data={"text": text}, files=files)


def zip_bytes(names):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in names:
            z.writestr(n, b"x")
    return buf.getvalue()


def test_health():
    assert client.get("/api/health").json() == {"status": "ok"}


def test_scam_is_critical_with_chain_and_replay():
    r = post(KYC).json()
    assert r["level"] == "Critical" and r["chain"] == "fake_kyc" and r["replay"]


def test_genuine_alert_is_low():
    assert post(GENUINE).json()["level"] == "Low signals"


def test_bare_domain_link_is_analysed():
    r = post("Your KYC is pending, update at hdfc-kyc-update.com/login").json()
    assert any(s["id"] == "link_lookalike_brand" for s in r["signals"])


def test_empty_input_does_not_crash():
    r = post("")
    assert r.status_code == 200 and r.json()["level"] == "Low signals"


def test_very_long_text_is_capped_not_rejected():
    assert post("hello " * 5000).status_code == 200


def test_result_always_carries_the_disclaimer_and_never_says_safe():
    r = post(GENUINE).json()
    assert "cannot guarantee" in r["disclaimer"] and r["level"] != "Safe"


def test_non_apk_file_is_skipped_with_a_note():
    r = post("", files={"apk": ("notes.txt", b"hello", "text/plain")})
    assert r.status_code == 200 and r.json()["notes"]


def test_fake_apk_that_is_not_a_zip_is_skipped():
    r = post("", files={"apk": ("evil.apk", b"not a zip", "application/octet-stream")})
    assert r.status_code == 200 and "not an Android app file" in r.json()["notes"][0]


def test_zip_without_manifest_is_skipped():
    r = post("", files={"apk": ("x.apk", zip_bytes(["readme.txt"]), "application/octet-stream")})
    assert "no Android manifest" in r.json()["notes"][0]


def test_zip_with_too_many_entries_is_skipped(monkeypatch):
    monkeypatch.setattr(server, "MAX_ZIP_ENTRIES", 3)
    r = post("", files={"apk": ("x.apk", zip_bytes([f"f{i}" for i in range(10)] + ["AndroidManifest.xml"]), "a/b")})
    assert "unusual number of files" in r.json()["notes"][0]


def test_oversized_upload_is_refused(monkeypatch):
    monkeypatch.setattr(server, "MAX_APK", 100)
    r = post("", files={"apk": ("x.apk", b"PK" + b"0" * 500, "a/b")})
    assert r.status_code == 200 and "larger than" in r.json()["notes"][0]



def test_streamed_body_without_content_length_is_rejected_before_parsing():
    import asyncio

    async def scenario():
        called = False
        sent_messages = []
        chunks = [b"a" * 8, b"b" * 8]

        async def receive():
            if chunks:
                chunk = chunks.pop(0)
                return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}
            return {"type": "http.disconnect"}

        async def downstream(scope, receive, send):
            nonlocal called
            called = True

        async def send(message):
            sent_messages.append(message)

        middleware = server.BodyLimitMiddleware(downstream, max_body=10)
        scope = {"type": "http", "method": "POST", "path": "/api/scan", "headers": []}
        await middleware(scope, receive, send)
        assert not called, "oversized streamed body reached multipart parsing"
        assert sent_messages[0]["status"] == 413
        assert b"too large" in sent_messages[1]["body"]

    asyncio.run(scenario())


def test_streamed_body_within_limit_reaches_application():
    import asyncio

    async def scenario():
        received = []
        chunks = [b"hello", b"world"]

        async def receive():
            if chunks:
                chunk = chunks.pop(0)
                return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}
            return {"type": "http.disconnect"}

        async def downstream(scope, receive, send):
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    break
                received.append(message["body"])
                if not message.get("more_body", False):
                    break

        async def send(message):
            pass

        middleware = server.BodyLimitMiddleware(downstream, max_body=10)
        scope = {"type": "http", "method": "POST", "path": "/api/scan", "headers": []}
        await middleware(scope, receive, send)
        assert received == [b"hello", b"world"]

    asyncio.run(scenario())

def test_huge_declared_body_is_rejected_early():
    r = client.post("/api/scan", content=b"x", headers={"content-length": str(server.MAX_BODY + 10)})
    assert r.status_code == 413


def test_odd_app_file_leaves_no_trace_on_disk_and_leaks_nothing():
    before = set(Path(tempfile.gettempdir()).glob("tmp*.apk"))
    r = post("", files={"apk": ("x.apk", zip_bytes(["AndroidManifest.xml"]), "a/b")})
    after = set(Path(tempfile.gettempdir()).glob("tmp*.apk"))
    assert r.status_code == 200
    assert after == before, "uploaded file was retained on disk"
    for forbidden in ("Traceback", "/tmp", "site-packages", "androguard"):
        assert forbidden not in r.text


def test_unreadable_app_is_reported_safely_and_temp_file_is_deleted(monkeypatch):
    def boom(path):
        raise RuntimeError("cannot read " + path)
    monkeypatch.setattr(server, "analyze_apk", boom)
    before = set(Path(tempfile.gettempdir()).glob("tmp*.apk"))
    r = post("", files={"apk": ("x.apk", zip_bytes(["AndroidManifest.xml"]), "a/b")})
    after = set(Path(tempfile.gettempdir()).glob("tmp*.apk"))
    assert r.status_code == 200 and "could not be read" in r.json()["notes"][0]
    assert after == before and "/tmp" not in r.text


def test_server_errors_never_expose_internal_paths(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("/srv/secret/path.py exploded with token=abc123")
    monkeypatch.setattr(server, "scan_with_notes", boom)
    r = post("hello")
    assert r.status_code == 500 and r.json() == {"error": server.GENERIC_ERROR}
    assert "secret" not in r.text and "abc123" not in r.text


def test_malformed_request_gets_a_generic_error():
    r = client.post("/api/scan", content=b"not multipart", headers={"content-type": "multipart/form-data; boundary=x"})
    assert r.status_code in (400, 422) and "Traceback" not in r.text


def test_forwarded_ip_is_ignored_from_untrusted_peer(monkeypatch):
    import ipaddress
    from starlette.requests import Request

    monkeypatch.setattr(server, "TRUSTED_PROXY_NETWORKS", ())
    request = Request({
        "type": "http",
        "headers": [(b"x-forwarded-for", b"203.0.113.99")],
        "client": ("198.51.100.10", 1234),
    })
    assert server.client_ip(request) == "198.51.100.10"


def test_forwarded_ip_chain_uses_nearest_untrusted_address(monkeypatch):
    import ipaddress
    from starlette.requests import Request

    monkeypatch.setattr(server, "TRUSTED_PROXY_NETWORKS", (
        ipaddress.ip_network("10.0.0.0/8"),
    ))
    request = Request({
        "type": "http",
        "headers": [(
            b"x-forwarded-for",
            b"198.51.100.99, 203.0.113.7, 10.0.0.1",
        )],
        "client": ("10.0.0.2", 1234),
    })
    assert server.client_ip(request) == "203.0.113.7"


def test_malformed_forwarded_ip_falls_back_to_peer(monkeypatch):
    import ipaddress
    from starlette.requests import Request

    monkeypatch.setattr(server, "TRUSTED_PROXY_NETWORKS", (
        ipaddress.ip_network("10.0.0.0/8"),
    ))
    request = Request({
        "type": "http",
        "headers": [(b"x-forwarded-for", b"not-an-ip, 203.0.113.7")],
        "client": ("10.0.0.2", 1234),
    })
    assert server.client_ip(request) == "10.0.0.2"


def test_rate_limit_returns_429_then_recovers():
    server.LIMITER.limit = 3
    codes = [post("hi").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429
    server.LIMITER.hits.clear()
    assert post("hi").status_code == 200


def test_rate_limiter_prunes_expired_clients_when_key_limit_is_reached():
    lim = server.RateLimiter(2, 60, max_clients=2)
    assert lim.allow("old-a", 0)
    assert lim.allow("old-b", 0)
    assert lim.allow("new", 100)
    assert list(lim.hits) == ["new"]


def test_rate_limiter_bounds_unique_client_keys():
    lim = server.RateLimiter(2, 60, max_clients=2)
    assert lim.allow("a", 0)
    assert lim.allow("b", 0)
    assert lim.allow("c", 0)
    assert len(lim.hits) == 2
    assert "a" not in lim.hits

def test_rate_limiter_window_expires():
    lim = server.RateLimiter(2, 60)
    assert lim.allow("a", 0) and lim.allow("a", 1) and not lim.allow("a", 2)
    assert lim.allow("a", 100)


def test_security_headers_are_present():
    h = client.get("/api/health").headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
    assert "default-src 'self'" in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]


def test_csp_does_not_allow_external_script_hosts():
    policy = client.get("/api/health").headers["content-security-policy"]
    assert "script-src 'self' 'unsafe-inline'" in policy
    assert "cdnjs.cloudflare.com" not in policy

def test_hsts_is_only_sent_on_https_including_early_body_rejections():
    secure = TestClient(server.app, base_url="https://testserver")
    assert secure.get("/api/health").headers["strict-transport-security"] == "max-age=31536000"
    assert "strict-transport-security" not in client.get("/api/health").headers
    rejected = secure.post(
        "/api/scan",
        content=b"x",
        headers={"content-length": str(server.MAX_BODY + 1)},
    )
    assert rejected.status_code == 413
    assert rejected.headers["strict-transport-security"] == "max-age=31536000"


def test_interactive_docs_are_switched_off():
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_messages_are_not_written_to_history_on_the_server():
    post("my secret message 98765")
    assert not any(hasattr(server, name) for name in ("HISTORY", "STORE", "DB"))
