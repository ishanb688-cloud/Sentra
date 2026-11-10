"""Read-only smoke test for the public Render deployment.

This checks the currently deployed service, which may not match an unmerged PR.
It does not scan user data or submit any content.
"""
import os
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

BASE = os.environ.get("SENTRA_BASE_URL", "https://sentra-cgbb.onrender.com").rstrip("/")
URL = BASE + "/api/health"
REQUIRED = {
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}
last_error = None
for attempt in range(3):
    try:
        request = Request(URL, headers={"User-Agent": "SENTRA-deployment-smoke/1.0"})
        with urlopen(request, timeout=25) as response:
            body = response.read(4096).decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in response.headers.items()}
            assert response.status == 200, f"health endpoint returned HTTP {response.status}"
            assert '"status"' in body and '"ok"' in body, f"unexpected health body: {body[:200]}"
            for name, expected in REQUIRED.items():
                actual = headers.get(name, "")
                assert expected in actual, f"missing/incorrect {name}: {actual!r}"
            csp = headers.get("content-security-policy", "")
            assert "default-src 'self'" in csp, f"missing restrictive CSP: {csp!r}"
            assert "frame-ancestors 'none'" in csp, f"CSP missing frame-ancestors: {csp!r}"
            print(f"PASS: {URL} returned HTTP 200 with HSTS, CSP, nosniff and frame denial")
            break
    except Exception as exc:
        last_error = exc
        if attempt < 2:
            time.sleep(10)
else:
    raise SystemExit(f"DEPLOYMENT SMOKE FAILED for {URL}: {last_error}")
