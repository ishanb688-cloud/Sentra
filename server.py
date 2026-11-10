"""Sentra API. Validates every input, limits abuse, and keeps nothing:
messages are processed in memory and uploaded files are deleted right after reading."""
import io
import logging
import os
import tempfile
import time
import zipfile
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from analyzers.app_file import analyze as analyze_apk
from analyzers.pipeline import scan_with_notes
from engine.fusion import fuse

log = logging.getLogger("sentra")
# docs pages are switched off in production: less surface, and they load third-party scripts
app = FastAPI(title="Sentra", docs_url=None, redoc_url=None, openapi_url=None)

MAX_APK = 50 * 1024 * 1024
MAX_BODY = MAX_APK + 1024 * 1024
MAX_TEXT = 5000
MAX_ZIP_ENTRIES = 20000
MAX_UNPACKED = 400 * 1024 * 1024
MAX_RATIO = 200
GENERIC_ERROR = "Sentra could not analyse that input."

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; "
       "connect-src 'self'; media-src 'self' blob:; manifest-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")



class BodyLimitMiddleware:
    """Buffer request bodies only up to MAX_BODY before parsing multipart data.

    This catches chunked requests and misleading/missing Content-Length headers.
    The bounded buffer is replayed to the application only after the full body
    has been received within the configured limit.
    """

    def __init__(self, app, max_body):
        self.app = app
        self.max_body = max_body

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                declared = int(raw_length)
            except ValueError:
                await self._reject(send, 400, "Invalid request.")
                return
            if declared < 0:
                await self._reject(send, 400, "Invalid request.")
                return
            if declared > self.max_body:
                await self._reject(send, 413, "That upload is too large.")
                return

        chunks = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_body:
                await self._reject(send, 413, "That upload is too large.")
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        index = 0

        async def replay():
            nonlocal index
            if index < len(chunks):
                chunk = chunks[index]
                index += 1
                return {"type": "http.request", "body": chunk,
                        "more_body": index < len(chunks)}
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send, status, message):
        body = ('{"error":"' + message + '"}').encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"content-security-policy", CSP.encode("latin-1")),
            (b"permissions-policy", b"camera=(self), microphone=(), geolocation=()"),
            (b"cache-control", b"no-store"),
        ]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


class RateLimiter:
    """Sliding-window limit per client address, kept in memory only."""

    def __init__(self, limit=30, window=60):
        self.limit, self.window = limit, window
        self.hits = defaultdict(deque)

    def allow(self, key, now=None):
        now = time.monotonic() if now is None else now
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        if len(self.hits) > 5000:  # forget idle clients
            for k in [k for k, v in self.hits.items() if not v]:
                del self.hits[k]
        return True


LIMITER = RateLimiter(int(os.environ.get("SENTRA_RATE", "30")), 60)


def client_ip(request: Request):
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() or (request.client.host if request.client else "unknown")


@app.middleware("http")
async def guard(request: Request, call_next):
    try:
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return JSONResponse({"error": "That upload is too large."}, status_code=413)
    except ValueError:
        return JSONResponse({"error": "Invalid request."}, status_code=400)
    if request.url.path == "/api/scan" and not LIMITER.allow(client_ip(request)):
        return JSONResponse({"error": "Too many checks. Please wait a minute."}, status_code=429,
                            headers={"Retry-After": "60"})
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    return resp


@app.exception_handler(RequestValidationError)
async def invalid(request, exc):
    return JSONResponse({"error": "Invalid request."}, status_code=422)


@app.exception_handler(Exception)
async def crashed(request, exc):
    log.error("unhandled %s", type(exc).__name__)
    return JSONResponse({"error": GENERIC_ERROR}, status_code=500)


@app.get("/api/health")
def health():
    return {"status": "ok"}


def validate_apk(data: bytes):
    """Return None if the bytes look like a safe Android package, else a short reason."""
    if data[:2] != b"PK":
        return "That file is not an Android app file, so it was skipped."
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except zipfile.BadZipFile:
        return "That file is damaged or not a real app package, so it was skipped."
    if len(infos) > MAX_ZIP_ENTRIES:
        return "That package has an unusual number of files, so it was skipped."
    if sum(i.file_size for i in infos) > MAX_UNPACKED:
        return "That package unpacks to an unsafe size, so it was skipped."
    if any(i.compress_size and i.file_size / i.compress_size > MAX_RATIO and i.file_size > 10_000_000
           for i in infos):
        return "That package looks like a decompression bomb, so it was skipped."
    if "AndroidManifest.xml" not in {i.filename for i in infos}:
        return "That file has no Android manifest, so it was skipped."
    return None


def merge(*groups):
    out = {}
    for g in groups:
        for s in g:
            if s["id"] not in out or s["strength"] > out[s["id"]]["strength"]:
                out[s["id"]] = s
    return sorted(out.values(), key=lambda s: s["id"])


@app.post("/api/scan")
async def scan_case(text: str = Form(""), apk: UploadFile | None = File(None)):
    try:
        text_signals, notes = scan_with_notes(text[:MAX_TEXT]) if text.strip() else ([], [])
        apk_signals = []

        if apk is not None and apk.filename:
            data = await apk.read(MAX_APK + 1)
            if len(data) > MAX_APK:
                notes.append("App file is larger than 50 MB and was skipped.")
            elif not apk.filename.lower().endswith(".apk"):
                notes.append("That file is not an Android app file, so it was skipped.")
            else:
                reason = validate_apk(data)
                if reason:
                    notes.append(reason)
                else:
                    fd, tmp = tempfile.mkstemp(suffix=".apk")
                    try:
                        with os.fdopen(fd, "wb") as f:
                            f.write(data)
                        apk_signals = analyze_apk(tmp)
                    except Exception as e:
                        log.error("app file could not be read: %s", type(e).__name__)
                        notes.append("The app file could not be read.")
                    finally:
                        try:
                            os.remove(tmp)
                        except OSError:
                            pass
            del data

        signals = merge(text_signals, apk_signals)
        result = fuse(signals)
        result["signals"] = sorted(
            ({**s, "weight": round(s["strength"] * s["reliability"], 3)} for s in signals),
            key=lambda s: (-s["weight"], s["id"]))
        result["notes"] = notes
        result["disclaimer"] = ("Sentra gives guidance based on warning signs. "
                                "It cannot guarantee that anything is safe.")
        return result
    except Exception as e:
        log.error("scan failed: %s", type(e).__name__)
        return JSONResponse({"error": GENERIC_ERROR}, status_code=500)


WEB = Path(__file__).parent / "web"
if WEB.is_dir():
    app.mount("/", StaticFiles(directory=str(WEB), html=True), name="web")


# Enforce the body cap before Starlette/FastAPI parses multipart uploads.
app.add_middleware(BodyLimitMiddleware, max_body=MAX_BODY)
