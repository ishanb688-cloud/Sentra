import logging
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from analyzers.app_file import analyze as analyze_apk
from analyzers.pipeline import scan
from engine.fusion import fuse

log = logging.getLogger("sentra")
app = FastAPI(title="Sentra")
MAX_APK = 50 * 1024 * 1024
MAX_TEXT = 5000


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/api/health")
def health():
    return {"status": "ok"}


def merge(*groups):
    out = {}
    for g in groups:
        for s in g:
            if s["id"] not in out or s["strength"] > out[s["id"]]["strength"]:
                out[s["id"]] = s
    return list(out.values())


@app.post("/api/scan")
async def scan_case(text: str = Form(""), apk: UploadFile | None = File(None)):
    try:
        text_signals = scan(text[:MAX_TEXT]) if text.strip() else []
        apk_signals, notes = [], []

        if apk is not None and apk.filename:
            data = await apk.read(MAX_APK + 1)
            if not apk.filename.lower().endswith(".apk") or data[:2] != b"PK":
                notes.append("That file is not an Android app file, so it was skipped.")
            elif len(data) > MAX_APK:
                notes.append("App file is larger than 50 MB and was skipped.")
            else:
                fd, tmp = tempfile.mkstemp(suffix=".apk")
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(data)
                    apk_signals = analyze_apk(tmp)
                except Exception:
                    log.exception("app file could not be read")
                    notes.append("The app file could not be read.")
                finally:
                    os.remove(tmp)

        signals = merge(text_signals, apk_signals)
        result = fuse(signals)
        result["signals"] = sorted(
            ({**s, "weight": round(s["strength"] * s["reliability"], 3)} for s in signals),
            key=lambda s: s["weight"], reverse=True)
        result["notes"] = notes
        result["disclaimer"] = ("Sentra gives guidance based on warning signs. "
                                "It cannot guarantee that anything is safe.")
        return result
    except Exception:
        log.exception("scan failed")
        return JSONResponse({"error": "Sentra could not analyse that input."}, status_code=500)


WEB = Path(__file__).parent / "web"
if WEB.is_dir():
    app.mount("/", StaticFiles(directory=str(WEB), html=True), name="web")