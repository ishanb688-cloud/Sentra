import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.staticfiles import StaticFiles

from analyzers.app_file import analyze as analyze_apk
from analyzers.pipeline import scan
from engine.fusion import fuse

app = FastAPI(title="Sentra")
MAX_APK = 50 * 1024 * 1024


def merge(*groups):
    out = {}
    for g in groups:
        for s in g:
            if s["id"] not in out or s["strength"] > out[s["id"]]["strength"]:
                out[s["id"]] = s
    return list(out.values())


@app.post("/api/scan")
async def scan_case(text: str = Form(""), apk: UploadFile | None = File(None)):
    text_signals = scan(text) if text.strip() else []
    apk_signals, notes = [], []

    if apk is not None and apk.filename:
        data = await apk.read()
        if len(data) > MAX_APK:
            notes.append("App file is larger than 50 MB and was skipped.")
        else:
            fd, tmp = tempfile.mkstemp(suffix=".apk")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                apk_signals = analyze_apk(tmp)
            except Exception:
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


WEB = Path(__file__).parent / "web"
if WEB.is_dir():
    app.mount("/", StaticFiles(directory=str(WEB), html=True), name="web")