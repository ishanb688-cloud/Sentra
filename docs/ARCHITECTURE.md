# Architecture

    input (message, link, QR address, app file)
            |
     +------+---------------+------------------+
     | analyzers/message.py | analyzers/link_qr.py | analyzers/app_file.py |
     +------+---------------+------------------+
            |  every analyzer emits the same signal shape
            v
     analyzers/pipeline.py   merges signals, keeping the strongest per id
            v
     engine/fusion.py        weights, categories, chains, dampeners, level
            v
     server.py  (POST /api/scan)  ->  web/index.html

## Signal shape
id, category, reliability (from the catalog), strength and evidence (from the
analyzer), and a plain-language reason.

## Design choices
- **Signal definitions are data** (`data/`), not code, so they can be reviewed and tuned without touching logic.
- **Static analysis only.** Links are never opened and app files are never run.
- **No "safe" verdict.** The lowest level is "Low signals".
- **Warning phrases are removed** before analysis, so genuine bank alerts that say "do not share your OTP" do not trigger a false alarm.
- **Uploaded app files** are written to a temporary file, read, and deleted immediately.