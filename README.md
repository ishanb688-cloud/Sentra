# Sentra

One check for every scam signal. Sentra reads a message, links, payment QR
addresses and an app file together, then explains the verdict.

Built for INNOVEX 2026, problem statement PS 05 (AI-Powered Cybersecurity).

**Live demo:** (add your Render link here)

## What it does
- Reads suspicious messages, links, UPI payment addresses and Android app files
- Combines every warning sign into one risk level with the exact evidence
- Shows how the scam would have played out (attack-path replay)
- Never says something is "safe", only how many warning signs it found

## How it decides
1. **Read:** three analyzers (message, link and QR, app file) turn input into signals. Nothing is opened or run.
2. **Weigh:** each signal has a strength (how clearly it appears) and a reliability (how trustworthy that kind of sign is).
3. **Connect:** signals roll up into categories, and complete scam scripts (for example impersonation, urgency and a request for a code) add a chain bonus. Official-domain matches reduce the score, but are capped so they cannot hide a full scam script.
4. **Explain:** the result lists the top evidence, the matched scam pattern and the replay.

## Run it locally
```
pip install -r requirements.txt
python -m uvicorn server:app --reload
```
Open http://127.0.0.1:8000

## Structure
- `analyzers/`: message, link and QR, and app-file readers
- `engine/fusion.py`: scoring and chain logic
- `data/`: signal catalog, scam chains, brand list (all editable data)
- `tests/`: scenario and evaluation scripts
- `server.py`: API
- `web/`: interface

## Limits
Static analysis only. The test set is small and written by the authors, so
the numbers are indicative, not a measure of real-world accuracy.