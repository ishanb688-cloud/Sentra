# SENTRA — INNOVEX '26 presentation plan

**Purpose:** a six-slide registration/final deck plus a repeatable live demonstration. Keep the deck within the event's six-slide limit and use the official INNOVEX template.

**One-line pitch:** SENTRA turns messages, links, UPI QR payloads and Android APKs into one explainable scam-risk assessment.

## Six-slide structure

### Slide 1 — Title
**SENTRA: One check for every scam signal**

- Explainable, multi-input scam-risk analysis
- Problem statement: PS 05 — AI-Powered Cybersecurity (INNOVEX 2026)
- Team name and member details as required by the official template

### Slide 2 — Problem
Scams are not isolated files or messages. A single social-engineering sequence can impersonate a bank or courier, create urgency, send a lookalike link, request an app installation, or use a QR code to redirect money.

Most simple checkers inspect only one submitted item. That can hide the relationship between the message, link, payment request and app.

**Show one short, fictional example chain:** fake bank KYC SMS → lookalike login link → request for OTP / APK installation. Do not use a real victim's data or a live malicious URL.

### Slide 3 — Target users
- Everyday smartphone users who receive unexpected payment, KYC, parcel or job messages
- Students and families who may need a plain-language explanation before clicking, installing or paying
- Community help-desk or awareness volunteers who need to explain warning signs

**User need:** not just a red/green label, but the exact evidence and a clear next step. Avoid claiming a measured user base or market size unless the team has a source.

### Slide 4 — Proposed solution
SENTRA accepts four evidence types:
1. Message text
2. URLs (including links found in message text)
3. QR / UPI payloads
4. Android APK files

Each analyzer emits named evidence signals. A shared pipeline merges them, then a deterministic fusion engine combines signal strength and reliability, recognizes known scam chains, applies capped reassuring signals, and explains the result.

**Safety boundaries**
- Submitted links are never opened or followed.
- APKs are inspected statically and never installed or executed.
- QR images are decoded in the browser.
- “Low signals” is not a guarantee of safety.
- QR payee text is not verified against bank or UPI records.

Use the architecture diagram in [ARCHITECTURE.md](ARCHITECTURE.md) or [METHODOLOGY.md](METHODOLOGY.md).

### Slide 5 — Technology and evidence
**Stack:** Python, FastAPI, Androguard for static APK parsing, browser-side jsQR decoding, HTML/CSS/JavaScript, pytest, GitHub Actions and Render.

**Current reproducible evidence (11 November 2026)**
- Latest successful regression CI: **138 automated tests passed**, with one Starlette/httpx deprecation warning. [View CI run](https://github.com/ishanb688-cloud/Sentra/actions/runs/42984436236).
- Main internal benchmark: 92 team-authored cases (59 malicious, 33 genuine). At Suspicious-or-higher: 59/59 malicious flagged and 0/33 genuine falsely flagged.
- Separate internal holdout: 40 team-authored cases (22 malicious, 18 genuine). At Suspicious-or-higher: 22/22 malicious flagged and 0/18 genuine falsely flagged.
- External UCI SMS Spam Collection evaluation: 5,572 historical English SMS messages (747 spam, 4,825 ham). At the evaluator's Suspicious cutoff: 189 true positives, 558 false negatives, 7 false positives and 4,818 true negatives; precision **96.43%**, recall **25.30%**, F1 **40.08%**, false-positive rate **0.145%**. [View evaluation run](https://github.com/ishanb688-cloud/Sentra/actions/runs/42984428938).

**Integrity note:** the internal cases are authored by the team, are not independent real-world validation, and must not be presented as proof of 100% real-world accuracy. The UCI corpus is historical English SMS data, not representative of current Indian-language scams, URLs, QR/UPI payloads or APKs. APK benchmark profiles are synthetic, not a corpus of real malware. The external result shows high precision but low recall: Sentra still missed 558 of 747 spam messages in this corpus.

### Slide 6 — Feasibility and impact
**Why it is feasible:** the prototype is already deployed, the analysis pipeline is modular, signal definitions are data-driven, and automated checks run in CI. The tool is designed to add a warning/explanation layer, not replace banks, antivirus products or human judgement.

**Potential impact:** help people pause and understand warning signs before sharing credentials, installing an app or authorizing a payment. This is a potential benefit, not a measured reduction in fraud losses.

**Next steps:** independent India-relevant evaluation, consented user testing, multilingual coverage, real APK corpus validation, improved browser/device QA and better recall without unacceptable false positives.

## Live demo sequence (about 2 minutes)

1. **Open the live demo early.** The free Render instance may need time to wake. Confirm the home screen is responsive before judges arrive.
2. **Show a suspicious message.** Use the built-in fictional KYC or delivery-fee example. Point to the exact evidence signals and explain why they matter.
3. **Show a genuine message.** Use the built-in genuine bank-alert example to demonstrate that context matters and that warnings such as “do not share your OTP” are not treated as an OTP request.
4. **Show a URL.** Use a fictional lookalike domain. Explain that analysis is static and the link is not opened.
5. **Show QR/UPI.** Use a prepared test QR. Explain send-versus-receive direction and explicitly state that the payee identity is not bank-verified.
6. **Show the combined assessment** if time allows. Explain how evidence from multiple inputs can form a known scam chain.

Do not spend demo time troubleshooting camera permissions. Keep a prepared QR image and a genuine screen recording of the current deployed build as a fallback. Never present a screenshot or recording from an older build as current.

## Before submission

- Confirm the official template and six-slide maximum are followed.
- Check team name, member details and any Team ID field against the current event instructions.
- Verify the public repository README and live URL open.
- Rehearse the demo on the actual presentation device and a phone if QR camera scanning is part of the demo.
- Run `python -m pytest -q`, `python tools/benchmark.py` and `python tools/benchmark.py --holdout`.
- Quote only the metrics that the latest CI run reproduces. Keep external evaluation separate.
- Rehearse [JUDGE_QA.md](JUDGE_QA.md) and [PITCH_SCRIPT.md](PITCH_SCRIPT.md).

## Five questions to rehearse

1. What is genuinely different? The integrated, explainable correlation of message, link, QR/UPI and APK evidence in one workflow—not a claim that any one detector is novel.
2. Where is the AI? The current engine is rule-based and deterministic, not a trained ML model. Describe it accurately.
3. Can it guarantee safety? No. Low signals means no strong known indicators were found; it is not a safety certificate.
4. Can it verify a UPI recipient or prove an APK is malware? No. It parses visible QR data and statically inspects APK indicators; neither capability proves account identity or malicious intent.
5. Are the results independent? The UCI SMS corpus is an external public dataset, but historical and limited to English SMS. The main and holdout benchmark examples remain team-authored. Broader India-relevant evaluation is still needed.
