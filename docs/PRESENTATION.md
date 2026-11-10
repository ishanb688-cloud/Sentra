# Presentation plan (about 5 minutes)

Follow the sequence judges expect: problem, solution, architecture, live demo, evidence, impact.

## Before you start
- Open `https://sentra-cgbb.onrender.com` two minutes early so the free server is awake, and press **Demo** once.
- Keep a screen recording of the demo as a backup.
- Say **"rule-based, explainable engine"**. Do not say "AI-trained" or "machine learning".

## 1. The problem (30 s)
People receive fraudulent messages, malicious links, QR payment requests and fake app files, and scams mix them: a message
pushes a link, the link pushes an app, the app steals the OTP. Most checkers look at one thing at a time.

## 2. The solution (30 s)
Sentra reads a message, links, UPI/QR payloads and app files **together**, shows exactly which warning signs it found, and
replays how the scam would have unfolded. It never says "safe". It never opens your links or runs your apps.

## 3. Technical architecture (60 s)
Show the diagram from `docs/METHODOLOGY.md`: three analyzers (message, link and QR, app file), one common signal format,
the scoring engine (weights, categories, scam scripts, capped dampeners), then the API and the interface.
Say: "Signals, weights and scam scripts are data files, so they can be reviewed and updated without touching code."

## 4. Live demonstration (90 s)
1. **A KYC scam.** Press **Demo**. Point at the gauge, the scam replay, and the evidence list: "every line is a reason".
2. **A genuine bank alert.** Message page, example "Genuine bank alert": stays Low, with reassuring signs listed.
3. **The multi-signal case.** Full check: paste the KYC message, add the fake challan link, then drop in an app file or scan
   a QR. "Now several weak signs line up into one script and the verdict rises."
4. If time allows: scan a UPI QR and show the card "This QR sends money. It does not receive money."

## 5. Evidence (45 s)
Open **How it works**, the measured results table. Say it plainly:
- 90 labelled cases, **first run before any tuning: 94.8% of scams flagged, 2 false alarms in 32 genuine**.
- A fresh **holdout of 40 cases, never tuned on: 77.3% flagged, 94.4% precision, 1 false alarm in 18 genuine**.
- "These are our own test cases, not independent data. Known gaps: delivery OTPs, investment scams, brand-prefix domains."
- 70 automated tests run on every push, including malformed-upload, rate-limit and no-retention tests.

## 6. Impact (30 s)
An ordinary person can understand a scam **before** losing money: not a red warning, but the reason. UPI, KYC, courier and
fake-app scams hit India every day. Next steps: a learned classifier as an extra signal, more languages, official
certificate fingerprints for bank apps, and an opt-in reporting loop.

## Slides (if you need them)
1. Problem  2. Solution + logo  3. Architecture  4. Demo (screenshots)  5. Evidence table  6. Impact and roadmap

## Questions
Rehearse `docs/JUDGE_QA.md`. The five hardest: where is the AI, how is the score calculated, how are APKs and publishers
verified, real versus fraudulent UPI, and what happens with a brand-new scam.
