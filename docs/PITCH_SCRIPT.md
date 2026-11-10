# SENTRA — judge presentation script

**Target length:** 3 minutes  
**Live demo:** https://sentra-cgbb.onrender.com  
**Positioning:** explainable, multi-signal scam-risk analysis for messages, links, UPI/QR payloads and Android APKs.

## 1. Opening (0:00–0:25)

"Good morning. Scams rarely arrive as just one suspicious message. A message can impersonate a bank, push you to a fake link, and then ask you to pay through a QR code. Checking each item separately can hide the full story.

SENTRA brings those signals together. It helps a user understand what looks suspicious, why it looks suspicious, and how different pieces may form one scam chain."

## 2. The solution (0:25–0:55)

"SENTRA accepts four evidence types: message text, URLs, QR/UPI payloads and Android APK files. Each analyzer produces named evidence signals. The fusion engine combines their strength and reliability, correlates known scam patterns, and returns an explainable risk level with the reasons.

A key design choice is safety: SENTRA does not open submitted links or execute APKs. QR decoding happens in the browser. The tool does not claim that a low-risk result means an item is safe."

## 3. Live demonstration (0:55–2:05)

Use the website's built-in Demo examples so the demonstration is repeatable.

1. **Message:** choose a bank/KYC or delivery-fee scam example. Point to the exact evidence: authority impersonation, urgency, payment/credential request and any link.
2. **Link:** show a lookalike or suspicious-domain example. Explain that inspection is static; SENTRA does not visit the destination or follow redirects.
3. **QR/UPI:** show a payment-request QR payload. Explain the distinction between money being sent and received. Explicitly say that the displayed payee name is copied from the QR payload and is not verified against bank records.
4. **Combined analysis:** show how message context and link/payment evidence contribute to one assessment. Point to the reasons, not just the colour or score.

If the camera or network fails, use the built-in examples and a prepared QR image. Do not spend presentation time troubleshooting a live camera.

## 4. Evidence and honesty (2:05–2:35)

"Our current engine is rule-based and explainable; it is not a trained machine-learning model. In our team-authored test suites, the Suspicious-or-higher threshold flagged all malicious examples with no genuine examples flagged. Those results are limited to our own selected cases and are not independent real-world accuracy.

We have automated regression tests and CI checks for detection, API limits, upload handling and deployment security headers. We are adding an external corpus evaluation separately and will report its result only after it has actually been run."

## 5. Close (2:35–3:00)

"Our goal is not to replace banks, antivirus tools or human judgement. SENTRA is an additional warning and explanation layer that helps people pause before sharing credentials, installing an app, opening a link or approving a payment.

SENTRA: one check for every scam signal. Thank you."

## Demo operator checklist

- Open the live URL early and allow the free Render instance to wake.
- Use the built-in Demo examples first; verify the page is responsive before judges arrive.
- Keep one prepared screenshot/video locally as a fallback, but only use genuine captures from the current deployed build.
- Have one QR image ready. Do not use a real person's payment details or a real bank account.
- Do not scan or open a live malicious URL during the presentation.
- If asked to prove the QR payee identity, state clearly that SENTRA cannot verify bank-registered recipient identity.
- If asked whether the model is AI/ML, answer: "The current implementation is deterministic and rule-based, not a trained ML model."
- If asked about the 100% benchmark result, explain that it is on team-authored examples only; it is not a real-world accuracy claim.
- If asked about APK analysis, explain that it is static and does not execute the app.

## Likely judge questions — concise answers

**What is novel?**  
The combination of message, link, QR/UPI and APK evidence in one explainable risk assessment, including correlation of multi-step scam patterns.

**Does it use machine learning?**  
Not currently. It uses deterministic rules, weighted signals and scam-chain correlation. We prefer to describe the implementation accurately rather than label rule-based logic as ML.

**Can it guarantee a link or app is safe?**  
No. It performs static analysis and cannot observe live page behaviour, redirects or runtime APK behaviour. "Low signals" is not a safety certificate.

**Can it verify the UPI recipient?**  
No. It parses the VPA and payee name embedded in the QR. The user must verify the registered name in their UPI app.

**Are the 100% benchmark results independent?**  
No. The current main and holdout sets are team-authored. We provide an external evaluation harness for a public SMS corpus, but no external score should be quoted until it has been run.

**What would you improve next?**  
Independent and India-specific labelled datasets, calibrated ML as an additional evidence source, broader multilingual coverage, real-device QA and safe validation against known benign/malicious APK corpora.
