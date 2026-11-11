# SENTRA — three-minute judge pitch

**Live demo:** https://sentra-cgbb.onrender.com  
**Positioning:** explainable, multi-input scam-risk analysis for messages, links, UPI/QR payloads and Android APKs.

## 0:00–0:25 — Opening

"Scams rarely arrive as just one suspicious message. A fraudster can impersonate a bank, send a lookalike link, ask for an app installation, and then steal an OTP or redirect a payment. Looking at each item separately can hide the full story.

SENTRA brings four kinds of evidence together and explains the warning signs, instead of showing only a red alert."

## 0:25–0:55 — Solution and safety

"SENTRA analyzes message text, URLs, QR/UPI payloads and Android APK files. Each analyzer produces named evidence signals. Our fusion engine combines signal strength and reliability, correlates known scam patterns, and returns an explainable risk level.

The design is deliberately cautious: we do not open submitted links or execute APKs. QR decoding happens in the browser. A low-signal result is not a guarantee of safety, and QR payee identity is not verified against bank records."

## 0:55–2:05 — Demo

Use the current live build and built-in fictional examples.

1. **Message:** choose a bank/KYC or delivery-fee scam. Point to the evidence: impersonation, urgency and credential/payment request.
2. **Genuine message:** show a genuine bank alert. Explain why context matters, including the difference between asking for an OTP and warning someone not to share one.
3. **Link:** show a fictional lookalike domain. Explain static inspection and that the destination is not opened.
4. **QR/UPI:** show a prepared test QR. Explain payment direction and the payee-identity limitation.
5. **Combined check:** if time permits, show how evidence from multiple inputs contributes to a known scam chain.

If camera/network fails, use the prepared QR image and built-in examples. Never troubleshoot live camera permissions in front of judges.

## 2:05–2:35 — Evidence

"Our latest successful regression run passed **138 automated tests**. Our internal development set has 92 team-authored cases: 59 malicious and 33 genuine. At the Suspicious threshold, all 59 malicious examples were flagged and none of the 33 genuine examples were flagged. A separate team-authored holdout has 40 cases: 22 malicious and 18 genuine, with the same result at that threshold.

We also evaluated the message detector on the public UCI SMS Spam Collection: 5,572 historical English messages. At our Suspicious cutoff, precision was 96.43%, recall was 25.30%, and F1 was 40.08%, with seven genuine messages falsely flagged. This is an external dataset, but it is not representative of current Indian-language scams or our URL, QR and APK inputs. The low recall is a real limitation: the detector missed 558 of 747 spam messages."

## 2:35–3:00 — Close

"SENTRA is not a replacement for banks, antivirus tools or human judgement. It is an additional explanation layer that helps people pause before sharing credentials, installing an app or authorizing a payment.

Our contribution is connecting different scam evidence into one understandable story. SENTRA: one check for every scam signal. Thank you."

## Operator checklist

- Open the live URL early; the free Render instance may need time to wake.
- Test the exact deployed build and the presentation device before judges arrive.
- Use built-in fictional examples and one prepared QR image; do not use real payment details.
- Keep a genuine screen recording of the current build as a fallback.
- Do not open live malicious URLs or install suspicious APKs during the demo.
- If asked whether Sentra is machine learning, say the current engine is deterministic and rule-based.
- If asked about 100% internal benchmark results, state that the sets are team-authored and do not establish real-world accuracy.
- If asked about UPI identity, say the payee name is parsed from the QR and is not bank-verified.
- If asked about APKs, say static indicators are not proof of malware.

## Likely questions

**What is novel?** The integration of message, link, QR/UPI and APK evidence into one explainable risk assessment with known scam-chain correlation.

**Does it use ML?** Not currently. It is rule-based and deterministic; we describe it accurately.

**Can it guarantee safety?** No. "Low signals" means no strong known indicators were found in the submitted material, not that the item is safe.

**Are the benchmarks independent?** The UCI SMS corpus is a public external dataset, but it is historical English SMS data and has limited scope. The main and holdout examples are authored by the team. Independent, India-relevant evaluation remains a priority.
