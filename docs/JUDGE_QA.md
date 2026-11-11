# Judge Q&A: honest technical answers

Use these answers to explain what the current code actually does. The benchmark figures below are from the latest successful GitHub Actions run for this branch. They are team-authored test sets, not independent real-world validation.

## 1. Is SENTRA genuinely AI-powered or rule-based?

SENTRA is currently a **rule-based, explainable detection engine**, not a trained machine-learning model. It analyzes messages, URLs, QR/UPI payloads and Android APK files, converts observable evidence into named signals, and combines those signals into a risk assessment.

Its intelligence is in correlating different evidence types and recognizing multi-step scam patterns. It does not learn new patterns automatically. A future machine-learning classifier could be added as another signal source, while retaining the rule engine for explainability and safety.

## 2. How is the risk score calculated?

Each signal has a strength and a reliability. Their product is its weight. Signals are combined within categories using a diminishing-returns formula; category scores are then combined, with a scaling factor. Recognized scam chains can add a bonus. Reassuring signals can reduce risk, but their effect is capped so they cannot erase a complete scam pattern.

The final levels are:
- Below 0.30: Low signals
- 0.30 to below 0.65: Suspicious
- 0.65 to below 0.85: High risk
- 0.85 and above: Critical

The weights are expert-defined and deterministic, not statistically trained or calibrated on a representative population. See [METHODOLOGY.md](METHODOLOGY.md) for the formula and worked example.

## 3. What input types does it inspect?

- **Messages:** requests for OTPs or credentials, pressure, impersonation, payment demands, job-fee lures, task/recharge scams and other known patterns.
- **Links:** suspicious domains, lookalikes, punycode, raw IP addresses, URL tricks, shorteners and app-download links. Link inspection is static; SENTRA does not open submitted links.
- **QR/UPI:** parses the payload to determine whether it requests a payment, who it appears to pay, and whether the payload conflicts with the surrounding claim. It cannot independently verify the account holder's registered name.
- **Android APKs:** statically inspects package metadata, permissions, components and signing-related indicators. It does not install or execute the app.

The full-check pipeline combines signals from submitted evidence into one assessment.

## 4. How does SENTRA analyze APKs? Does it prove an app is malware?

APK inspection is static and uses Androguard. It looks at indicators such as sensitive permission combinations, SMS interception, overlay/accessibility or device-admin capabilities, hidden components or files, debug signing and package identity.

These are indicators, not proof of malicious intent. SENTRA does not execute the APK, and it does not yet compare publisher certificates against a maintained, independently verified fingerprint database for every brand. The current test suite includes synthetic permission profiles; it should not be presented as broad validation against real malware samples.

## 5. How does it assess QR codes and UPI payments?

It decodes the QR payload and inspects the payment direction and visible payee information. For example, a code that sends money may conflict with a message promising that the user will receive a refund or reward. It can also identify suspicious payee descriptions or mismatches with the claimed brand.

It cannot query the bank or UPI network to verify the recipient's registered identity. Users should confirm the payee name shown in their own UPI app before authorizing any payment. SENTRA does not label a payment as guaranteed safe.

## 6. What are the current benchmark results?

Latest successful CI run (11 November 2026): **133 automated tests passed**. See [the run](https://github.com/ishanb688-cloud/Sentra/actions/runs/42969244571). The same run executed both benchmark commands.

### Main benchmark

- 92 team-authored cases: 59 malicious and 33 genuine.
- At Suspicious-or-higher: 59/59 malicious cases flagged; 0/33 genuine cases falsely flagged.
- Precision: 100%; recall: 100%; false-positive rate: 0%.
- At High-risk-or-higher: 36/59 malicious cases flagged; 0/33 genuine cases falsely flagged; recall 61.0%.

### Holdout benchmark

- 40 team-authored cases: 22 malicious and 18 genuine.
- At Suspicious-or-higher: 22/22 malicious cases flagged; 0/18 genuine cases falsely flagged.
- Precision: 100%; recall: 100%; false-positive rate: 0%.
- At High-risk-or-higher: 11/22 malicious cases flagged; 0/18 genuine cases falsely flagged; recall 50.0%.

The holdout set was kept separate from the main development set, but it was still written by the project team. These results show performance on these selected examples only. They do not establish real-world accuracy, and they do not mean SENTRA catches every scam. See [BENCHMARK.md](BENCHMARK.md) and [HOLDOUT.md](HOLDOUT.md).

## 7. What happens when a new scam appears?

A new scam may evade the current rules, especially if it uses unfamiliar wording or contains no observable warning signs in the submitted material. General patterns such as impersonation, urgency, credential requests and payment redirection may still be detected, but coverage is not guaranteed. New signals and scam chains can be added to the data catalog and covered by regression tests.

## 8. Why doesn't SENTRA open submitted links or run APKs?

Opening unknown links or executing untrusted apps would introduce avoidable security and privacy risks. SENTRA uses static inspection instead. This limits what it can know: for example, it cannot observe a live page's behavior, follow redirects, or determine what an APK does at runtime.

## 9. Is user data stored?

The project documentation describes in-memory message processing, immediate deletion of uploaded files after analysis, and browser-local history containing scan results. Refer to [SECURITY.md](SECURITY.md) for the implemented controls and limitations. Avoid promising absolute privacy or security beyond what the code and deployment configuration have been verified to provide.

## 10. What is the project's distinctive contribution?

SENTRA combines four evidence types—messages, links, QR/UPI payloads and Android APKs—into a single explainable assessment. It also correlates signals into scam scenarios and presents the evidence behind its verdict. The contribution is this integrated workflow, not a claim that any individual detection technique is entirely new.

## 11. What are the main limitations and next steps?

- Rule-based detection can be evaded and does not learn automatically.
- Benchmark examples are team-authored and do not represent the diversity of real-world scams.
- APK indicators are not proof of malware; real-world malware validation and trusted publisher-fingerprint data remain future work.
- QR/UPI parsing cannot verify the recipient's bank-registered identity.
- Static link inspection cannot observe live page behavior or redirects.
- A broader, consented and independently labelled evaluation set is needed before making real-world performance claims.
