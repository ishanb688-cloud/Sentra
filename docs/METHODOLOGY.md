# Methodology: how Sentra scores a case

Sentra is a **rule-based, explainable detection engine**. It is not machine learning and it does not learn
by itself. Every verdict is the result of named warning signs (**signals**), fixed weights, and known scam scripts
(**chains**). All of them live in editable data files (`data/signals.json`, `data/chains.json`, `data/brands.json`),
not hidden in code.

## Pipeline

```
message / link / QR payload / app file
        |
 analyzers/message.py   analyzers/link_qr.py   analyzers/app_file.py      (each emits the same signal shape)
        |
 analyzers/pipeline.py  merges signals (strongest per id; one failing analyzer never breaks the check)
        |
 engine/fusion.py       weights -> categories -> scam scripts -> dampeners -> level
        |
 server.py (POST /api/scan)  ->  web/index.html
```

## A signal

`id`, `category`, `reliability` (how trustworthy this kind of sign is, set once in the catalog), `strength`
(how clearly it appeared in this input, 0 to 1) and `evidence` (the exact text or fact that triggered it).
Categories: impersonation, urgency, credential theft, financial redirect, device takeover, obfuscation,
plus **dampeners** (reassuring signs).

## The calculation (`engine/fusion.py`)

1. **Weight** of a signal = `strength x reliability`.
2. **Category score** = `1 - product(1 - weight)` over the signals in that category (a noisy-OR). Repeats of the same
   kind of sign count less and less.
3. **Base risk** = the same combination across categories, with each category first scaled by **0.6**, so one kind of
   sign cannot reach the top alone.
4. **Scam script bonus.** A category counts as *present* from a score of 0.35. If the present categories complete a chain
   (for example impersonation + urgency + credential theft = fake bank verification), risk moves toward 1 by that
   chain's bonus (0.30 to 0.45). A chain may also require a specific signal.
5. **Dampeners** (such as an official-domain match) reduce risk, capped at **0.40**, and at **0.15** when a full chain is
   present, so one genuine link cannot hide a scam script.
6. **Level:** under 0.30 *Low signals*, under 0.65 *Suspicious*, under 0.85 *High risk*, otherwise *Critical*.
   Sentra never outputs "safe".

The functions are pure, so **the same input always gives the same score** (tested).

## Worked example (computed by the real engine)

Message: `Dear customer, your SBI account will be blocked today. Update your KYC immediately: http://sbi-kyc-update.xyz/login and share the OTP you receive.`

| Signal | Category | Strength | Reliability | Weight |
|---|---|---|---|---|
| `msg_otp_request` | credential_theft | 1.00 | 0.90 | 0.900 |
| `link_lookalike_brand` | impersonation | 1.00 | 0.85 | 0.850 |
| `msg_kyc_update` | credential_theft | 1.00 | 0.70 | 0.700 |
| `msg_threat_block` | urgency | 1.00 | 0.65 | 0.650 |
| `link_credential_form` | credential_theft | 0.80 | 0.80 | 0.640 |
| `link_suspicious_tld` | obfuscation | 1.00 | 0.50 | 0.500 |
| `msg_deadline_pressure` | urgency | 0.80 | 0.55 | 0.440 |
| `msg_authority_claim` | impersonation | 0.60 | 0.60 | 0.360 |

1. **Category scores** (diminishing returns inside each category): credential_theft 0.989, impersonation 0.904, obfuscation 0.500, urgency 0.804.
2. **Base risk** = combine the categories after scaling each by 0.6: **0.933**.
3. **Scam script**: the categories impersonation, urgency and credential theft are all present, which completes the `fake_kyc` chain, so risk moves toward 1 by that chain's bonus: **0.956**.
4. **Level**: 0.956 is at or above 0.85, so the verdict is **Critical**.


## What each analyzer looks at

- **Message:** wording patterns (OTP/PIN requests, pressure and deadlines, impersonation, threats, payment demands,
  job and family-impersonation lures). Genuine warnings such as "do not share your OTP" and toll-free dispute lines are
  removed first so real bank alerts are not flagged.
- **Link:** found anywhere in the text, including bare domains (`example.com`), `www.` forms, shorteners and
  address-without-scheme. Checks: lookalike and typo brand domains, brand name in a subdomain, look-alike characters
  (punycode), raw IP, `@` tricks, unusual ports, suspicious endings, direct app downloads, login-style paths on
  unofficial sites. **Links are never visited**, so there is no redirect following (a shortener is flagged because
  it hides the destination).
- **UPI / QR:** whether the code sends money while the message says you will receive it, a payee named like a refund
  or reward, payee name versus the brand the message mentions, a business-sounding name on a personal phone-number
  ID, and an unfamiliar UPI handle.
- **App file (static only, never run):** SMS read plus screen overlay, SMS interception priority, accessibility and
  device-admin requests, call control, hidden app or code files inside the package, installer permission, debug
  certificate, no valid signature, hidden launcher icon, many sensitive permissions, and a bank-like name whose
  package is not that bank's official app ID.

## Measured quality

### Main benchmark (development set)

90 labelled cases: 58 malicious, 32 genuine.

> Authored by the Sentra team. Not independent real-world data. APK profiles are synthetic permission sets, not real malware.

A case is *flagged* when its level is at or above the cut-off.

| Cut-off | Precision | Recall | False-positive rate | F1 | TP | FN | FP | TN |
|---|---|---|---|---|---|---|---|---|
| Suspicious or above | 100.0% | 100.0% | 0.0% | 1.00 | 58 | 0 | 0 | 32 |
| High risk or above | 100.0% | 60.3% | 0.0% | 0.75 | 35 | 23 | 0 | 32 |

## By category (flagged at Suspicious or above)

| Category | Cases | Malicious caught | Genuine wrongly flagged |
|---|---|---|---|
| Phishing / KYC messages | 20 | 20/20 | 0/0 |
| Parcel and payment scams | 15 | 15/15 | 0/0 |
| Genuine messages | 20 | 0/0 | 0/20 |
| Suspicious URLs | 20 | 14/14 | 0/6 |
| QR / UPI examples | 10 | 6/6 | 0/4 |
| APK permission profiles | 5 | 3/3 | 0/2 |

## Misses and false alarms

None at the Suspicious cut-off.


See `docs/BENCHMARK.md` and `docs/HOLDOUT.md` for every case, and `python tools/benchmark.py [--holdout]` to reproduce.
The test cases were written by the Sentra team, so they are **not independent real-world data**.
