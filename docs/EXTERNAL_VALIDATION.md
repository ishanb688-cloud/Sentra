# External validation plan

## Purpose

The existing 92-case development benchmark and 40-case holdout are authored by the SENTRA team. They are useful regression suites, but they are not independent evidence. This document defines a reproducible external check without presenting unrun results as facts.

## First external corpus: UCI SMS Spam Collection

- Source: [UCI Machine Learning Repository — SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection)
- Size: 5,574 English SMS messages, labelled `spam` or `ham`.
- Original research: Almeida, Hidalgo and Yamakami, *Contributions to the Study of SMS Spam Filtering: New Collection and Results* (2011).
- This is a public research corpus, not a current India-specific scam dataset. It is suitable for an independent message-only check, not for validating URLs, UPI/QR or APK analysis.

### Reproduce the evaluation

1. Download the dataset from the official UCI page and extract the `SMSSpamCollection` tab-separated file.
2. Do not add its rows to `tests/benchmark.json` or tune SENTRA's rules against the test output.
3. From the repository root, run:

```bash
python tools/evaluate_uci_sms.py /path/to/SMSSpamCollection
python tools/evaluate_uci_sms.py /path/to/SMSSpamCollection --json external_sms_results.json
```

The script runs the existing message pipeline unchanged and reports TP, FN, FP, TN, precision, recall, F1 and false-positive rate at the Suspicious threshold. Keep the raw corpus outside the repository unless its terms and privacy implications have been reviewed.

### Interpretation limits

- This is an external corpus evaluation, not proof of current real-world performance.
- The corpus is English and historical; it does not represent modern Indian bank, UPI, parcel, job, Hinglish or regional-language scams.
- The labels are spam/ham, not a perfect mapping to fraud/non-fraud. Some spam is merely unwanted marketing, and some harmful messages may be labelled ham.
- It tests message analysis only. It says nothing about URL, QR/UPI or APK performance.
- Report the exact corpus version, file hash, date downloaded, evaluated row count, skipped rows, threshold and confusion matrix with any result.
- Do not combine these results with the team-authored benchmark/holdout into one headline score.

## Additional independent URL sources (malicious-only)

- [PhishTank developer data](https://www.phishtank.org/developer_info.php) provides community-verified phishing URLs and metadata.
- [URLhaus Community API](https://urlhaus.abuse.ch/api/) provides malware-distribution URL data and requires an Auth-Key for downloads.

These feeds can be used for a malicious-URL challenge set after checking their current access and terms. They are malicious-only feeds: they cannot estimate false-positive rate or specificity without a separately sourced, carefully labelled benign set. Never open or browse malicious URLs to test them. Feed entries should be parsed offline as strings and deduplicated by registrable domain/time window to reduce leakage.

## Reporting template

Do not fill in numbers until the script has actually been run:

| Item | Result |
|---|---|
| Dataset/version and download date | Pending |
| SHA-256 of source file | Pending |
| Rows evaluated / skipped | Pending |
| Threshold | Suspicious or above |
| TP / FN / FP / TN | Pending |
| Precision / recall / F1 / FPR | Pending |
| Known limitations | English historical SMS corpus; message-only |

## Recorded evaluation

The evaluator was run in GitHub Actions run [42984428938](https://github.com/ishanb688-cloud/Sentra/actions/runs/42984428938) on 5,572 messages: 747 labelled spam and 4,825 labelled ham.

| Item | Recorded result |
|---|---|
| Dataset | UCI SMS Spam Collection; historical English SMS |
| Rows evaluated | 5,572 |
| Spam / ham | 747 / 4,825 |
| Source-file SHA-256 | Not recorded in the available run summary |
| Download date | Not recorded in the available run summary |
| Threshold | Suspicious or above |
| TP / FN / FP / TN | 189 / 558 / 7 / 4,818 |
| Precision / recall / F1 / FPR | 96.43% / 25.30% / 40.08% / 0.145% |

**Interpretation:** this is an evaluation on a public external corpus, not a current real-world deployment study. The low recall is material: 558 of 747 spam messages were not flagged. Do not describe the result as overall Sentra accuracy or use it to make claims about URL, QR/UPI or APK analysis. The original reproducibility harness remains available; for a fully reproducible rerun, retain the exact downloaded file, its SHA-256, download date, script revision and complete output.
