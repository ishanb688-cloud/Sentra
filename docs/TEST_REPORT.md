# SENTRA test report

## What the automated suite covers

| Area | Automated coverage | What is checked |
|---|---|---|
| Message detection | `tests/test_message.py`, `tests/test_message_regressions.py` | OTP theft vs doorstep delivery OTP, bank warnings, investment-return pitches, delivery fees, job-registration fees, task scams, threats and ordinary messages |
| URL analysis | `tests/test_urls.py`, `tests/test_links.py` | Official domains, brand lookalikes, Paytm-style impersonation, misleading subdomains, percent-encoded host/path, IP hosts, shorteners, punycode, unusual schemes and QR payload separation |
| QR / UPI | `tests/test_links.py` | Payment request presented as receiving money, payee/brand mismatch, business-like payee on a personal-number VPA, normal merchant/person examples |
| APK | `tests/test_app_rules.py`, `tests/test_api.py` | Sensitive permission combinations, package/name mismatch, malformed ZIPs, missing manifest, entry-count/unpacked-size limits, oversized uploads and temporary-file cleanup |
| API security | `tests/test_api.py` | Invalid multipart requests, generic errors, no traceback/path leakage, request-body limits, rate limiting, proxy-header trust, security headers and shared limiter failure behaviour |
| Browser demo | `tests/test_frontend_contract.py` | QR upload byte/pixel caps before canvas sizing, camera failure fallback, repeatable demo examples and explicit unverified-payee warning |
| Public deployment | `tools/check_deployment.py` | Live HTTPS health endpoint, HSTS, CSP, nosniff and frame-denial headers; runs on pushes to `main` against the Render URL after merge/deployment |
| APK demo fixture | `tools/make_demo_apk.py`, `tests/test_api.py` | Reproducible intentionally malformed `.apk` upload demonstrates graceful rejection; it is not an installable app or malware sample |

## Reproduce locally

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
python tools/benchmark.py
python tools/benchmark.py --holdout
python tools/make_demo_apk.py
```

The benchmark commands report precision, recall, F1, false-positive rate and confusion-matrix counts at both Suspicious and High risk thresholds.

## Evaluation integrity

- `tests/benchmark.json` is the development benchmark.
- `tests/holdout.json` is a separate team-authored evaluation set; detector tuning should use neither its examples nor its results.
- The holdout is not independent, externally labelled or representative of real-world scam prevalence. It is a limited internal check, not a claim of production accuracy.
- Synthetic APK permission profiles are not real malware samples.
- Rule-based indicators can be evaded by unseen wording, domains and malware behaviour.

## Manual checks still required

The deployment smoke script checks the public Render API health response and security headers from the CI runner. It does not verify that this unmerged PR has been deployed. Camera behaviour on a physical phone and visual correctness of screenshots still require a real browser/device. Do not represent static HTML contract tests as end-to-end browser tests.
