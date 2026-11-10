# Sentra holdout

40 labelled cases: 22 malicious, 18 genuine.

> Holdout set written after the main benchmark and NOT used to tune rules. Still authored by the Sentra team, so not independent real-world data.

A case is *flagged* when its level is at or above the cut-off.

| Cut-off | Precision | Recall | False-positive rate | F1 | TP | FN | FP | TN |
|---|---|---|---|---|---|---|---|---|
| Suspicious or above | 94.4% | 77.3% | 5.6% | 0.85 | 17 | 5 | 1 | 17 |
| High risk or above | 100.0% | 40.9% | 0.0% | 0.58 | 9 | 13 | 0 | 18 |

## By category (flagged at Suspicious or above)

| Category | Cases | Malicious caught | Genuine wrongly flagged |
|---|---|---|---|
| Holdout: messages | 26 | 10/14 | 1/12 |
| Holdout: links | 9 | 4/5 | 0/4 |
| Holdout: QR / UPI | 5 | 3/3 | 0/2 |

## Misses and false alarms

- **H01** MISSED scam (Low signals, risk 0.288): `Hello sir, your parcel address is incorrect. Update here to avoid return: trackmypkg-india`
- **H02** MISSED scam (Low signals, risk 0.248): `Congrats! You are selected for Amazon part time job. Earn 3000/day. Registration fee Rs 49`
- **H06** MISSED scam (Low signals, risk 0.264): `Your credit card has been charged Rs 49,999 for iPhone. If not authorised, call our helpli`
- **H13** MISSED scam (Low signals, risk 0.0): `Hi, I saw your profile. Invest Rs 5,000 in our crypto plan and get Rs 20,000 in 2 days. Gu`
- **H16** FALSE ALARM (Suspicious, risk 0.54): `Your Flipkart order is out for delivery. Share the delivery OTP 4821 with the agent only a`
- **H31** MISSED scam (Low signals, risk 0.0): `https://paytmbank-kyc.in/upload`

## Every case

| ID | Category | Label | Level | Risk | Chain | Correct (Suspicious cut-off) |
|---|---|---|---|---|---|---|
| H01 | Holdout: messages | malicious | Low signals | 0.288 | - | **no** |
| H02 | Holdout: messages | malicious | Low signals | 0.248 | - | **no** |
| H03 | Holdout: messages | malicious | Suspicious | 0.39 | - | yes |
| H04 | Holdout: messages | malicious | Critical | 0.894 | fake_kyc | yes |
| H05 | Holdout: messages | malicious | High risk | 0.735 | - | yes |
| H06 | Holdout: messages | malicious | Low signals | 0.264 | - | **no** |
| H07 | Holdout: messages | malicious | Suspicious | 0.39 | - | yes |
| H08 | Holdout: messages | malicious | Suspicious | 0.3 | - | yes |
| H09 | Holdout: messages | malicious | High risk | 0.665 | fake_shop | yes |
| H10 | Holdout: messages | malicious | High risk | 0.701 | - | yes |
| H11 | Holdout: messages | malicious | Suspicious | 0.54 | - | yes |
| H12 | Holdout: messages | malicious | Critical | 0.893 | bad_app | yes |
| H13 | Holdout: messages | malicious | Low signals | 0.0 | - | **no** |
| H14 | Holdout: messages | malicious | High risk | 0.81 | courier_fee | yes |
| H15 | Holdout: messages | genuine | Low signals | 0.162 | - | yes |
| H16 | Holdout: messages | genuine | Suspicious | 0.54 | - | **no** |
| H17 | Holdout: messages | genuine | Low signals | 0.0 | - | yes |
| H18 | Holdout: messages | genuine | Low signals | 0.0 | - | yes |
| H19 | Holdout: messages | genuine | Low signals | 0.162 | - | yes |
| H20 | Holdout: messages | genuine | Low signals | 0.0 | - | yes |
| H21 | Holdout: messages | genuine | Low signals | 0.216 | - | yes |
| H22 | Holdout: messages | genuine | Low signals | 0.0 | - | yes |
| H23 | Holdout: messages | genuine | Low signals | 0.162 | - | yes |
| H24 | Holdout: messages | genuine | Low signals | 0.288 | - | yes |
| H25 | Holdout: messages | genuine | Low signals | 0.0 | - | yes |
| H26 | Holdout: messages | genuine | Low signals | 0.273 | - | yes |
| H27 | Holdout: links | malicious | High risk | 0.666 | - | yes |
| H28 | Holdout: links | malicious | Suspicious | 0.545 | - | yes |
| H29 | Holdout: links | malicious | High risk | 0.678 | - | yes |
| H30 | Holdout: links | malicious | Suspicious | 0.435 | - | yes |
| H31 | Holdout: links | malicious | Low signals | 0.0 | - | **no** |
| H32 | Holdout: links | genuine | Low signals | 0.151 | - | yes |
| H33 | Holdout: links | genuine | Low signals | 0.0 | - | yes |
| H34 | Holdout: links | genuine | Low signals | 0.0 | - | yes |
| H35 | Holdout: links | genuine | Low signals | 0.0 | - | yes |
| H36 | Holdout: QR / UPI | malicious | Suspicious | 0.584 | - | yes |
| H37 | Holdout: QR / UPI | malicious | High risk | 0.731 | fake_shop | yes |
| H38 | Holdout: QR / UPI | malicious | Suspicious | 0.569 | - | yes |
| H39 | Holdout: QR / UPI | genuine | Low signals | 0.0 | - | yes |
| H40 | Holdout: QR / UPI | genuine | Low signals | 0.0 | - | yes |
