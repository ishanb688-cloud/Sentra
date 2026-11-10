# Sentra benchmark

92 labelled cases: 59 malicious, 33 genuine.

> Authored by the Sentra team. Not independent real-world data. APK profiles are synthetic permission sets, not real malware.

A case is *flagged* when its level is at or above the cut-off.

| Cut-off | Precision | Recall | False-positive rate | F1 | TP | FN | FP | TN |
|---|---|---|---|---|---|---|---|---|
| Suspicious or above | 100.0% | 100.0% | 0.0% | 1.00 | 58 | 0 | 0 | 32 |
| High risk or above | 100.0% | 59.3% | 0.0% | 0.74 | 35 | 24 | 0 | 33 |

## By category (flagged at Suspicious or above)

| Category | Cases | Malicious caught | Genuine wrongly flagged |
|---|---|---|---|
| Phishing / KYC messages | 20 | 20/20 | 0/0 |
| Parcel and payment scams | 15 | 15/15 | 0/0 |
| Genuine messages | 20 | 0/0 | 0/20 |
| Suspicious URLs | 20 | 14/14 | 0/6 |
| QR / UPI examples | 10 | 6/6 | 0/4 |
| APK permission profiles | 5 | 3/3 | 0/2 |
| Online task scams | 2 | 1/1 | 0/1 |

## Misses and false alarms

None at the Suspicious cut-off.

## Every case

| ID | Category | Label | Level | Risk | Chain | Correct (Suspicious cut-off) |
|---|---|---|---|---|---|---|
| P01 | Phishing / KYC messages | malicious | High risk | 0.718 | - | yes |
| P02 | Phishing / KYC messages | malicious | Critical | 0.904 | fake_kyc | yes |
| P03 | Phishing / KYC messages | malicious | Suspicious | 0.423 | - | yes |
| P04 | Phishing / KYC messages | malicious | High risk | 0.761 | authority_coercion | yes |
| P05 | Phishing / KYC messages | malicious | High risk | 0.68 | - | yes |
| P06 | Phishing / KYC messages | malicious | Suspicious | 0.477 | - | yes |
| P07 | Phishing / KYC messages | malicious | Suspicious | 0.522 | - | yes |
| P08 | Phishing / KYC messages | malicious | Critical | 0.926 | fake_kyc | yes |
| P09 | Phishing / KYC messages | malicious | Suspicious | 0.639 | - | yes |
| P10 | Phishing / KYC messages | malicious | Critical | 0.864 | fake_kyc | yes |
| P11 | Phishing / KYC messages | malicious | Suspicious | 0.482 | - | yes |
| P12 | Phishing / KYC messages | malicious | Suspicious | 0.51 | - | yes |
| P13 | Phishing / KYC messages | malicious | High risk | 0.735 | - | yes |
| P14 | Phishing / KYC messages | malicious | Critical | 0.855 | authority_coercion | yes |
| P15 | Phishing / KYC messages | malicious | High risk | 0.847 | fake_kyc | yes |
| P16 | Phishing / KYC messages | malicious | High risk | 0.726 | fake_shop | yes |
| P17 | Phishing / KYC messages | malicious | Critical | 0.853 | - | yes |
| P18 | Phishing / KYC messages | malicious | High risk | 0.684 | - | yes |
| P19 | Phishing / KYC messages | malicious | High risk | 0.664 | - | yes |
| P20 | Phishing / KYC messages | malicious | High risk | 0.745 | - | yes |
| S01 | Parcel and payment scams | malicious | Critical | 0.866 | fake_shop | yes |
| S02 | Parcel and payment scams | malicious | High risk | 0.665 | - | yes |
| S03 | Parcel and payment scams | malicious | High risk | 0.828 | fake_shop | yes |
| S04 | Parcel and payment scams | malicious | Suspicious | 0.502 | - | yes |
| S05 | Parcel and payment scams | malicious | High risk | 0.783 | fake_shop | yes |
| S06 | Parcel and payment scams | malicious | Suspicious | 0.39 | - | yes |
| S07 | Parcel and payment scams | malicious | High risk | 0.799 | courier_fee | yes |
| S08 | Parcel and payment scams | malicious | Suspicious | 0.516 | - | yes |
| S09 | Parcel and payment scams | malicious | Suspicious | 0.3 | - | yes |
| S10 | Parcel and payment scams | malicious | Suspicious | 0.576 | - | yes |
| S11 | Parcel and payment scams | malicious | Suspicious | 0.39 | - | yes |
| S12 | Parcel and payment scams | malicious | High risk | 0.751 | wrong_transfer | yes |
| S13 | Parcel and payment scams | malicious | High risk | 0.687 | - | yes |
| S14 | Parcel and payment scams | malicious | Suspicious | 0.54 | - | yes |
| S15 | Parcel and payment scams | malicious | High risk | 0.849 | qr_reverse | yes |
| G01 | Genuine messages | genuine | Low signals | 0.13 | - | yes |
| G02 | Genuine messages | genuine | Low signals | 0.162 | - | yes |
| G03 | Genuine messages | genuine | Low signals | 0.216 | - | yes |
| G04 | Genuine messages | genuine | Low signals | 0.13 | - | yes |
| G05 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G06 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G07 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G08 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G09 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G10 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G11 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G12 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G13 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G14 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G15 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G16 | Genuine messages | genuine | Low signals | 0.162 | - | yes |
| G17 | Genuine messages | genuine | Low signals | 0.162 | - | yes |
| G18 | Genuine messages | genuine | Low signals | 0.162 | - | yes |
| G19 | Genuine messages | genuine | Low signals | 0.0 | - | yes |
| G20 | Genuine messages | genuine | Low signals | 0.162 | - | yes |
| U01 | Suspicious URLs | malicious | High risk | 0.757 | - | yes |
| U02 | Suspicious URLs | malicious | Suspicious | 0.48 | - | yes |
| U03 | Suspicious URLs | malicious | High risk | 0.676 | - | yes |
| U04 | Suspicious URLs | malicious | High risk | 0.742 | - | yes |
| U05 | Suspicious URLs | malicious | Suspicious | 0.586 | - | yes |
| U06 | Suspicious URLs | malicious | Suspicious | 0.459 | - | yes |
| U07 | Suspicious URLs | malicious | Suspicious | 0.435 | - | yes |
| U08 | Suspicious URLs | malicious | High risk | 0.794 | - | yes |
| U09 | Suspicious URLs | malicious | Suspicious | 0.635 | - | yes |
| U10 | Suspicious URLs | malicious | Suspicious | 0.586 | - | yes |
| U11 | Suspicious URLs | malicious | Critical | 0.887 | bad_app | yes |
| U12 | Suspicious URLs | malicious | High risk | 0.653 | - | yes |
| U13 | Suspicious URLs | malicious | High risk | 0.778 | - | yes |
| U14 | Suspicious URLs | malicious | Suspicious | 0.435 | - | yes |
| U15 | Suspicious URLs | genuine | Low signals | 0.151 | - | yes |
| U16 | Suspicious URLs | genuine | Low signals | 0.0 | - | yes |
| U17 | Suspicious URLs | genuine | Low signals | 0.0 | - | yes |
| U18 | Suspicious URLs | genuine | Low signals | 0.0 | - | yes |
| U19 | Suspicious URLs | genuine | Low signals | 0.0 | - | yes |
| U20 | Suspicious URLs | genuine | Low signals | 0.202 | - | yes |
| Q01 | QR / UPI examples | malicious | Suspicious | 0.553 | - | yes |
| Q02 | QR / UPI examples | malicious | High risk | 0.731 | fake_shop | yes |
| Q03 | QR / UPI examples | malicious | High risk | 0.731 | fake_shop | yes |
| Q04 | QR / UPI examples | malicious | High risk | 0.827 | fake_kyc | yes |
| Q05 | QR / UPI examples | malicious | Suspicious | 0.482 | - | yes |
| Q06 | QR / UPI examples | malicious | Suspicious | 0.628 | - | yes |
| Q07 | QR / UPI examples | genuine | Low signals | 0.0 | - | yes |
| Q08 | QR / UPI examples | genuine | Low signals | 0.0 | - | yes |
| Q09 | QR / UPI examples | genuine | Low signals | 0.216 | - | yes |
| Q10 | QR / UPI examples | genuine | Low signals | 0.0 | - | yes |
| A01 | APK permission profiles | malicious | Critical | 0.943 | bad_app | yes |
| A02 | APK permission profiles | malicious | Critical | 0.932 | bad_app | yes |
| A03 | APK permission profiles | malicious | Critical | 0.899 | bad_app | yes |
| A04 | APK permission profiles | genuine | Low signals | 0.24 | - | yes |
| A05 | APK permission profiles | genuine | Low signals | 0.0 | - | yes |
| T01 | Online task scams | malicious | Suspicious | 0.589 | task_recharge | yes |
| T02 | Online task scams | genuine | Low signals | 0.0 | - | yes |
