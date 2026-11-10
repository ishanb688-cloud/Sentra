# Sentra holdout benchmark

40 labelled cases: 22 malicious and 18 genuine.

> Written by the Sentra team and kept separate from the main development set. This is not independent real-world data.

A case is *flagged* when its level is at or above the selected cut-off.

| Cut-off | Precision | Recall | False-positive rate | F1 | TP | FN | FP | TN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Suspicious or above | **100.0%** | **100.0%** | **0.0%** | **1.00** | 22 | 0 | 0 | 18 |
| High risk or above | 100.0% | 50.0% | 0.0% | 0.67 | 11 | 11 | 0 | 18 |

## Results by input type

| Category | Cases | Malicious caught | Genuine wrongly flagged |
|---|---:|---:|---:|
| Messages | 26 | 14 / 14 | 0 / 12 |
| Links | 9 | 5 / 5 | 0 / 4 |
| QR / UPI | 5 | 3 / 3 | 0 / 2 |

## Misses and false alarms

None at the Suspicious-or-higher cut-off in this holdout run.

## Reproduce

```bash
python tools/benchmark.py --holdout
python tools/benchmark.py --holdout --write
```

The `--write` option regenerates the case-by-case report and JSON summary from the current code. Do not treat this
team-authored benchmark as proof of real-world accuracy; independent and consented evaluation data is still needed.
