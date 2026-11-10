"""Evaluate SENTRA on the public UCI SMS Spam Collection (no training or tuning).

Download and extract the UCI dataset, then run:
    python tools/evaluate_uci_sms.py /path/to/SMSSpamCollection
    python tools/evaluate_uci_sms.py /path/to/SMSSpamCollection --json external_sms_results.json

The dataset is external to SENTRA's team-authored benchmarks. This script only
measures the existing rule engine; it does not train a model or change rules.
"""
import argparse
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analyzers.pipeline import scan
from engine.fusion import ORDER, fuse


def evaluate(path: Path, cutoff: str = "Suspicious") -> dict:
    if cutoff not in ORDER:
        raise ValueError(f"Unknown cutoff {cutoff!r}; choose one of: {', '.join(ORDER)}")

    rows = []
    skipped = 0
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.reader(handle, delimiter="\t")
        for row in reader:
            if len(row) < 2:
                skipped += 1
                continue
            label = row[0].strip().lower()
            message = "\t".join(row[1:]).strip()
            if label not in {"spam", "ham"} or not message:
                skipped += 1
                continue
            result = fuse(scan(message))
            flagged = ORDER.index(result["level"]) >= ORDER.index(cutoff)
            rows.append((label, flagged, result["level"]))

    tp = sum(label == "spam" and flagged for label, flagged, _ in rows)
    fn = sum(label == "spam" and not flagged for label, flagged, _ in rows)
    fp = sum(label == "ham" and flagged for label, flagged, _ in rows)
    tn = sum(label == "ham" and not flagged for label, flagged, _ in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "dataset": "UCI SMS Spam Collection",
        "cutoff": cutoff,
        "cases_evaluated": len(rows),
        "skipped_rows": skipped,
        "spam": tp + fn,
        "ham": fp + tn,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fpr,
        "f1": f1,
        "scope_note": (
            "External English SMS corpus; historical and not representative of "
            "current Indian-language scams, URLs, QR/UPI payloads or APKs."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="Path to UCI SMSSpamCollection TSV file")
    parser.add_argument("--cutoff", default="Suspicious", choices=ORDER)
    parser.add_argument("--json", dest="json_path", type=Path, help="Optional path to save machine-readable results")
    args = parser.parse_args()

    if not args.dataset.is_file():
        parser.error(f"Dataset file not found: {args.dataset}")

    result = evaluate(args.dataset, args.cutoff)
    print(json.dumps(result, indent=2))
    if args.json_path:
        args.json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Saved results to {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
