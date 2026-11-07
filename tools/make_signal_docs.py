import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
signals = json.loads((root / "data" / "signals.json").read_text(encoding="utf-8"))

lines = [
    "# Signal catalog",
    "",
    "Generated from `data/signals.json`. Refresh with `python tools/make_signal_docs.py`.",
    "",
    "| Signal | Category | Reliability | Meaning |",
    "|---|---|---|---|",
]
for s in signals:
    lines.append(f"| `{s['id']}` | {s['category']} | {s['reliability']:.2f} | {s['reason']} |")

(root / "docs" / "SIGNALS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"Wrote {len(signals)} signals")