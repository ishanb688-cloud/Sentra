"""Runs the labelled benchmark and reports precision, recall, false-positive rate and F1.

    python tools/benchmark.py            # print the report
    python tools/benchmark.py --write    # also write docs/BENCHMARK.md and docs/benchmark.json
"""
import json
import sys
from collections import OrderedDict, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from analyzers.app_file import signals_from_facts
from analyzers.pipeline import scan
from engine.fusion import ORDER, fuse

SET = "holdout" if "--holdout" in sys.argv else "benchmark"
DATA = json.loads((ROOT / "tests" / f"{SET}.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]


def evaluate(case):
    if case["kind"] == "app":
        facts = {**case["facts"], "permissions": set(case["facts"]["permissions"])}
        signals = signals_from_facts(facts)
    elif case["kind"] == "qr":
        signals = scan((case.get("context", "") + "\n" + case["input"]).strip())
    else:
        signals = scan(case["input"])
    r = fuse(signals)
    return r["level"], r["risk"], r["chain"], [s["id"] for s in signals]


def metrics(rows, cut):
    flag = lambda lv: ORDER.index(lv) >= ORDER.index(cut)
    tp = sum(1 for c, r in rows if c["label"] == "malicious" and flag(r[0]))
    fn = sum(1 for c, r in rows if c["label"] == "malicious" and not flag(r[0]))
    fp = sum(1 for c, r in rows if c["label"] == "genuine" and flag(r[0]))
    tn = sum(1 for c, r in rows if c["label"] == "genuine" and not flag(r[0]))
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return dict(tp=tp, fn=fn, fp=fp, tn=tn, precision=prec, recall=rec, fpr=fpr, f1=f1)


def run():
    rows = [(c, evaluate(c)) for c in CASES]
    out = {"cutoffs": {}, "categories": OrderedDict(), "rows": rows}
    for cut in ("Suspicious", "High risk"):
        out["cutoffs"][cut] = metrics(rows, cut)
    cats = OrderedDict()
    for c, r in rows:
        cats.setdefault(c["category"], []).append((c, r))
    for name, rs in cats.items():
        out["categories"][name] = {cut: metrics(rs, cut) for cut in ("Suspicious", "High risk")} | {"n": len(rs)}
    return out


def pct(x):
    return f"{x * 100:.1f}%"


def report(res):
    L = ["# Sentra " + ("holdout" if SET == "holdout" else "benchmark"), "",
         f"{len(CASES)} labelled cases: {sum(1 for c in CASES if c['label']=='malicious')} malicious, "
         f"{sum(1 for c in CASES if c['label']=='genuine')} genuine.", "",
         "> " + DATA["meta"]["note"], "",
         "A case is *flagged* when its level is at or above the cut-off.", ""]
    L += ["| Cut-off | Precision | Recall | False-positive rate | F1 | TP | FN | FP | TN |", "|---|---|---|---|---|---|---|---|---|"]
    for cut, m in res["cutoffs"].items():
        L.append(f"| {cut} or above | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['fpr'])} | {m['f1']:.2f} | {m['tp']} | {m['fn']} | {m['fp']} | {m['tn']} |")
    L += ["", "## Confusion matrix (Suspicious or above)", "",
          "| | Predicted scam | Predicted not flagged |", "|---|---:|---:|",
          f"| Actual scam | {res['cutoffs']['Suspicious']['tp']} (TP) | {res['cutoffs']['Suspicious']['fn']} (FN) |",
          f"| Actual genuine | {res['cutoffs']['Suspicious']['fp']} (FP) | {res['cutoffs']['Suspicious']['tn']} (TN) |",
          "", "## By category (flagged at Suspicious or above)", "",
          "| Category | Cases | Malicious caught | Genuine wrongly flagged |", "|---|---|---|---|"]
    for name, d in res["categories"].items():
        m = d["Suspicious"]
        mal, gen = m["tp"] + m["fn"], m["fp"] + m["tn"]
        L.append(f"| {name} | {d['n']} | {m['tp']}/{mal} | {m['fp']}/{gen} |" if mal or gen else f"| {name} | {d['n']} | - | - |")
    L += ["", "## Misses and false alarms", ""]
    bad = [(c, r) for c, r in res["rows"]
           if (c["label"] == "malicious" and ORDER.index(r[0]) < 1) or (c["label"] == "genuine" and ORDER.index(r[0]) >= 1)]
    if not bad:
        L.append("None at the Suspicious cut-off.")
    for c, r in bad:
        kind = "MISSED scam" if c["label"] == "malicious" else "FALSE ALARM"
        L.append(f"- **{c['id']}** {kind} ({r[0]}, risk {r[1]}): `{c['input'][:90]}`")
    L += ["", "## Every case", "", "| ID | Category | Label | Level | Risk | Chain | Correct (Suspicious cut-off) |", "|---|---|---|---|---|---|---|"]
    for c, r in res["rows"]:
        flagged = ORDER.index(r[0]) >= 1
        ok = flagged == (c["label"] == "malicious")
        L.append(f"| {c['id']} | {c['category']} | {c['label']} | {r[0]} | {r[1]} | {r[2] or '-'} | {'yes' if ok else '**no**'} |")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    res = run()
    text = report(res)
    print(text.split("## Every case")[0])
    if "--write" in sys.argv:
        (ROOT / "docs").mkdir(exist_ok=True)
        (ROOT / "docs" / ("HOLDOUT.md" if SET == "holdout" else "BENCHMARK.md")).write_text(text, encoding="utf-8")
        summary = {"cases": len(CASES), "cutoffs": res["cutoffs"],
                   "categories": {k: {"n": v["n"], "Suspicious": v["Suspicious"]} for k, v in res["categories"].items()}}
        (ROOT / "docs" / ("holdout.json" if SET == "holdout" else "benchmark.json")).write_text(json.dumps(summary, indent=1), encoding="utf-8")
        print("wrote the report files in docs/")
