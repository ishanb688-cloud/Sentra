import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"

with open(DATA / "chains.json") as f:
    CHAINS = [{**c, "need": set(c["need"])} for c in json.load(f)]

with open(DATA / "signals.json") as f:
    CATALOG = {s["id"]: s for s in json.load(f)}

LEVELS = [(0.30, "Low signals"), (0.65, "Suspicious"),
          (0.85, "High risk"), (1.01, "Critical")]

def make(signal_id, strength, evidence=""):
    return {**CATALOG[signal_id], "strength": strength, "evidence": evidence}


def weight(sig):
    return sig["strength"] * sig["reliability"]


def noisy_or(weights):
    left = 1.0
    for w in weights:
        left *= (1.0 - w)
    return 1.0 - left


def fuse(signals):
    risk_sigs = [s for s in signals if s["category"] != "dampener"]
    damp_sigs = [s for s in signals if s["category"] == "dampener"]

    # 1. roll up within each category (repeats give diminishing returns)
    by_cat = {}
    for s in risk_sigs:
        by_cat.setdefault(s["category"], []).append(weight(s))
    cat_scores = {c: noisy_or(ws) for c, ws in by_cat.items()}

    # 2. combine categories, kept below 1 so chains have room to matter
    base = noisy_or([v * 0.6 for v in cat_scores.values()])

    # 3. chain bonus: pick the strongest complete chain
    present = {c for c, v in cat_scores.items() if v >= 0.35}
    done = [ch for ch in CHAINS if ch["need"] <= present]
    best = max(done, key=lambda ch: ch["bonus"], default=None)
    risk = base + (1 - base) * best["bonus"] if best else base

    # 4. dampeners, capped so they cannot erase a complete chain
    damp = min(0.4, sum(weight(s) for s in damp_sigs))
    if best:
        damp = min(damp, 0.15)
    risk *= (1 - damp)

    level = next(name for limit, name in LEVELS if risk < limit)
    ranked = sorted(risk_sigs, key=weight, reverse=True)
    return {
        "risk": round(risk, 3),
        "level": level,
        "chain": best["id"] if best else None,
        "categories": {c: round(v, 3) for c, v in cat_scores.items()},
        "replay": best["replay"] if best else [],
        "top_signals": ranked[:5],
        "dampeners": damp_sigs,
    }