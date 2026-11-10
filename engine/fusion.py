"""Sentra scoring engine: turns signals into one explainable risk verdict.

Pure functions only: the same signals always give the same score.
"""
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"

with open(DATA / "chains.json", encoding="utf-8") as f:
    CHAINS = [{**c, "need": set(c["need"])} for c in json.load(f)]

with open(DATA / "signals.json", encoding="utf-8") as f:
    CATALOG = {s["id"]: s for s in json.load(f)}

LEVELS = [(0.30, "Low signals"), (0.65, "Suspicious"),
          (0.85, "High risk"), (1.01, "Critical")]
ORDER = [name for _, name in LEVELS]
CATEGORY_SCALE = 0.6      # keeps one category from reaching the top alone
CHAIN_PRESENT_AT = 0.35   # a category counts toward a chain from this score
DAMP_CAP = 0.40           # dampeners can reduce risk by at most this much
DAMP_CAP_WITH_CHAIN = 0.15


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

    by_cat = {}
    for s in risk_sigs:
        by_cat.setdefault(s["category"], []).append(weight(s))
    cat_scores = {c: noisy_or(ws) for c, ws in by_cat.items()}

    base = noisy_or([v * CATEGORY_SCALE for v in cat_scores.values()])

    present = {c for c, v in cat_scores.items() if v >= CHAIN_PRESENT_AT}
    ids = {x["id"] for x in risk_sigs}
    done = [ch for ch in CHAINS
            if ch["need"] <= present and set(ch.get("with_signals", [])) <= ids]
    best = max(done, key=lambda ch: (ch["bonus"], len(ch["need"])), default=None)
    risk = base + (1 - base) * best["bonus"] if best else base

    damp = min(DAMP_CAP, sum(weight(s) for s in damp_sigs))
    if best:
        damp = min(damp, DAMP_CAP_WITH_CHAIN)
    risk *= (1 - damp)

    level = next(name for limit, name in LEVELS if risk < limit)
    ranked = sorted(risk_sigs, key=lambda s: (-weight(s), s["id"]))
    return {
        "risk": round(risk, 3),
        "level": level,
        "chain": best["id"] if best else None,
        "replay": best["replay"] if best else [],
        "categories": {c: round(v, 3) for c, v in sorted(cat_scores.items())},
        "top_signals": ranked[:5],
        "dampeners": damp_sigs,
    }
