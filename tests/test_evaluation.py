import json
from pathlib import Path

from analyzers.pipeline import scan
from engine.fusion import fuse

ORDER = ["Low signals", "Suspicious", "High risk", "Critical"]
CASES = json.loads((Path(__file__).parent / "cases.json").read_text(encoding="utf-8"))


def level(text):
    return ORDER.index(fuse(scan(text))["level"])


def test_no_false_alarms_on_genuine_messages():
    bad = [c["text"] for c in CASES if c["label"] == "genuine" and level(c["text"]) >= 1]
    assert bad == []


def test_most_scams_are_flagged():
    scams = [c for c in CASES if c["label"] == "scam"]
    caught = sum(level(c["text"]) >= 1 for c in scams)
    assert caught >= int(len(scams) * 0.85)