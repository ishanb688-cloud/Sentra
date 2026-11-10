"""Every advertised signal must actually be produced, and every produced signal must be documented."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = {s["id"]: s for s in json.loads((ROOT / "data" / "signals.json").read_text(encoding="utf-8"))}
SOURCE = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "analyzers").glob("*.py"))
ID_LIKE = re.compile(r'"((?:msg|link|qr|app)_[a-z_]+|official_domain_match|no_action_requested|known_sender_format)"')


def test_every_catalog_signal_is_produced_by_an_analyzer():
    unused = [i for i in CATALOG if f'"{i}"' not in SOURCE]
    assert unused == [], f"advertised but never produced: {unused}"


def test_every_signal_used_in_code_is_in_the_catalog():
    missing = sorted(set(ID_LIKE.findall(SOURCE)) - set(CATALOG))
    assert missing == [], f"used in code but missing from data/signals.json: {missing}"


def test_chains_only_use_known_categories_and_signals():
    cats = {s["category"] for s in CATALOG.values()}
    for c in json.loads((ROOT / "data" / "chains.json").read_text(encoding="utf-8")):
        assert set(c["need"]) <= cats
        assert set(c.get("with_signals", [])) <= set(CATALOG)
        assert c["replay"]


def test_every_signal_has_a_plain_reason_and_valid_reliability():
    for s in CATALOG.values():
        assert 0 < s["reliability"] <= 1 and len(s["reason"]) > 10
