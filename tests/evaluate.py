import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzers.pipeline import scan
from engine.fusion import fuse

cases = json.loads((Path(__file__).parent / "cases.json").read_text(encoding="utf-8"))
ORDER = ["Low signals", "Suspicious", "High risk", "Critical"]

rows = []
for c in cases:
    r = fuse(scan(c["text"]))
    rows.append((c["label"], r["level"], r["risk"], c["text"]))

scams = [r for r in rows if r[0] == "scam"]
genuine = [r for r in rows if r[0] == "genuine"]

for cut in ("Suspicious", "High risk"):
    flag = lambda lv: ORDER.index(lv) >= ORDER.index(cut)
    caught = sum(1 for r in scams if flag(r[1]))
    alarms = sum(1 for r in genuine if flag(r[1]))
    print(f"Flag at {cut} or above: caught {caught}/{len(scams)} scams, "
          f"{alarms}/{len(genuine)} false alarms")

print("\nMissed scams (below High risk):")
for r in scams:
    if ORDER.index(r[1]) < ORDER.index("High risk"):
        print(f"  {r[1]:12} {r[2]:<6} {r[3][:70]}")

print("\nGenuine messages flagged Suspicious or above:")
for r in genuine:
    if ORDER.index(r[1]) >= ORDER.index("Suspicious"):
        print(f"  {r[1]:12} {r[2]:<6} {r[3][:70]}")