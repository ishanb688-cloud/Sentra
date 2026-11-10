"""Guards the measured quality so a future change cannot quietly make Sentra worse."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


def _run(holdout):
    import importlib
    argv = sys.argv[:]
    sys.argv = ["benchmark"] + (["--holdout"] if holdout else [])
    try:
        import benchmark
        importlib.reload(benchmark)
        return benchmark.run()["cutoffs"]["Suspicious"]
    finally:
        sys.argv = argv


def test_development_benchmark_has_no_false_alarms_and_high_recall():
    m = _run(False)
    assert m["fp"] == 0 and m["recall"] == 1.0 and m["precision"] == 1.0


def test_holdout_floor_so_regressions_are_noticed():
    import importlib
    import benchmark
    argv = sys.argv[:]
    sys.argv = ["benchmark", "--holdout"]
    try:
        importlib.reload(benchmark)
        result = benchmark.run()
    finally:
        sys.argv = argv
    m = result["cutoffs"]["Suspicious"]
    false_alarms = [
        (case["id"], case["input"], verdict[0], verdict[1], verdict[2], verdict[3])
        for case, verdict in result["rows"]
        if case["label"] == "genuine" and benchmark.ORDER.index(verdict[0]) >= benchmark.ORDER.index("Suspicious")
    ]
    assert (
        m["fpr"] == 0.0 and m["recall"] == 1.0 and m["precision"] == 1.0
    ), f"holdout metrics={m}; genuine false alarms={false_alarms}"
