"""Regression tests for the external SMS evaluation harness."""
from pathlib import Path

from tools.evaluate_uci_sms import evaluate


def test_external_sms_evaluator_reports_complete_confusion_matrix(tmp_path: Path):
    corpus = tmp_path / "SMSSpamCollection"
    corpus.write_text(
        "spam\tWIN a cash prize now! Call 09000000000\n"
        "ham\tAre we still meeting for lunch today?\n"
        "invalid\tThis row has an unsupported label\n"
        "ham\t\n",
        encoding="utf-8",
    )

    result = evaluate(corpus)

    assert result["dataset"] == "UCI SMS Spam Collection"
    assert result["cases_evaluated"] == 2
    assert result["skipped_rows"] == 2
    assert result["spam"] == 1
    assert result["ham"] == 1
    assert result["tp"] + result["fn"] == result["spam"]
    assert result["fp"] + result["tn"] == result["ham"]
    assert 0.0 <= result["precision"] <= 1.0
    assert 0.0 <= result["recall"] <= 1.0
    assert 0.0 <= result["false_positive_rate"] <= 1.0
    assert 0.0 <= result["f1"] <= 1.0


def test_external_sms_evaluator_rejects_unknown_cutoff(tmp_path: Path):
    corpus = tmp_path / "SMSSpamCollection"
    corpus.write_text("ham\tHello there\n", encoding="utf-8")

    import pytest

    with pytest.raises(ValueError, match="Unknown cutoff"):
        evaluate(corpus, cutoff="Definitely Safe")
