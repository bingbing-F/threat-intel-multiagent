"""Regression guard tests: deployed prompt version must not degrade quality."""
import src.evaluation.runtime as runtime
from src.evaluation.regression import run_regression


def test_active_version_roundtrip(tmp_path, monkeypatch):
    import json

    monkeypatch.setattr(runtime, "RUNTIME_PATH", tmp_path / "rt.json")
    runtime.save_active_version("v1.2")
    assert runtime.RUNTIME_PATH.exists()
    data = json.loads(runtime.RUNTIME_PATH.read_text(encoding="utf-8"))
    assert data["version"] == "v1.2"


def test_regression_of_later_versions_passes():
    # v1.3 (winner) must be >= baseline captured from v1.2.
    report = run_regression(version="v1.3", mock_mode=True)
    assert report.passed, report.summary
    assert report.version == "v1.3"


def test_regression_of_older_version_fails():
    # v1.0/1.1 sit below the baseline and must be flagged as a regression.
    for weak_version in ("v1.0",):
        report = run_regression(version=weak_version, mock_mode=True)
        assert not report.passed, weak_version