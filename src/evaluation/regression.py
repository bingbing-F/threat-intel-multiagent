"""Regression guard: the production prompt version must not regress quality.

Freezing a baseline (from the last accepted version) and asserting the deployed
version keeps accuracy / recall / F1 / confidence at or above it prevents silent
quality drops - a core "AI 测试" practice.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from src.evaluation.ab_tester import ABTester
from src.evaluation.prompt_registry import PromptRegistry
from src.evaluation.runtime import load_active_version

# Baseline equals the metrics of the previously accepted version (v1.2),
# captured from the mock A/B run on the shared benchmark.
DEFAULT_BASELINE: Dict[str, float] = {
    "accuracy": 0.8,
    "recall": 0.6,
    "f1": 0.69,
    "avg_confidence": 0.63,
}


@dataclass
class RegressionReport:
    version: str
    metrics: Dict[str, float]
    baseline: Dict[str, float]
    passed: bool
    summary: str


def run_regression(
    version: str = "",
    benchmark_path: str = "data/benchmark_dataset.json",
    baseline: Dict[str, float] | None = None,
    mock_mode: bool = True,
) -> RegressionReport:
    """Evaluate the given (or deployed) version and compare against the baseline."""
    registry = PromptRegistry()
    version = version or load_active_version() or registry.latest().version
    tester = ABTester(mock_mode=mock_mode)
    result = tester.evaluate(benchmark_path)
    metrics = result.results[version]
    baseline = baseline or DEFAULT_BASELINE

    checks = {
        "accuracy": metrics.accuracy >= baseline["accuracy"],
        "recall": metrics.recall >= baseline["recall"],
        "f1": metrics.f1 >= baseline["f1"],
        "avg_confidence": metrics.avg_confidence >= baseline["avg_confidence"],
    }
    passed = all(checks.values())
    summary = ", ".join(
        f"{key}={metrics.__getattribute__(key):.2f} >= {baseline[key]:.2f} ({'ok' if ok else 'FAIL'})"
        for key, ok in checks.items()
    )
    return RegressionReport(
        version=version,
        metrics={key: metrics.__getattribute__(key) for key in baseline},
        baseline=baseline,
        passed=passed,
        summary=summary,
    )