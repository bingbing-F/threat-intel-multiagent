"""Tests for A/B prompt evaluation."""
from pathlib import Path

from src.evaluation.ab_tester import ABTester
from src.evaluation.prompt_registry import PromptRegistry


def test_ab_tester_mock_mode(tmp_path):
    registry = PromptRegistry()
    assert registry.list_versions(), "No prompt versions found"

    benchmark = [
        {
            "raw_text": "Test leak with IP 192.0.2.1 and domain example.com.",
            "expected": {
                "title": "Test leak",
                "threat_type": "数据泄露",
                "iocs": ["192.0.2.1", "example.com"],
                "involved_assets": ["卫星"],
                "satellite_model": "",
                "summary": "Test",
                "min_confidence": 0.9,
            },
        }
    ]
    benchmark_path = tmp_path / "benchmark.json"
    benchmark_path.write_text(__import__("json").dumps(benchmark), encoding="utf-8")

    tester = ABTester(prompt_registry=registry, mock_mode=True)
    result = tester.evaluate(str(benchmark_path))

    assert result.winner in registry.list_versions()
    assert len(result.results) == len(registry.list_versions())
    for version, metrics in result.results.items():
        assert 0.0 <= metrics.accuracy <= 1.0
        assert 0.0 <= metrics.recall <= 1.0
        assert 0.0 <= metrics.f1 <= 1.0
        assert metrics.samples_count == len(benchmark)


def test_ab_tester_improves_with_later_versions(tmp_path):
    registry = PromptRegistry()
    versions = registry.list_versions()
    if len(versions) < 2:
        return

    benchmark_path = Path("data/benchmark_dataset.json")
    if not benchmark_path.exists():
        return

    tester = ABTester(prompt_registry=registry, mock_mode=True)
    result = tester.evaluate(str(benchmark_path))

    f1_values = [result.results[v].f1 for v in versions]
    # Later versions should generally perform better in mock mode.
    assert f1_values[-1] >= f1_values[0]
