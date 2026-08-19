"""Run A/B evaluation across prompt versions."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluation.ab_tester import ABTester
from src.evaluation.regression import run_regression
from src.evaluation.runtime import save_active_version

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    mock_mode = "--mock" in sys.argv
    deploy = "--deploy" in sys.argv
    benchmark_path = args[0] if args else "data/benchmark_dataset.json"
    tester = ABTester(mock_mode=mock_mode)
    result = tester.evaluate(benchmark_path)

    print("\n=== A/B Evaluation Result ===")
    print(f"Benchmark: {result.benchmark_path}")
    print(f"Winner: {result.winner}")
    print(f"Notes: {result.notes}")
    print("\nMetrics by version:")
    for version, metrics in result.results.items():
        print(
            f"  {version}: accuracy={metrics.accuracy:.2f}, "
            f"recall={metrics.recall:.2f}, f1={metrics.f1:.2f}, "
            f"avg_confidence={metrics.avg_confidence:.2f}"
        )

    # Save result
    output_path = Path("data/ab_eval_result.json")
    output_path.write_text(
        json.dumps(
            {
                "winner": result.winner,
                "notes": result.notes,
                "results": {
                    v: m.model_dump() for v, m in result.results.items()
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nResult saved to {output_path}")

    if deploy and result.winner:
        save_active_version(result.winner)
        print(f"Deployed active prompt version: {result.winner}")
        report = run_regression(version=result.winner, benchmark_path=benchmark_path,
                                mock_mode=mock_mode)
        print(f"Regression guard ({result.winner}): {'PASS' if report.passed else 'FAIL'}")
        print(f"  {report.summary}")
