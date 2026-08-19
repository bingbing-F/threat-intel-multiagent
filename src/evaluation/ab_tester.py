"""A/B evaluation for prompt versions using a labeled benchmark dataset."""
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from src.agents.analyzer import AnalyzerAgent
from src.evaluation.prompt_registry import PromptRegistry
from src.llm.client import LLMClient
from src.models.evaluation import EvaluationMetrics, EvaluationResult
from src.models.intelligence import ThreatIntelligence
from src.models.source import RawContent
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ABTester:
    """Evaluate multiple prompt versions against a labeled benchmark."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        prompt_registry: Optional[PromptRegistry] = None,
        mock_mode: bool = False,
    ):
        self.mock_mode = mock_mode
        # Avoid initializing LLM client in mock mode so demos/tests work without API keys.
        self.llm = llm_client if llm_client is not None else (None if mock_mode else LLMClient())
        self.registry = prompt_registry or PromptRegistry()

    def evaluate(self, benchmark_path: str) -> EvaluationResult:
        """Run A/B evaluation across all registered prompt versions."""
        benchmark = self._load_benchmark(benchmark_path)
        versions = self.registry.list_versions()
        if not versions:
            raise ValueError("No prompt versions registered")

        results: Dict[str, EvaluationMetrics] = {}
        for version in versions:
            metrics = self._evaluate_version(version, benchmark)
            results[version] = metrics
            logger.info(
                f"Version {version}: accuracy={metrics.accuracy:.2f}, "
                f"recall={metrics.recall:.2f}, f1={metrics.f1:.2f}"
            )

        winner = self._pick_winner(results)
        notes = (
            f"Evaluated {len(versions)} prompt versions on {len(benchmark)} samples. "
            f"Best overall F1: {winner}"
        )

        return EvaluationResult(
            benchmark_path=benchmark_path,
            results=results,
            winner=winner,
            notes=notes,
        )

    def _load_benchmark(self, benchmark_path: str) -> List[Dict[str, Any]]:
        path = Path(benchmark_path)
        if not path.exists():
            raise FileNotFoundError(f"Benchmark dataset not found: {path}")
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Benchmark dataset must be a JSON list")
        return data

    def _evaluate_version(
        self, version: str, benchmark: List[Dict[str, Any]]
    ) -> EvaluationMetrics:
        accuracies: List[float] = []
        recalls: List[float] = []
        confidences: List[float] = []

        for sample in benchmark:
            raw = RawContent(
                source_name="benchmark",
                content=sample["raw_text"],
                content_hash="",
            )
            expected = sample.get("expected", {})

            if self.mock_mode:
                intel = self._mock_analyze(version, raw, expected)
            else:
                analyzer = AnalyzerAgent(
                    llm_client=self.llm,
                    prompt_registry=self.registry,
                    prompt_version=version,
                    db=None,
                )
                intel = analyzer.analyze(raw, persist=False)

            if intel is None:
                accuracies.append(0.0)
                recalls.append(0.0)
                continue

            confidences.append(intel.confidence)
            accuracies.append(self._sample_accuracy(intel, expected))
            recalls.append(self._sample_recall(intel, expected))

        avg_accuracy = sum(accuracies) / len(accuracies) if accuracies else 0.0
        avg_recall = sum(recalls) / len(recalls) if recalls else 0.0
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        f1 = self._f1(avg_accuracy, avg_recall)

        return EvaluationMetrics(
            accuracy=round(avg_accuracy, 4),
            recall=round(avg_recall, 4),
            f1=round(f1, 4),
            avg_confidence=round(avg_confidence, 4),
            samples_count=len(benchmark),
        )

    def _sample_accuracy(self, intel: ThreatIntelligence, expected: Dict[str, Any]) -> float:
        """1.0 if threat type matches and at least half of expected IOCs are found."""
        expected_type = expected.get("threat_type", "")
        if expected_type and intel.threat_type != expected_type:
            return 0.0

        expected_iocs: Set[str] = set(expected.get("iocs", []))
        if not expected_iocs:
            return 1.0 if intel.confidence >= expected.get("min_confidence", 0.0) else 0.0

        found = expected_iocs & set(intel.iocs)
        return 1.0 if len(found) / len(expected_iocs) >= 0.5 else 0.0

    def _sample_recall(self, intel: ThreatIntelligence, expected: Dict[str, Any]) -> float:
        """IOC recall for this sample."""
        expected_type = expected.get("threat_type", "")
        if expected_type and intel.threat_type != expected_type:
            return 0.0

        expected_iocs: Set[str] = set(expected.get("iocs", []))
        if not expected_iocs:
            return 1.0

        found = expected_iocs & set(intel.iocs)
        return len(found) / len(expected_iocs)

    def _f1(self, precision: float, recall: float) -> float:
        if precision + recall == 0:
            return 0.0
        return 2 * precision * recall / (precision + recall)

    def _pick_winner(self, results: Dict[str, EvaluationMetrics]) -> Optional[str]:
        if not results:
            return None
        return max(results.items(), key=lambda item: item[1].f1)[0]

    @staticmethod
    def _stable(text: str) -> float:
        """Deterministic pseudo-random value in [0, 1) for a string.

        Python's built-in ``hash()`` is salted per process, so it is replaced
        with a SHA-256 based value that is stable across runs.
        """
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return int(digest[:8], 16) / 0xFFFFFFFF

    def _mock_analyze(
        self, version: str, raw: RawContent, expected: Dict[str, Any]
    ) -> ThreatIntelligence:
        """Deterministic mock analyzer for demos and tests without API keys.

        Later prompt versions are simulated to extract more accurate threat types
        and recall more expected IOCs. A stable per-sample/per-IOC threshold is
        compared against the version score, so accuracy and recall are guaranteed
        to be non-decreasing as the version improves (v1.0 -> v1.3).
        """
        version_score = {
            "v1.0": 0.55,
            "v1.1": 0.70,
            "v1.2": 0.85,
            "v1.3": 0.95,
        }.get(version, 0.7)
        expected_iocs = expected.get("iocs", [])
        expected_assets = expected.get("involved_assets", [])
        expected_type = expected.get("threat_type", "数据泄露")

        # Simulate confidence calibration: irrelevant content gets low confidence.
        is_irrelevant = (
            "电影" in raw.content or "小说" in raw.content or "科普" in raw.content
        )
        if is_irrelevant:
            return ThreatIntelligence(
                title=expected.get("title", "非威胁内容"),
                threat_type="其他",
                iocs=[],
                involved_assets=[],
                satellite_model="",
                confidence=0.25,
                summary=expected.get("summary", ""),
                source="benchmark",
                raw_text=raw.content,
                is_valid=False,
            )

        # Stable per-sample difficulty: a sample is classified correctly once the
        # version score reaches its threshold, guaranteeing monotonic improvement.
        type_correct = version_score >= self._stable(raw.content)
        predicted_type = expected_type if type_correct else "其他"

        # Stable per-IOC difficulty: recall non-decreasing across versions.
        found_iocs = [
            ioc for ioc in expected_iocs if version_score >= self._stable(ioc)
        ]

        base_confidence = min(0.98, version_score + 0.03)
        return ThreatIntelligence(
            title=expected.get("title", "Mock extraction"),
            threat_type=predicted_type,
            iocs=found_iocs,
            involved_assets=expected_assets if type_correct else [],
            satellite_model=expected.get("satellite_model", "") if type_correct else "",
            confidence=round(base_confidence, 2),
            summary=expected.get("summary", ""),
            source="benchmark",
            raw_text=raw.content,
            is_valid=base_confidence >= 0.9,
        )
