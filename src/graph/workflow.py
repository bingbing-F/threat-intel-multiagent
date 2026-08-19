"""Workflow orchestration for the multi-agent threat intelligence pipeline.

``ThreatIntelWorkflow`` describes the pipeline as a graph of agent nodes
(LangGraph StateGraph when available, with a linear fallback). The orchestration
itself — Collect -> Analyze -> Validate -> Correlate -> Report, with conditional
edges — is a first-class artifact, not a hand-rolled for-loop.
"""
from dataclasses import dataclass, field
from typing import List, Optional, TypedDict

try:
    from langgraph.graph import END, START, StateGraph

    HAS_LANGGRAPH = True
except ImportError:  # pragma: no cover - dependency guards the linear fallback
    HAS_LANGGRAPH = False

from src.agents.analyzer import AnalyzerAgent
from src.agents.collector import CollectorAgent
from src.agents.correlator import CorrelatorAgent
from src.agents.reporter import ReporterAgent
from src.agents.reviewer import CoordinatorAgent, ReviewerAgent
from src.agents.validator import ValidatorAgent
from src.models.intelligence import ThreatIntelligence
from src.models.source import RawContent
from src.sources.factory import build_sources
from src.storage.db import Database
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class WorkflowResult:
    """Result of a workflow run."""

    raw_count: int = 0
    analyzed_count: int = 0
    valid_count: int = 0
    invalid_count: int = 0
    errors: List[str] = field(default_factory=list)
    valid_items: List[ThreatIntelligence] = field(default_factory=list)
    # Adversarial review metrics.
    review_flagged: int = 0
    review_resolved_fixes: int = 0
    review_residual: int = 0
    reviews_persisted: int = 0
    # Cross-source correlation metrics.
    event_count: int = 0
    corroborated_events: int = 0


class _WorkflowState(TypedDict):
    result: WorkflowResult
    raw_items: List[RawContent]
    analyzed_items: List[ThreatIntelligence]
    send_alerts: bool
    generate_report: bool
    limit: Optional[int]


class ThreatIntelWorkflow:
    """Multi-agent pipeline orchestrated as a graph."""

    def __init__(
        self,
        db: Optional[Database] = None,
        collector: Optional[CollectorAgent] = None,
        analyzer: Optional[AnalyzerAgent] = None,
        validator: Optional[ValidatorAgent] = None,
        reporter: Optional[ReporterAgent] = None,
        demo: bool = False,
    ):
        self.demo = demo
        self.db = db or Database()
        if demo:
            from src.llm.demo_client import DemoLLM
            from src.sources.demo_source import DemoSource

            self.collector = collector or CollectorAgent(sources=[DemoSource()], db=self.db)
            self.analyzer = analyzer or AnalyzerAgent(llm_client=DemoLLM(), db=self.db)
            # Demo content is Chinese; do not apply the English keyword pre-filter
            # which is tuned for English OSINT sources. Semantic/IoC/confidence
            # validation still run, so valid vs. invalid is meaningful.
            self.validator = validator or ValidatorAgent(required_keywords=[], db=self.db)
        else:
            self.collector = collector or CollectorAgent(sources=build_sources(), db=self.db)
            self.analyzer = analyzer or AnalyzerAgent(db=self.db)
            self.validator = validator or ValidatorAgent(db=self.db)
        self.reporter = reporter or ReporterAgent(db=self.db)
        self.correlator = CorrelatorAgent()
        # Adversarial collaboration pair: independent reviewer + fix coordinator.
        reviewer = ReviewerAgent(llm_client=None if demo else self.analyzer.llm)
        self.coordinator = CoordinatorAgent(reviewer=reviewer)
        self._graph = None

    @property
    def graph(self):
        if self._graph is None:
            self._graph = self._build_graph()
        return self._graph

    # ------------------------------------------------------------------ #
    # LangGraph orchestration
    # ------------------------------------------------------------------ #
    def _build_graph(self):
        graph = StateGraph(_WorkflowState)
        graph.add_node("collect", self._node_collect)
        graph.add_node("analyze", self._node_analyze)
        graph.add_node("validate", self._node_validate)
        graph.add_node("correlate", self._node_correlate)
        graph.add_node("report", self._node_report)
        graph.add_edge(START, "collect")
        graph.add_edge("collect", "analyze")
        graph.add_edge("analyze", "validate")
        graph.add_edge("validate", "correlate")
        graph.add_conditional_edges(
            "correlate",
            self._route_after_correlate,
            {"report": "report", "end": END},
        )
        graph.add_edge("report", END)
        return graph.compile()

    @staticmethod
    def _route_after_correlate(state: _WorkflowState) -> str:
        return "report" if state["generate_report"] else "end"

    def _node_collect(self, state: _WorkflowState) -> dict:
        result = state["result"]
        logger.info("=== Graph Node: Collect ===")
        raw_items = self.collector.collect(persist=True)
        limit = state.get("limit")
        if limit is not None:
            raw_items = raw_items[:limit]
        result.raw_count = len(raw_items)
        logger.info(f"Collected {result.raw_count} raw items")
        state["raw_items"] = raw_items
        return {"result": result, "raw_items": raw_items}

    def _node_analyze(self, state: _WorkflowState) -> dict:
        result = state["result"]
        logger.info("=== Graph Node: Analyze (with adversarial review) ===")
        analyzed_items: List[ThreatIntelligence] = []
        for raw in state["raw_items"]:
            try:
                intel = self.analyzer.analyze(raw, persist=True)
                if intel:
                    # Reviewer critiques, Coordinator applies fixable feedback; the
                    # item is re-reviewed, and the review record is persisted.
                    intel = self.coordinator.collaborate(
                        intel, raw.content, version=self.analyzer._version
                    )
                    self._persist_review(intel, result)
                    analyzed_items.append(intel)
            except Exception as e:
                msg = f"Analysis failed for {raw.id}: {e}"
                logger.error(msg)
                result.errors.append(msg)
        result.analyzed_count = len(analyzed_items)
        logger.info(f"Analyzed {result.analyzed_count} items")
        state["analyzed_items"] = analyzed_items
        return {"result": result, "analyzed_items": analyzed_items}

    def _node_validate(self, state: _WorkflowState) -> dict:
        result = state["result"]
        logger.info("=== Graph Node: Validate ===")
        for intel in state["analyzed_items"]:
            try:
                validated = self.validator.validate(intel, persist=True)
                if validated.is_valid:
                    result.valid_items.append(validated)
                    result.valid_count += 1
                    if state["send_alerts"]:
                        self.reporter.send_alert(validated)
                else:
                    result.invalid_count += 1
            except Exception as e:
                msg = f"Validation failed for {intel.id}: {e}"
                logger.error(msg)
                result.errors.append(msg)
        logger.info(
            f"Validation complete: {result.valid_count} valid, "
            f"{result.invalid_count} invalid"
        )
        return {"result": result}

    def _node_correlate(self, state: _WorkflowState) -> dict:
        result = state["result"]
        logger.info("=== Graph Node: Correlate (cross-source) ===")
        try:
            events = self.correlator.correlate(state["analyzed_items"])
            for event in events:
                self.db.save_event(event)
                if event.corroborated:
                    result.corroborated_events += 1
            result.event_count = len(events)
            logger.info(
                f"Correlated {result.event_count} events "
                f"({result.corroborated_events} corroborated)"
            )
        except Exception as e:
            msg = f"Correlation failed: {e}"
            logger.error(msg)
            result.errors.append(msg)
        return {"result": result}

    def _node_report(self, state: _WorkflowState) -> dict:
        result = state["result"]
        logger.info("=== Graph Node: Report ===")
        try:
            report = self.reporter.generate_daily_report(result.valid_items)
            logger.info(f"Generated report ({len(report)} chars)")
            if state["send_alerts"]:
                self.reporter.send_daily_report(result.valid_items)
        except Exception as e:
            msg = f"Report generation failed: {e}"
            logger.error(msg)
            result.errors.append(msg)
        return {"result": result}

    # ------------------------------------------------------------------ #
    # Public entrypoint
    # ------------------------------------------------------------------ #
    def run(
        self,
        send_alerts: bool = False,
        generate_report: bool = False,
        limit: Optional[int] = None,
    ) -> WorkflowResult:
        """Run the full pipeline once.

        ``limit`` caps the number of raw items analyzed (useful to control real
        LLM cost during demos). Executed through the LangGraph state machine when
        available; otherwise falls back to a linear traversal of the same nodes.
        """
        state: _WorkflowState = {
            "result": WorkflowResult(),
            "raw_items": [],
            "analyzed_items": [],
            "send_alerts": send_alerts,
            "generate_report": generate_report,
            "limit": limit,
        }

        try:
            if HAS_LANGGRAPH:
                final_state = self.graph.invoke(state)
                return final_state["result"]
            self._node_collect(state)
            self._node_analyze(state)
            self._node_validate(state)
            self._node_correlate(state)
            if state["generate_report"]:
                self._node_report(state)
            return state["result"]
        except Exception as e:
            msg = f"Workflow failed: {e}"
            logger.error(msg)
            state["result"].errors.append(msg)
            return state["result"]

    def _persist_review(self, intel: ThreatIntelligence, result: WorkflowResult) -> None:
        """Persist a review record and update adversarial review metrics."""
        flagged = intel.review_rounds >= 2
        if flagged:
            result.review_flagged += 1
            if not intel.review_approved:
                result.review_residual += 1
        result.review_resolved_fixes += intel.review_fixes_applied

        from src.models.review import ReviewRecord

        record = ReviewRecord(
            intelligence_id=intel.id,
            version=intel.review_version,
            reviewer_mode=intel.review_mode,
            approved=bool(intel.review_approved),
            issue_codes=list(intel.review_issue_codes),
            rounds=intel.review_rounds,
            confidence_before=round(intel.confidence - intel.confidence_delta, 4),
            confidence_after=float(intel.confidence),
        )
        try:
            self.db.save_review(record)
            result.reviews_persisted += 1
        except Exception as e:  # noqa: BLE001 - review persistence must never break the run
            logger.error(f"Failed to persist review for {intel.id}: {e}")