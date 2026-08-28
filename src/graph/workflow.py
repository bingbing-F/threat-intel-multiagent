"""多智能体威胁情报处理流水线的工作流编排。

`ThreatIntelWorkflow` 将整个处理流程定义为一张图结构的 Agent 节点编排：
在可用 LangGraph 时使用 `StateGraph`，否则退化为线性执行。
编排本身涵盖了收集 -> 监测 -> 分析 -> 验证 -> 关联 -> 报告的完整链路，
并通过条件边决定是否进入汇报节点，这是一等公民的工作流结构，
而不是手写的简单 for 循环。
"""
from dataclasses import dataclass, field
from typing import List, Optional, TypedDict

try:
    # 优先引入 LangGraph 提供的状态图能力，以支持图结构编排和条件边
    from langgraph.graph import END, START, StateGraph

    HAS_LANGGRAPH = True
except ImportError:  # pragma: no cover - 依赖缺失时回退到线性执行
    HAS_LANGGRAPH = False

from src.agents.analyzer import AnalyzerAgent
from src.agents.collector import CollectorAgent
from src.agents.correlator import CorrelatorAgent
from src.agents.monitor import DomainMonitorAgent
from src.agents.reporter import ReporterAgent
from src.agents.reviewer import CoordinatorAgent, ReviewerAgent
from src.agents.validator import ValidatorAgent
from src.memory.store import MemoryStore
from src.models.intelligence import ThreatIntelligence
from src.models.source import RawContent
from src.sources.factory import build_sources
from src.storage.db import Database
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class WorkflowResult:
    """一次工作流执行的结果汇总。"""

    raw_count: int = 0
    analyzed_count: int = 0
    valid_count: int = 0
    invalid_count: int = 0
    errors: List[str] = field(default_factory=list)
    valid_items: List[ThreatIntelligence] = field(default_factory=list)
    # 对抗性审查相关指标：用于统计评审是否触发、修正是否生效以及是否残留问题。
    review_flagged: int = 0
    review_resolved_fixes: int = 0
    review_residual: int = 0
    reviews_persisted: int = 0
    # 跨来源关联指标：统计事件总量和互证强度。
    event_count: int = 0
    corroborated_events: int = 0
    # 多域监控相关指标：观察多个监控域名与命中情况。
    monitor_domains: int = 0
    monitor_matched_items: int = 0
    monitor_dark_sources: int = 0


class _WorkflowState(TypedDict):
    """LangGraph 状态定义，保存当前节点间共享的数据和控制参数。"""

    result: WorkflowResult
    raw_items: List[RawContent]
    analyzed_items: List[ThreatIntelligence]
    send_alerts: bool
    generate_report: bool
    limit: Optional[int]


class ThreatIntelWorkflow:
    """以图结构编排的多智能体威胁情报处理流水线。"""

    def __init__(
        self,
        db: Optional[Database] = None,
        collector: Optional[CollectorAgent] = None,
        analyzer: Optional[AnalyzerAgent] = None,
        validator: Optional[ValidatorAgent] = None,
        reporter: Optional[ReporterAgent] = None,
        demo: bool = False,
    ):
        # 工作流实例持有统一数据库连接与各个智能体组件
        self.demo = demo
        self.db = db or Database()
        if demo:
            from src.llm.demo_client import DemoLLM
            from src.sources.demo_source import DemoSource

            self.collector = collector or CollectorAgent(sources=[DemoSource()], db=self.db)
            self.analyzer = analyzer or AnalyzerAgent(llm_client=DemoLLM(), db=self.db)
            # 演示数据为中文内容，因此不使用英文 OSINT 语料中专门 tuned 的关键词预过滤。
            # 但语义、IoC 和置信度校验仍在执行，因此有效/无效判断仍然是有意义的。
            self.validator = validator or ValidatorAgent(required_keywords=[], db=self.db)
        else:
            self.collector = collector or CollectorAgent(sources=build_sources(), db=self.db)
            # 非演示模式启用代理式分析：模型可调用本地记忆工具做 IOC 核对，
            # 把「单次抽取」升级为带工具/记忆的多步 Agent。
            self.analyzer = analyzer or AnalyzerAgent(
                db=self.db, agentic=True, memory=MemoryStore(self.db)
            )
            self.validator = validator or ValidatorAgent(db=self.db)
        self.reporter = reporter or ReporterAgent(db=self.db)
        self.correlator = CorrelatorAgent()
        self.monitor = DomainMonitorAgent(db=self.db)
        # 对抗式协作对：独立评审者 + 修正协调者，负责审查和迭代改进输出。
        reviewer = ReviewerAgent(llm_client=None if demo else self.analyzer.llm)
        self.coordinator = CoordinatorAgent(reviewer=reviewer)
        self._graph = None

    @property
    def graph(self):
        """懒加载并缓存图对象，避免重复构建状态图。"""
        if self._graph is None:
            self._graph = self._build_graph()
        return self._graph

    # ------------------------------------------------------------------ #
    # LangGraph 编排：定义节点、边以及条件分支
    # ------------------------------------------------------------------ #
    def _build_graph(self):
        """构建状态图，串联采集、监控、分析、验证、关联、汇报等节点。"""
        graph = StateGraph(_WorkflowState)
        graph.add_node("collect", self._node_collect)
        graph.add_node("monitor", self._node_monitor)
        graph.add_node("analyze", self._node_analyze)
        graph.add_node("validate", self._node_validate)
        graph.add_node("correlate", self._node_correlate)
        graph.add_node("report", self._node_report)

        # 入口和主链路顺序：收集 -> 监控 -> 分析 -> 验证 -> 关联
        graph.add_edge(START, "collect")
        graph.add_edge("collect", "monitor")
        graph.add_edge("monitor", "analyze")
        graph.add_edge("analyze", "validate")
        graph.add_edge("validate", "correlate")

        # 关联后根据是否需要生成报告决定接下来进入报告节点还是结束
        graph.add_conditional_edges(
            "correlate",
            self._route_after_correlate,
            {"report": "report", "end": END},
        )
        graph.add_edge("report", END)
        return graph.compile()

    @staticmethod
    def _route_after_correlate(state: _WorkflowState) -> str:
        """依据状态中 generate_report 标志决定后续分支。"""
        return "report" if state["generate_report"] else "end"

    def _node_collect(self, state: _WorkflowState) -> dict:
        """采集原始情报源内容，并将结果写入状态。"""
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

    def _node_monitor(self, state: _WorkflowState) -> dict:
        """对采集到的内容执行多域名/多来源监控检查。"""
        result = state["result"]
        logger.info("=== Graph Node: Monitor (multi-domain) ===")
        try:
            metrics = self.monitor.scan(state["raw_items"])
            result.monitor_domains = len(metrics)
            result.monitor_matched_items = sum(m.matched_items for m in metrics)
            result.monitor_dark_sources = sum(m.dark_sources for m in metrics)
            logger.info(
                f"Monitoring: {result.monitor_domains} domains matched, "
                f"{result.monitor_matched_items} items, "
                f"{result.monitor_dark_sources} dark-source items"
            )
        except Exception as e:
            msg = f"Monitoring scan failed: {e}"
            logger.error(msg)
            result.errors.append(msg)
        return {"result": result}

    def _node_analyze(self, state: _WorkflowState) -> dict:
        """分析原始内容，生成威胁情报对象，并进行对抗式评审修正。"""
        result = state["result"]
        logger.info("=== Graph Node: Analyze (with adversarial review) ===")
        analyzed_items: List[ThreatIntelligence] = []
        for raw in state["raw_items"]:
            try:
                intel = self.analyzer.analyze(raw, persist=True)
                if intel:
                    # 评审者给出修改建议，协调器负责将可修正问题落实到情报对象中。
                    # 修正后会再次进行评审，并保存评审记录，确保输出链路具备“审查-修正-再审查”的闭环。
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
        """校验分析结果中的可靠性、IOC、语义完整性与置信度。"""
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
        """跨来源聚合和相关事件关联，识别共性威胁模式。"""
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
        """生成日报或汇总报告，并在需要时发送环境告警。"""
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
    # 对外入口：启动一次完整流程
    # ------------------------------------------------------------------ #
    def run(
        self,
        send_alerts: bool = False,
        generate_report: bool = False,
        limit: Optional[int] = None,
    ) -> WorkflowResult:
        """执行一次完整的威胁情报处理链路。

        `limit` 用于限制参与处理的原始数据条数，可在演示场景中控制 LLM 成本。
        若 LangGraph 可用，则通过状态图执行；否则退回到线性节点遍历实现，
        但语义和步骤保持一致，保证不同环境下行为一致。
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
                # 在支持的环境中使用图执行器来驱动工作流状态迁移
                final_state = self.graph.invoke(state)
                return final_state["result"]

            # 退化场景：按固定顺序手动执行各个节点，保持同样的逻辑设计
            self._node_collect(state)
            self._node_monitor(state)
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
        """保存审查记录，并更新对抗式审查相关指标。"""
        flagged = intel.review_rounds >= 2
        if flagged:
            result.review_flagged += 1
            if not intel.review_approved:
                result.review_residual += 1
        result.review_resolved_fixes += intel.review_fixes_applied

        from src.models.review import ReviewRecord

        # 评审记录会保存在数据库中，便于后续复盘审计和版本追踪
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
        except Exception as e:  # noqa: BLE001 - 审查记录持久化失败不能中断主流程执行
            logger.error(f"Failed to persist review for {intel.id}: {e}")