"""分析代理：使用 LLM 从原始文本中抽取结构化威胁情报。

此 Agent 负责：
- 使用 `PromptRegistry` 生成针对具体 prompt 版本的提示并调用 LLM。
- 使用 `StructuredParser` 将模型响应解析为 `ExtractedIntelligence`。
- 作为后备策略，对原始文本进行正则 IOC 提取并与 LLM 输出合并，
  以提升对常见 IoC（如 IP、域名、哈希）的覆盖率。
- 将解析结果封装为 `ThreatIntelligence` 并在需要时持久化。
"""
from typing import List, Optional
import json
from uuid import uuid4

from src.llm.client import LLMClient
from src.llm.parser import StructuredParser
from src.models.intelligence import ExtractedIntelligence, ThreatIntelligence
from src.models.source import RawContent
from src.evaluation.prompt_registry import PromptRegistry
from src.evaluation.runtime import load_active_version
from src.memory.store import MemoryStore
from src.storage.db import Database
from src.utils.ioc_extractor import IOCExtractor
from src.utils.logger import get_logger

logger = get_logger(__name__)

# 解析失败重试时追加的严格约束：要求模型只输出合法 JSON 对象，避免散文/代码块包裹。
_STRICT_SUFFIX = (
    "\n\n[STRICT] 仅输出一个合法 JSON 对象，不要任何额外说明、不要 markdown 代码块、"
    "不要截断。字段必须完全符合给定 schema。"
)

# 代理式抽取的系统提示：允许模型通过工具核对 IOC 是否在历史中出现过（记忆检索）。
AGENTIC_SYSTEM = (
    "你是一名威胁情报抽取器。当抽取的字段包含 IOC（IP/域名/CVE/哈希）时，"
    "应先调用 cross_check_ioc 工具核对它是否曾在历史情报中出现，再输出最终 JSON。"
)


class AnalyzerAgent:
    """对原始内容执行语义抽取并生成结构化威胁情报的 Agent。

    设计注意点：
    - LLM 响应可能不完整或包含格式偏差，依赖 `StructuredParser` 进行
      严格解析并根据需要降级处理。
    - 对关键字段（如 IoC）进行规则化后合并，以提高下游关联与告警的
      鲁棒性。
    - 支持按需持久化（`persist`），便于在单元测试或演示中禁用写入。
    - 启用 `agentic=True` 时，模型可调用 `cross_check_ioc` 本地工具检索记忆，
      从「单次抽取」升级为「可调用工具、具备记忆的多步 Agent」，且对不支持
      工具调用的模型自动降级为单次抽取。
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        prompt_registry: Optional[PromptRegistry] = None,
        db: Optional[Database] = None,
        prompt_version: Optional[str] = None,
        agentic: bool = False,
        memory: Optional[MemoryStore] = None,
    ):
        # 使用外部注入的 LLM 客户端/提示注册表以便于测试替换
        self.llm = llm_client or LLMClient()
        self.registry = prompt_registry or PromptRegistry()
        self.db = db
        self.prompt_version = prompt_version
        # 代理式模式：仅在注入真实 LLM 时才会真正触发工具调用。
        self.agentic = agentic
        self.memory = memory or (MemoryStore(db) if agentic else None)

    def analyze(self, raw: RawContent, persist: bool = True, agentic: Optional[bool] = None) -> Optional[ThreatIntelligence]:
        """分析单条原始内容，返回 `ThreatIntelligence` 或在失败时返回 `None`。

        流程：渲染 prompt -> 调用 LLM（代理式模式下可多步调用工具）-> 解析结构化结果
        -> 提取并合并 IoC ->（可选）写入记忆 -> 构建情报对象 ->（可选）持久化。
        """
        use_agentic = self.agentic if agentic is None else agentic
        prompt = self.registry.render(self._version, raw.content)
        logger.info(f"Analyzing raw content {raw.id} with prompt {self._version}")

        try:
            response = self._invoke_model(prompt, use_agentic)
            # 解析为结构化模型；解析失败（JSON 格式偏差）时重试一次
            try:
                extracted = StructuredParser.parse(response, ExtractedIntelligence)
            except ValueError as e:
                if "decode JSON" not in str(e):
                    raise
                logger.warning(
                    f"raw {raw.id}: JSON 解析失败，使用严格约束重试一次"
                )
                response = self._invoke_model(prompt + _STRICT_SUFFIX, use_agentic)
                extracted = StructuredParser.parse(response, ExtractedIntelligence)
            # 作为降级补充：从原文中用正则抽取 IOC，合并 LLM 输出以避免遗漏
            extracted_iocs = IOCExtractor.extract(raw.content)
            merged_iocs = sorted(set(extracted.iocs + extracted_iocs))

            # 把本次抽取到的 IOC 写入短期记忆，供后续条目做 novelty / 去重判断。
            if self.memory:
                self.memory.remember(merged_iocs)

            intel = ThreatIntelligence(
                id=raw.content_hash or str(uuid4()),
                source_url=raw.url,
                title=extracted.title,
                threat_type=extracted.threat_type,
                iocs=merged_iocs,
                involved_assets=extracted.involved_assets,
                satellite_model=extracted.satellite_model,
                confidence=extracted.confidence,
                summary=extracted.summary,
                source=raw.source_name,
                raw_text=raw.content,
            )

            if persist and self.db:
                # 将情报对象持久化到数据库，供后续验证/关联使用
                self.db.save_intelligence(intel)
            return intel
        except Exception as e:
            # 任何步骤失败（LLM 调用、解析、持久化）都记录错误并返回 None
            logger.error(f"Failed to analyze raw content {raw.id}: {e}")
            return None

    def _invoke_model(self, prompt: str, agentic: bool) -> str:
        """根据是否代理式模式选择调用方式。

        - 代理式 + 真实 LLM：走 `invoke_with_tools`，模型可调用 `cross_check_ioc`
          本地工具检索记忆（IOCs 是否曾在历史出现），实现多步推理。
        - 其他情况：单次 `invoke`。
        """
        if agentic and self._is_real_llm(self.llm):
            tools = [
                {
                    "type": "function",
                    "function": {
                        "name": "cross_check_ioc",
                        "description": "核对某个 IOC 是否曾在历史情报中出现（记忆检索）",
                        "parameters": {
                            "type": "object",
                            "properties": {"ioc": {"type": "string"}},
                            "required": ["ioc"],
                        },
                    },
                }
            ]

            def handler(name: str, args: dict):
                if name == "cross_check_ioc":
                    seen = self.memory.recall(args.get("ioc", "")) if self.memory else False
                    return {"seen_before": seen}
                return {"error": "unknown tool"}

            return self.llm.invoke_with_tools(prompt, tools, handler, system_prompt=AGENTIC_SYSTEM)
        return self.llm.invoke(prompt)

    @staticmethod
    def _is_real_llm(client) -> bool:
        if client is None:
            return False
        # DemoLLM 是确定性 mock，不应触发工具调用路径。
        return "demo" not in type(client).__name__.lower()

    def analyze_batch(self, raw_items: List[RawContent], persist: bool = True) -> List[ThreatIntelligence]:
        """顺序处理多条原始内容并返回成功解析的情报列表。"""
        results: List[ThreatIntelligence] = []
        for raw in raw_items:
            intel = self.analyze(raw, persist=persist)
            if intel:
                results.append(intel)
        return results

    @property
    def _version(self) -> str:
        """确定使用的提示（prompt）版本：优先使用注入的 `prompt_version`，
        否则尝试读取运行时激活的版本并回退到注册表中的最新版本。

        该逻辑允许通过运行时配置切换 prompt 版本而无需修改代码。
        """
        if self.prompt_version:
            return self.prompt_version
        candidates = self.registry.list_versions()
        active = load_active_version()
        if active in candidates:
            return active
        if active:
            logger.warning(
                f"Active prompt version {active} not registered; falling back to latest"
            )
        return self.registry.latest().version
