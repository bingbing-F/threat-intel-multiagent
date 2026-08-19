"""Analysis Agent: extract structured intelligence from raw content using LLM."""
from typing import List, Optional

from src.llm.client import LLMClient
from src.llm.parser import StructuredParser
from src.models.intelligence import ExtractedIntelligence, ThreatIntelligence
from src.models.source import RawContent
from src.evaluation.prompt_registry import PromptRegistry
from src.evaluation.runtime import load_active_version
from src.storage.db import Database
from src.utils.ioc_extractor import IOCExtractor
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AnalyzerAgent:
    """Agent that analyzes raw content and extracts structured threat intelligence."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        prompt_registry: Optional[PromptRegistry] = None,
        db: Optional[Database] = None,
        prompt_version: Optional[str] = None,
    ):
        self.llm = llm_client or LLMClient()
        self.registry = prompt_registry or PromptRegistry()
        self.db = db
        self.prompt_version = prompt_version

    def analyze(self, raw: RawContent, persist: bool = True) -> Optional[ThreatIntelligence]:
        """Analyze a single raw content item."""
        prompt = self.registry.render(self._version, raw.content)
        logger.info(f"Analyzing raw content {raw.id} with prompt {self._version}")

        try:
            response = self.llm.invoke(prompt)
            extracted = StructuredParser.parse(response, ExtractedIntelligence)
            # Enrich IOCs with regex extraction as fallback
            extracted_iocs = IOCExtractor.extract(raw.content)
            merged_iocs = sorted(set(extracted.iocs + extracted_iocs))

            intel = ThreatIntelligence(
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
                self.db.save_intelligence(intel)
            return intel
        except Exception as e:
            logger.error(f"Failed to analyze raw content {raw.id}: {e}")
            return None

    def analyze_batch(self, raw_items: List[RawContent], persist: bool = True) -> List[ThreatIntelligence]:
        """Analyze multiple raw content items sequentially."""
        results: List[ThreatIntelligence] = []
        for raw in raw_items:
            intel = self.analyze(raw, persist=persist)
            if intel:
                results.append(intel)
        return results

    @property
    def _version(self) -> str:
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
