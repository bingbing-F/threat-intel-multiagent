"""Verify real-mode LLM on satellite-tuned demo content (cost: 3 LLM calls)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.llm.client import LLMClient
from src.agents.analyzer import AnalyzerAgent
from src.agents.validator import ValidatorAgent
from src.sources.demo_source import DemoSource

client = LLMClient()
assert "demo" not in type(client).__name__.lower(), "should use real LLM"
analyzer = AnalyzerAgent(llm_client=client, db=None)
validator = ValidatorAgent(required_keywords=[], db=None)

raws = DemoSource().fetch()
print("total demo raw:", len(raws))
for r in raws[:3]:
    obj = analyzer.analyze(r, persist=False)
    if not obj:
        print("SKIP (analyze None)")
        continue
    print("---")
    print("title:", obj.title)
    print("type:", obj.threat_type, "| conf:", round(obj.confidence, 3))
    v = validator.validate(obj, persist=False)
    print("valid:", v.is_valid, "|", (v.validation_reason or "")[:70])