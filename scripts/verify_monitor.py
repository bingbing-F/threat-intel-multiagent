"""Capture local dataset multi-domain monitoring evidence (no LLM cost)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.agents.monitor import DomainMonitorAgent
from src.config_loader import Settings
from src.sources.local_dataset_source import LocalDatasetSource

print("settings app version:", Settings().get("app.version"))
raw = LocalDatasetSource().fetch()
print("dataset samples:", len(raw))
from collections import Counter

print("tiers:", dict(Counter(i.metadata["tier"] for i in raw)))
metrics = DomainMonitorAgent(db=None).scan(raw)
for m in metrics:
    print(f"{m.domain}: {m.matched_items} items, {m.total_sources} src, dark={m.dark_sources}")

dark_total = sum(m.dark_sources for m in metrics)
print("total dark-source items:", dark_total)