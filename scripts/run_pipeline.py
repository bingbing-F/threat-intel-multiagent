"""Run the full threat intelligence pipeline once."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.graph.workflow import ThreatIntelWorkflow
from src.storage.db import init_db

if __name__ == "__main__":
    demo = "--demo" in sys.argv
    limit = None
    for i, arg in enumerate(sys.argv):
        if arg == "--limit" and i + 1 < len(sys.argv):
            limit = int(sys.argv[i + 1])

    init_db()
    workflow = ThreatIntelWorkflow(demo=demo)
    result = workflow.run(send_alerts=False, generate_report=True, limit=limit)
    print("\n=== Workflow Result ===")
    if demo:
        print("Mode: demo (deterministic DemoLLM, no LLM API required)")
    print(f"Raw items: {result.raw_count}")
    print(f"Analyzed items: {result.analyzed_count}")
    print(f"Valid items: {result.valid_count}")
    print(f"Invalid items: {result.invalid_count}")
    if result.errors:
        print(f"Errors: {len(result.errors)}")
        for err in result.errors[:5]:
            print(f"  - {err}")
