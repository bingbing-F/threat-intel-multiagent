"""Runtime prompt-version selection.

A/B evaluation produces a winner; this module lets the winning prompt version
become the production default used by the analyzer at runtime - closing the
"evaluate -> deploy -> regression-guard" loop that is the AI-testing story.
"""
import json
from pathlib import Path

RUNTIME_PATH = Path("data/runtime_prompt.json")


def load_active_version(default: str = "") -> str:
    """Return the deployed prompt version, or ``default`` if none / unreadable."""
    if RUNTIME_PATH.exists():
        try:
            data = json.loads(RUNTIME_PATH.read_text(encoding="utf-8"))
            version = data.get("version", "")
            if version:
                return version
        except Exception:  # noqa: BLE001 - fall back to default on corrupted file
            pass
    return default


def save_active_version(version: str) -> None:
    RUNTIME_PATH.parent.mkdir(parents=True, exist_ok=True)
    RUNTIME_PATH.write_text(
        json.dumps({"version": version}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )