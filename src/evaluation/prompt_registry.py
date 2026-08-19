"""Prompt version registry and loader."""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PromptVersion:
    version: str
    name: str
    description: str
    file_path: Path
    content: str


class PromptRegistry:
    """Manage prompt templates with versioning."""

    VERSION_PATTERN = re.compile(r"v(\d+\.\d+)_(.+)\.txt")

    def __init__(self, prompts_dir: Optional[Path] = None):
        if prompts_dir is None:
            root = Path(__file__).resolve().parent.parent.parent
            prompts_dir = root / "config" / "prompts"
        self.prompts_dir = prompts_dir
        self._prompts: Dict[str, PromptVersion] = {}
        self.load_all()

    def load_all(self) -> None:
        """Load all prompt files from the prompts directory."""
        if not self.prompts_dir.exists():
            logger.warning(f"Prompts directory not found: {self.prompts_dir}")
            return

        for file_path in sorted(self.prompts_dir.glob("*.txt")):
            match = self.VERSION_PATTERN.match(file_path.name)
            if not match:
                continue
            version = f"v{match.group(1)}"
            name = match.group(2)
            content = file_path.read_text(encoding="utf-8")
            self._prompts[version] = PromptVersion(
                version=version,
                name=name,
                description=f"Prompt version {version} for {name}",
                file_path=file_path,
                content=content,
            )
            logger.info(f"Loaded prompt {version}: {file_path.name}")

    def get(self, version: str) -> PromptVersion:
        if version not in self._prompts:
            raise KeyError(f"Prompt version {version} not found. Available: {list(self._prompts.keys())}")
        return self._prompts[version]

    def list_versions(self) -> List[str]:
        return list(self._prompts.keys())

    def latest(self) -> PromptVersion:
        if not self._prompts:
            raise ValueError("No prompts loaded")
        # Sort by semantic version
        latest = sorted(self._prompts.keys(), key=lambda v: [int(x) for x in v[1:].split(".")])[-1]
        return self._prompts[latest]

    def render(self, version: str, raw_text: str) -> str:
        prompt = self.get(version)
        return prompt.content.format(raw_text=raw_text)
