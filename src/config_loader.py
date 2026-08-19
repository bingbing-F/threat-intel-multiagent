"""Configuration loader with environment variable substitution."""
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Lazy-loaded application settings."""

    _instance = None
    _config: Dict[str, Any] = {}

    def __new__(cls, path: Optional[str] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load(path or cls._default_path())
        return cls._instance

    @staticmethod
    def _default_path() -> str:
        root = Path(__file__).resolve().parent.parent
        return str(root / "config" / "settings.yaml")

    def _load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        substituted = self._substitute_env(raw)
        self._config = yaml.safe_load(substituted)

    @staticmethod
    def _substitute_env(content: str) -> str:
        """Replace ${VAR} or ${VAR:-default} with environment values."""
        pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

        def replacer(match: re.Match) -> str:
            var_name = match.group(1)
            default = match.group(2)
            value = os.environ.get(var_name)
            if value is None and default is None:
                raise ValueError(f"Environment variable {var_name} is not set")
            return value if value is not None else default

        return pattern.sub(replacer, content)

    def get(self, key: str, default: Any = None) -> Any:
        """Dot-notation access, e.g. settings.get('llm.model')."""
        keys = key.split(".")
        value = self._config
        for k in keys:
            if not isinstance(value, dict):
                return default
            value = value.get(k, default)
            if value is None:
                return default
        return value

    @property
    def config(self) -> Dict[str, Any]:
        return self._config


def get_settings() -> Settings:
    return Settings()
