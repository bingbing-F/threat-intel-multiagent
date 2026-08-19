"""Unified LLM client with caching and provider switching."""
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from openai import OpenAI

from src.config_loader import get_settings


class LLMClient:
    """Configuration-driven LLM client supporting OpenAI-compatible APIs."""

    def __init__(self, provider: Optional[str] = None, model: Optional[str] = None):
        settings = get_settings()
        self.provider = (provider or settings.get("llm.provider", "openai")).lower()
        self.model = model or settings.get("llm.model", "gpt-4o-mini")
        self.api_key = settings.get("llm.api_key") or os.environ.get("LLM_API_KEY", "")
        self.base_url = settings.get("llm.base_url")
        self.temperature = float(settings.get("llm.temperature", 0.1))
        self.max_tokens = int(settings.get("llm.max_tokens", 2048))
        self.timeout = int(settings.get("llm.timeout", 60))
        self.cache_enabled = bool(settings.get("llm.cache_enabled", True))
        self.cache_dir = Path(settings.get("llm.cache_dir", "data/llm_cache"))
        if self.cache_enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._client = self._build_client()

    def _build_client(self) -> OpenAI:
        kwargs: Dict[str, Any] = {"timeout": self.timeout}
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return OpenAI(**kwargs)

    def _cache_key(self, system: str, user: str) -> str:
        content = f"{self.model}:{self.temperature}:{system}:{user}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def _load_cache(self, key: str) -> Optional[str]:
        if not self.cache_enabled:
            return None
        path = self._cache_path(key)
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8")).get("content")
        return None

    def _save_cache(self, key: str, content: str) -> None:
        if not self.cache_enabled:
            return
        path = self._cache_path(key)
        path.write_text(json.dumps({"content": content}, ensure_ascii=False), encoding="utf-8")

    def invoke(self, user_prompt: str, system_prompt: Optional[str] = None) -> str:
        system = system_prompt or "You are a helpful assistant."
        cached = self._load_cache(self._cache_key(system, user_prompt))
        if cached is not None:
            return cached

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ]
        response = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        content = response.choices[0].message.content or ""
        self._save_cache(self._cache_key(system, user_prompt), content)
        return content

    async def ainvoke(self, user_prompt: str, system_prompt: Optional[str] = None) -> str:
        # For MVP, run sync invoke in thread; async client can be added later
        return self.invoke(user_prompt, system_prompt)


def get_llm_client() -> LLMClient:
    return LLMClient()
