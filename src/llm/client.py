"""统一的 LLM 客户端，支持缓存与后端提供者切换。"""
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from openai import OpenAI

from src.config_loader import get_settings


class LLMClient:
    """基于配置构建的 LLM 客户端，兼容 OpenAI 风格的 API 调用。

    功能要点：
    - 从配置或环境变量读取模型、API Key、base_url 等设置。
    - 支持本地磁盘缓存以避免重复调用（可通过 `llm.cache_enabled` 控制）。
    - 提供同步 `invoke` 与异步兼容接口 `ainvoke`（当前由同步实现包装）。
    """

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
        """基于配置构建并返回 OpenAI 客户端实例（或兼容包装）。"""
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
        """调用模型并返回文本回复；先检查本地缓存以降低 API 费用与延迟。"""
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

    def invoke_with_tools(
        self,
        user_prompt: str,
        tools: list,
        tool_handler: callable,
        system_prompt: Optional[str] = None,
        max_steps: int = 3,
    ) -> str:
        """带工具调用的多步代理式调用（function calling）。

        流程：模型可在需要时发出 `tool_calls`；本方法在本地执行对应的工具处理函数
        （如 `cross_check_ioc` 记忆检索，完全本地、合规），将结果回灌模型，直到模型
        给出最终文本或达到 `max_steps` 步数。这是让 LLM 从「单次抽取」升级为
        「可调用工具、具备记忆的多步 Agent」的关键能力。

        若底层模型不支持工具调用（返回内容而非 tool_calls），则退化为单次 `invoke`，
        行为与 `invoke` 一致，不会破坏现有流程。
        """
        system = system_prompt or "You are a helpful assistant."
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ]
        for _ in range(max_steps):
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                tools=tools,
                tool_choice="auto",
            )
            msg = response.choices[0].message
            tool_calls = getattr(msg, "tool_calls", None)
            if not tool_calls:
                # 模型不再调用工具，返回最终内容（退化路径安全）。
                return msg.content or ""
            # 把带工具调用的 assistant 消息原样回填，供下一轮上下文使用。
            messages.append(
                {
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in tool_calls
                    ],
                }
            )
            for tc in tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except Exception:
                    args = {}
                result = tool_handler(tc.function.name, args)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(result, ensure_ascii=False),
                    }
                )
        # 达到步数上限时返回最后一条消息内容（若存在）。
        return msg.content or ""

    async def ainvoke(self, user_prompt: str, system_prompt: Optional[str] = None) -> str:
        # MVP 方案：临时将同步 `invoke` 包装为异步接口；后续可替换为真正的异步客户端实现。
        return self.invoke(user_prompt, system_prompt)


def get_llm_client() -> LLMClient:
    return LLMClient()
