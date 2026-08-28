"""从 LLM 响应文本中解析结构化 JSON 输出并校验。"""
import json
import re
from typing import Type, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class StructuredParser:
    """从模型文本回复中抽取并验证 JSON 字符串的工具。

    特性：支持从 Markdown 代码块中提取 JSON，或从裸文本中定位第一个 JSON 对象，
    然后使用给定的 Pydantic 模型进行严格验证并返回验证后的实例。
    """

    @staticmethod
    def extract_json(text: str) -> dict:
        """从文本中抽取第一个 JSON 对象；支持处理 markdown 代码块（```json ... ```）。"""
        text = text.strip()
        # 尝试从 Markdown 代码块中提取 JSON
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if fence_match:
            text = fence_match.group(1).strip()
        # 尝试直接定位第一个花括号包围的 JSON 对象
        brace_match = re.search(r"\{[\s\S]*\}", text)
        if brace_match:
            text = brace_match.group(0)
        return json.loads(text)

    @classmethod
    def parse(cls, text: str, model_class: Type[T]) -> T:
        """将 LLM 输出解析为指定的 Pydantic 模型实例，解析或验证失败时抛出 ValueError。"""
        try:
            data = cls.extract_json(text)
            return model_class.model_validate(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to decode JSON from LLM output: {e}\nOutput:\n{text}") from e
        except ValidationError as e:
            raise ValueError(f"LLM output does not match schema: {e}\nOutput:\n{text}") from e
