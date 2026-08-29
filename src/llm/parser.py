"""从 LLM 响应文本中解析结构化 JSON 输出并校验。"""
import json
import re
from typing import Optional, Type, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class StructuredParser:
    """从模型文本回复中抽取并验证 JSON 字符串的工具。

    特性：支持从 Markdown 代码块中提取 JSON，或从裸文本中定位第一个 JSON 对象，
    然后使用给定的 Pydantic 模型进行严格验证并返回验证后的实例。
    """

    @staticmethod
    def extract_json(text: str) -> dict:
        """从文本中抽取第一个 JSON 对象；支持处理 markdown 代码块（```json ... ```）。

        依次尝试多种候选切片，并对常见格式瑕疵做有限修复（去除结尾逗号、
        规范化 Python 字面量），以容忍 LLM 偶发的格式偏差。全部失败则抛出
        JSONDecodeError，由 `parse` 包装为 ValueError。
        """
        text = text.strip()
        candidates = []
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if fence_match:
            candidates.append(fence_match.group(1).strip())
        brace_match = re.search(r"\{[\s\S]*\}", text)
        if brace_match:
            candidates.append(brace_match.group(0))
        candidates.append(text)

        for cand in candidates:
            try:
                return json.loads(cand)
            except json.JSONDecodeError:
                salvaged = StructuredParser._salvage(cand)
                if salvaged is not None:
                    return salvaged
        raise json.JSONDecodeError("no valid JSON object found in LLM output", text, 0)

    @staticmethod
    def _salvage(text: str) -> Optional[dict]:
        """对单个候选做有限修复后重试解析；无法修复时返回 None。"""
        try:
            s = text.strip()
            if not s.startswith("{"):
                start, end = s.find("{"), s.rfind("}")
                if start == -1 or end == -1 or end < start:
                    return None
                s = s[start : end + 1]
            s = re.sub(r",\s*([}\]])", r"\1", s)
            s = s.replace("True", "true").replace("False", "false").replace("None", "null")
            return json.loads(s)
        except Exception:
            return None

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
