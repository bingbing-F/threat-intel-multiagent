"""Parse structured JSON output from LLM responses."""
import json
import re
from typing import Type, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class StructuredParser:
    """Extract and validate JSON from LLM text output."""

    @staticmethod
    def extract_json(text: str) -> dict:
        """Extract the first JSON object from text, handling markdown fences."""
        text = text.strip()
        # Try to find JSON inside markdown code fence
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if fence_match:
            text = fence_match.group(1).strip()
        # Try to find a JSON object directly
        brace_match = re.search(r"\{[\s\S]*\}", text)
        if brace_match:
            text = brace_match.group(0)
        return json.loads(text)

    @classmethod
    def parse(cls, text: str, model_class: Type[T]) -> T:
        """Parse LLM output into a Pydantic model."""
        try:
            data = cls.extract_json(text)
            return model_class.model_validate(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to decode JSON from LLM output: {e}\nOutput:\n{text}") from e
        except ValidationError as e:
            raise ValueError(f"LLM output does not match schema: {e}\nOutput:\n{text}") from e
