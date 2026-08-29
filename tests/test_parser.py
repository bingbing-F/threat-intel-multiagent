"""Tests for the structured-output JSON parser (salvage / fence handling)."""
import json

import pytest

from src.llm.parser import StructuredParser


def test_extract_fenced_json():
    text = "some prose\n```json\n{\"a\": 1}\n```"
    assert StructuredParser.extract_json(text) == {"a": 1}


def test_extract_prose_with_trailing_comma_salvaged():
    text = 'here is the result: {"iocs": ["1.2.3.4",], "ok": true,}'
    data = StructuredParser.extract_json(text)
    assert data["iocs"] == ["1.2.3.4"]
    assert data["ok"] is True


def test_extract_python_literals_salvaged():
    text = 'summary: {"flag": None, "on": False, "n": 3}'
    data = StructuredParser.extract_json(text)
    assert data["flag"] is None
    assert data["on"] is False


def test_no_json_raises():
    with pytest.raises(json.JSONDecodeError):
        StructuredParser.extract_json("no json here at all")
