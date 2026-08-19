"""Deterministic demo LLM client with the same interface as LLMClient.

Replaces the real model during zero-cost demos: it parses the raw text from the
rendered prompt, extracts IOCs/type/confidence with deterministic heuristics, and
returns a JSON string that ``StructuredParser`` can validate - exactly like a real
model response. Swap it back to ``LLMClient`` to run the true LLM path.
"""
import hashlib
import json
import re
import unicodedata
from typing import Optional

from src.utils.ioc_extractor import IOCExtractor

TEXT_MARKER = "原文："


def _stable(text: str) -> float:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


class DemoLLM:
    """A deterministic stand-in model emitting schema-compatible JSON."""

    def __init__(self, version: str = "v1.3"):
        self.version = version

    def invoke(self, user_prompt: str, system_prompt: Optional[str] = None) -> str:
        raw_text = self._extract_raw_text(user_prompt)
        payload = self._analyze(raw_text)
        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
    def _extract_raw_text(prompt: str) -> str:
        idx = prompt.rfind(TEXT_MARKER)
        if idx == -1:
            return prompt
        return prompt[idx + len(TEXT_MARKER):].strip()

    def _analyze(self, text: str) -> dict:
        threat_type, evidence = self._classify(text)
        iocs = IOCExtractor.extract(text)
        assets = self._collect_assets(text)
        satellite_model = self._extract_satellite_model(text)
        confidence = self._score_conf(text, threat_type, evidence, iocs, assets)
        title = self._make_title(text, threat_type)
        summary = self._make_summary(text, threat_type, iocs)

        return {
            "title": title,
            "threat_type": threat_type,
            "iocs": iocs,
            "involved_assets": assets,
            "satellite_model": satellite_model or "",
            "confidence": round(confidence, 4),
            "summary": summary,
        }

    @staticmethod
    def _classify(text: str):
        lower = text.lower()
        if "电影" in text or "小说" in text or "科普" in text:
            return "其他", "irrelevant"
        if "cve-" in lower or "漏洞" in text:
            return "漏洞利用", "vuln"
        if "钓鱼" in text or "phish" in lower:
            return "钓鱼攻击", "phish"
        if "ddos" in lower or "拒绝服务" in text:
            return "拒绝服务", "dos"
        if "apt" in lower or "供应链" in text:
            return "APT攻击", "apt"
        if "恶意软件" in text or "木马" in text or "样本" in text:
            return "恶意软件", "malware"
        if "泄露" in text or "leak" in lower or "泄露" in text or "数据泄露" in text:
            return "数据泄露", "leak"
        if "攻击" in text or "入侵" in text or "未授权" in text:
            return "数据泄露", "breach"
        return "其他", "none"

    @staticmethod
    def _collect_assets(text: str) -> list:
        rules = {
            "遥感卫星": ["遥感卫星", "卫星地面站", "地面站"],
            "卫星通信链路": ["卫星通信链路", "通信链路", "通信"],
            "任务控制系统": ["任务控制系统", "控制系统"],
            "供应商网络": ["供应链", "供应商"],
            "Web组件": ["Web组件", "web组件"],
            "数据库": ["数据库"],
            "卫星运营商": ["运营商"],
        }
        found: list = []
        for asset, keywords in rules.items():
            if any(k in text for k in keywords):
                found.append(asset)
        return found

    @staticmethod
    def _extract_satellite_model(text: str) -> str:
        # e.g. GF-7, orbiteye-3
        match = re.search(r"\b[a-zA-Z]{2,}-\d{1,2}\b", text)
        return match.group(0) if match else ""

    @staticmethod
    def _score_conf(text: str, threat_type: str, evidence: str,
                    iocs: list, assets: list) -> float:
        if evidence == "irrelevant":
            return 0.25
        has_cve = any("cve" in i.lower() for i in iocs)
        ioc_count = len(iocs)
        if ioc_count == 0 and evidence in ("none",):
            return 0.45
        if has_cve:
            return 0.90 + 0.06 * _stable(text + "cve")
        if evidence in ("leak", "breach", "vuln") and (ioc_count >= 2 or assets):
            return 0.92 + 0.05 * _stable(text + "leak")
        if ioc_count >= 1:
            return 0.88 + 0.08 * _stable(text + "ioc")
        if evidence in ("malware", "apt", "phish", "dos"):
            return 0.80 + 0.10 * _stable(text + "ev")
        return 0.60 + 0.30 * _stable(text + "g")

    @staticmethod
    def _make_title(text: str, threat_type: str) -> str:
        # Reuse first sentence up to ~40 chars as a natural title.
        cleaned = unicodedata.normalize("NFKC", text)
        head = re.split(r"[。！？!?;；]", cleaned, maxsplit=1)[0]
        return (head[:38] + "…") if len(head) > 40 else (head[:40] or f"{threat_type}情报")

    @staticmethod
    def _make_summary(text: str, threat_type: str, iocs: list) -> str:
        ioc_hint = f"，关联 {len(iocs)} 个 IoC" if iocs else ""
        return f"检测到潜在{threat_type}事件{ioc_hint}。请结合原始来源进一步研判。"