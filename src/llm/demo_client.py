"""确定性演示 LLM 客户端，接口与 LLMClient 保持一致。"""
"""
替换真实模型以进行零成本演示：该客户端解析渲染后的 prompt 中的原文，
使用确定性启发式规则抽取 IoC、类型与置信度，并返回 StructuredParser 可以
验证的 JSON 字符串，行为与真实模型的响应格式兼容。要切回真实路径只需恢复使用 LLMClient。
"""
import hashlib
import json
import re
import unicodedata
from typing import Optional

from src.utils.ioc_extractor import IOCExtractor

TEXT_MARKER = "原文："


def _stable(text: str) -> float:
    """基于文本计算一个稳定的浮点随机值（用于生成可重复的置信度扰动）。"""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


class DemoLLM:
    """确定性的替代模型，输出与目标 schema 兼容的 JSON。"""

    def __init__(self, version: str = "v1.3"):
        self.version = version

    def invoke(self, user_prompt: str, system_prompt: Optional[str] = None) -> str:
        raw_text = self._extract_raw_text(user_prompt)
        payload = self._analyze(raw_text)
        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
    def _extract_raw_text(prompt: str) -> str:
        """从渲染后的 prompt 中抽取标记为 TEXT_MARKER 的原始文本；若未找到则返回整个 prompt。"""
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
        if "泄露" in text or "leak" in lower or "数据泄露" in text:
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
        # 例如 GF-7、orbiteye-3
        match = re.search(r"\b[a-zA-Z]{2,}-\d{1,2}\b", text)
        return match.group(0) if match else ""

    @staticmethod
    def _score_conf(text: str, threat_type: str, evidence: str,
                    iocs: list, assets: list) -> float:
        # 基于启发式规则为示例数据生成稳定的置信度分数
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
        # 复用第一句（约 40 字）作为自然的标题。
        cleaned = unicodedata.normalize("NFKC", text)
        head = re.split(r"[。！？!?;；]", cleaned, maxsplit=1)[0]
        return (head[:38] + "…") if len(head) > 40 else (head[:40] or f"{threat_type}情报")

    @staticmethod
    def _make_summary(text: str, threat_type: str, iocs: list) -> str:
        ioc_hint = f"，关联 {len(iocs)} 个 IoC" if iocs else ""
        return f"检测到潜在{threat_type}事件{ioc_hint}。请结合原始来源进一步研判。"
