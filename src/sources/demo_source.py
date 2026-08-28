"""演示来源：用于零成本端到端演示的确定性示例内容。

说明：流水线保持真实（Collector -> DemoLLM 提取 -> 实际 Validator ->
实际 Reporter -> 持久化 DB）；仅数据采集使用本地样本以便在没有 LLM API Key
或无网络时也能完整跑通演示流程。
"""
from typing import List

from src.models.source import RawContent
from src.sources.base import BaseSource

DEMO_ITEMS = [
    {
        "title": "遥感卫星地面站数据库暴露",
        "source_name": "demo:rss-krebs",
        "content": (
            "某遥感卫星地面站数据库配置错误暴露至公网，攻击者可访问卫星轨道数据。"
            "涉及IP 192.0.2.15，域名 leaked-sat-db.example.com，卫星型号为 GF-7。"
        ),
    },
    {
        "title": "卫星通信链路访问权限出售",
        "source_name": "demo:forum",
        "content": (
            "黑客论坛出现帖文声称出售某商业卫星通信链路访问权限，"
            "附带样本IP 198.51.100.32 和 MD5 哈希 a3f5c8e9d2b140ff559d7a9cf7c9a1e2。"
        ),
    },
    {
        "title": "卫星任务控制系统 Web 漏洞",
        "source_name": "demo:nvd",
        "content": (
            "CVE-2024-11223 影响某卫星任务控制系统的Web组件，可利用漏洞获取地面站管理员权限。"
            "POC已在GitHub公开。"
        ),
    },
    {
        "title": "恶意软件 FakeSatLoader 分发",
        "source_name": "demo:blog",
        "content": (
            "安全厂商监测到新型恶意软件 FakeSatLoader 通过钓鱼邮件分发，"
            "利用 CVE-2025-2231 执行初始访问，样本 MD5 为 dc4a12f4c95ab2f8c1e07d9a6b5f03e8。"
        ),
    },
    {
        "title": "APT 组织针对卫星运营商供应链攻击",
        "source_name": "demo:threatfeed",
        "content": (
            "APT 组织 GhostNet 针对某卫星运营商供应商网络发起供应链攻击，"
            "域名 ghostctl.example.net 被用作回连 C2，攻击已持续数周。"
        ),
    },
    {
        "title": "商业卫星公司 API 数据泄露",
        "source_name": "demo:blog2",
        "content": (
            "商业卫星影像公司曝出 API 未授权访问漏洞，"
            "外部 IP 203.0.113.88 可下载未发布影像数据，涉及遥感卫星 orbiteye-3。"
        ),
    },
    {
        "source_name": "demo:media",
        "content": "这部电影讲述了一颗虚构卫星被黑客控制，导致全球网络瘫痪的剧情。片中IP 203.0.113.7 是导演编造的。",
        "title": "电影剧情，非真实威胁",
    },
    {
        "source_name": "demo:edu",
        "content": "最新科普文章介绍遥感卫星成像原理，没有任何安全事件或IoC信息。",
        "title": "科普文章",
    },
    {
        "source_name": "demo:research",
        "content": (
            "某安全观测团队在公开博客记录了来自 IP 203.0.114.9 的观测数据，"
            "仅作研究分享，目前无可证实的威胁事件。"
        ),
        "title": "观测日志，疑似误报",
    },
    {
        "source_name": "demo:vendor-a",
        "content": (
            "安全厂商 A 发布报告：CVE-2025-6601 被用于针对卫星地面站的攻击，"
            "涉及回连 IP 192.0.2.99。"
        ),
        "title": "厂商A：CVE-2025-6601 攻击报告",
    },
    {
        "source_name": "demo:vendor-b",
        "content": (
            "安全厂商 B 独立监测：确认 192.0.2.99 与 CVE-2025-6601 相关的攻击活动，"
            "多家单位已受影响。"
        ),
        "title": "厂商B：CVE-2025-6601 独立确认",
    },
]


def _stable_hash(text: str) -> str:
    """返回文本的稳定 SHA-256 哈希，用于演示数据的内容指纹。

    仅用于生成可复现的 `content_hash`，便于演示中去重和示例追踪。
    """
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class DemoSource(BaseSource):
    """提供一组固定的、精选的演示示例条目作为数据源。"""

    def __init__(self):
        super().__init__("demo", enabled=True)

    def fetch(self) -> List[RawContent]:
        items: List[RawContent] = []
        for i, item in enumerate(DEMO_ITEMS):
            content = item["content"]
            items.append(
                RawContent(
                    source_name=item.get("source_name", "demo"),
                    url=f"demo://sample/{i}",
                    title=item.get("title"),
                    content=content,
                    content_hash=_stable_hash(content),
                )
            )
        return items