"""Reporting Agent: generate daily reports and send alerts."""
from datetime import datetime
from typing import List, Optional

from jinja2 import Template

from src.config_loader import get_settings
from src.models.intelligence import ThreatIntelligence
from src.storage.db import Database
from src.utils.alert import send_email, send_lark
from src.utils.logger import get_logger

logger = get_logger(__name__)


REPORT_TEMPLATE = """# 威胁情报日报

生成时间：{{ now }}
今日有效情报数：{{ items | length }}

{% for item in items %}
## {{ loop.index }}. {{ item.title }}

- 威胁类型：{{ item.threat_type }}
- 置信度：{{ "%.2f" | format(item.confidence) }}
- 来源：{{ item.source }}
- IoC：{{ item.iocs | join(", ") or "无" }}
- 涉及资产：{{ item.involved_assets | join(", ") or "未知" }}
- 摘要：{{ item.summary }}

{% endfor %}

---
本报告由基于多智能体协作的自动化网络威胁情报监控与预警系统生成。
"""


class ReporterAgent:
    """Agent responsible for generating reports and sending alerts."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db
        self.template = Template(REPORT_TEMPLATE)

    def generate_daily_report(self, items: Optional[List[ThreatIntelligence]] = None) -> str:
        """Generate a Markdown daily report."""
        if items is None and self.db:
            items = self.db.list_intelligence(is_valid=True, limit=100)
        items = items or []
        return self.template.render(items=items, now=datetime.utcnow().isoformat())

    def send_alert(self, item: ThreatIntelligence) -> bool:
        """Send a real-time alert for a high-confidence intelligence item."""
        settings = get_settings()
        if not settings.get("alert.enabled", False):
            logger.info("Alert is disabled in settings")
            return False

        subject = f"[威胁情报告警] {item.threat_type} - {item.title}"
        body = (
            f"威胁类型：{item.threat_type}\n"
            f"置信度：{item.confidence:.2f}\n"
            f"来源：{item.source}\n"
            f"IoC：{', '.join(item.iocs) or '无'}\n"
            f"摘要：{item.summary}\n"
        )

        email_ok = send_email(subject, body)
        lark_ok = send_lark(f"{subject}\n\n{body}")
        return email_ok or lark_ok

    def send_daily_report(self, items: Optional[List[ThreatIntelligence]] = None) -> bool:
        """Send the daily report via email and Lark."""
        report = self.generate_daily_report(items)
        subject = f"威胁情报日报 {datetime.utcnow().strftime('%Y-%m-%d')}"
        email_ok = send_email(subject, report)
        lark_ok = send_lark(f"{subject}\n\n{report}")
        return email_ok or lark_ok
