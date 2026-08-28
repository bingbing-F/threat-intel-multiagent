"""汇报代理：生成日报并发送告警通知的组件。

此模块负责将通过验证的情报组织为可读的日报（Markdown），并在配置允许时通过
邮件或 Lark 发送实时告警或日报。告警开关与通道在配置中管理。
"""
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
- 类型：{{ item.threat_type }}
- 来源地址：{{ item.source_url or "—" }}
- IoC：{{ item.iocs | join(", ") or "无" }}
- 涉及资产：{{ item.involved_assets | join(", ") or "未知" }}
- 摘要：{{ item.summary }}

{% endfor %}

---
本报告由基于多智能体协作的自动化网络威胁情报监控与预警系统生成。
"""


class ReporterAgent:
    """负责生成报告和发送告警的 Agent。

    说明：模板使用 Jinja2 渲染，告警发送通过 `send_email` 与 `send_lark` 两条
    通道并行尝试，返回值表示至少有一种通道发送成功。
    """

    def __init__(self, db: Optional[Database] = None):
        self.db = db
        self.template = Template(REPORT_TEMPLATE)

    def generate_daily_report(self, items: Optional[List[ThreatIntelligence]] = None) -> str:
        """生成 Markdown 格式的日报字符串。

        若未指定 `items` 且存在 `db`，则默认从数据库读取最近的有效情报（limit=100）。
        """
        if items is None and self.db:
            items = self.db.list_intelligence(is_valid=True, limit=100)
        items = items or []
        return self.template.render(items=items, now=datetime.utcnow().isoformat())

    def send_alert(self, item: ThreatIntelligence) -> bool:
        """对高置信度情报发送实时告警（邮件 + Lark）。

        告警是否启用由配置项 `alert.enabled` 控制，若关闭则仅记录日志并返回 False。
        """
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
        """通过邮件和 Lark 发送日常报告，返回至少一条通道发送成功的布尔值。"""
        report = self.generate_daily_report(items)
        subject = f"威胁情报日报 {datetime.utcnow().strftime('%Y-%m-%d')}"
        email_ok = send_email(subject, report)
        lark_ok = send_lark(f"{subject}\n\n{report}")
        return email_ok or lark_ok
