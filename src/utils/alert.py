"""告警通道实现：支持发送 Lark（企业微信类）Webhook 与基于 SMTP 的邮件告警。"""
from datetime import datetime
from typing import List

import httpx

from src.config_loader import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


def send_lark(message: str) -> bool:
    """通过 Lark Webhook 发送文本消息。

    若未在配置中填写 `alert.lark.webhook_url` 则忽略发送并返回 False。
    """
    settings = get_settings()
    webhook_url = settings.get("alert.lark.webhook_url")
    if not webhook_url:
        logger.warning("Lark webhook URL not configured, skipping alert")
        return False
    try:
        payload = {"msg_type": "text", "content": {"text": message}}
        response = httpx.post(webhook_url, json=payload, timeout=30)
        response.raise_for_status()
        logger.info("Lark alert sent successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to send Lark alert: {e}")
        return False


def send_email(subject: str, body: str) -> bool:
    """发送邮件告警（基于 SMTP）。

    需要在配置 `alert.email` 中提供 `smtp_host`、`smtp_port`、`username`、`password` 和 `to` 列表。
    若配置不完整则跳过并返回 False。
    """
    settings = get_settings()
    email_cfg = settings.get("alert.email", {})
    smtp_host = email_cfg.get("smtp_host")
    smtp_port = int(email_cfg.get("smtp_port", 587))
    username = email_cfg.get("username")
    password = email_cfg.get("password")
    to = email_cfg.get("to", [])

    if not (smtp_host and username and password and to):
        logger.warning("Email not fully configured, skipping alert")
        return False

    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart()
        msg["From"] = email_cfg.get("from", username)
        msg["To"] = ", ".join(to)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        # 使用 TLS 加密会话并发送邮件
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(username, password)
            server.sendmail(username, to, msg.as_string())
        logger.info("Email alert sent successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
        return False
