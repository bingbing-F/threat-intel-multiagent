"""日志工具封装。

提供一个统一的 `get_logger` 接口来根据配置创建并返回格式化的 logger。
若已存在处理器（handlers）则直接返回，避免重复添加 handler。
"""
import logging
import sys
from typing import Optional

from src.config_loader import get_settings


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """获取一个配置好的 logger 实例。

    - 名称可选，默认使用 `threat_intel`。
    - 日志级别从配置 `app.log_level` 读取（默认为 INFO）。
    - 使用标准输出流并添加统一的输出格式，便于调试与容器化运行时查看日志。
    """
    logger = logging.getLogger(name or "threat_intel")
    if logger.handlers:
        return logger

    settings = get_settings()
    log_level = settings.get("app.log_level", "INFO")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
