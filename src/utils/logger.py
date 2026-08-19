"""Logging utilities."""
import logging
import sys
from typing import Optional

from src.config_loader import get_settings


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a configured logger."""
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
