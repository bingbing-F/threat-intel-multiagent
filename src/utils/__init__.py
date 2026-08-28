"""工具包模块：汇总项目内通用辅助函数。

当前子模块：
- `logger`：统一日志创建与格式化。
- `alert`：告警发送（Lark webhook 与邮件）。
- `ioc_extractor`：从文本提取并规范化 IoC（Indicators of Compromise）。

仅包含文档说明，实际实现位于同目录下的各模块文件中。
"""

from .logger import get_logger
from .alert import send_lark, send_email
from .ioc_extractor import IOCExtractor

__all__ = ["get_logger", "send_lark", "send_email", "IOCExtractor"]
