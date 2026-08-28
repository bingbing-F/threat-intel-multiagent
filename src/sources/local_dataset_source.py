"""本地数据集来源：从磁盘读取精选的种子/监控样本。

说明：`data/dark_dataset/` 下的每个 JSON 文件都表示一个合成的威胁情报样本，
通常包含 `sample: true` 标记，覆盖不同域名并区分两个来源层级：

- `dark`     -> 模拟暗网论坛/市场/频道来源。
- `clearnet` -> 公开的厂商博客 / 威胁情报订阅源。

该来源用于在离线或无 Tor 环境下提供确定性的监控样本（无需 SOCKS 代理或 .onion 解析），
从而使得整个流水线（Collector -> Analyzer -> Validator -> Correlator -> Reporter）
及跨域监控仍能真实运行。它在语义上类似于 `DemoSource`，但每条样本携带
`source_tier` 字段以便于区域/分层级报告。
"""
import hashlib
import json
from pathlib import Path
from typing import List

from src.models.source import RawContent
from src.sources.base import BaseSource
from src.utils.logger import get_logger

logger = get_logger(__name__)

# 项目根目录与默认数据集目录（可被构造器的 `directory` 参数覆盖）
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DIR = PROJECT_ROOT / "data" / "dark_dataset"


def _stable_hash(text: str) -> str:
    """计算文本的稳定 SHA-256 哈希，用作样本的可复现 content_hash。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class LocalDatasetSource(BaseSource):
    """从本地 JSON 目录加载种子监控样本并将其转换为 `RawContent` 条目。"""

    def __init__(self, directory: str = None, name: str = "local_dataset", enabled: bool = True):
        super().__init__(name, enabled)
        self.directory = Path(directory) if directory else DEFAULT_DIR

    def fetch(self) -> List[RawContent]:
        results: List[RawContent] = []
        # 目录存在性检查：若目录不存在则记录警告并返回空结果（不会抛出异常）。
        if not self.directory.exists():
            logger.warning(f"Local dataset directory not found: {self.directory}")
            return results
        for path in sorted(self.directory.glob("*.json")):
            try:
                # 读取并解析 JSON 样本文件；解析失败或 IO 错误会被记录并跳过该文件。
                entry = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Failed to read dataset sample {path}: {e}")
                continue
            content = entry.get("content", "").strip()
            if not content:
                # 空内容样本直接跳过
                continue
            metadata = {
                # tier 表示来源层级（dark / clearnet），用于后续汇总与分层报告
                "tier": entry.get("tier", "clearnet"),
                "domain": entry.get("domain", "未分类"),
                "sample": True,
                "dataset_file": path.name,
            }
            if entry.get("keywords"):
                metadata["keywords"] = list(entry["keywords"])
            results.append(
                RawContent(
                    source_name=entry.get("source", f"{self.name}:{path.stem}"),
                    url=entry.get("url"),
                    title=entry.get("title"),
                    content=content,
                    content_hash=_stable_hash(content),
                    metadata=metadata,
                )
            )
        logger.info(f"LocalDatasetSource[{self.name}] loaded {len(results)} samples")
        return results