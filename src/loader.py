from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pandas as pd
import yaml

COMMON_ENCODINGS = ["utf-8", "gbk", "gb2312", "gb18030"]


def load_yaml(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _try_read_csv(path: str | Path, skiprows: int = 0) -> pd.DataFrame:
    last_error = None
    for encoding in COMMON_ENCODINGS:
        try:
            return pd.read_csv(path, encoding=encoding, skiprows=skiprows, low_memory=False)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise ValueError(f"无法读取CSV文件: {path}. 最后一次错误: {last_error}")


def detect_best_skiprows(path: str | Path, aliases: dict, max_skiprows: int = 20) -> tuple[int, pd.DataFrame]:
    best_score = -1
    best_skiprows = 0
    best_df: pd.DataFrame | None = None

    alias_map = {
        canonical: {str(v).strip().lower() for v in values}
        for canonical, values in aliases.items()
    }

    for skiprows in range(max_skiprows + 1):
        try:
            df = _try_read_csv(path, skiprows=skiprows)
        except Exception:
            continue

        cols = {str(c).strip().lower() for c in df.columns}
        score = 0
        for values in alias_map.values():
            if cols & values:
                score += 1

        if score > best_score:
            best_score = score
            best_skiprows = skiprows
            best_df = df

    if best_df is None:
        raise ValueError(f"无法自动识别CSV表头: {path}")
    return best_skiprows, best_df


def read_log_table(
    path: str | Path,
    aliases: dict,
    skiprows: int | None = None,
    auto_detect_skiprows: bool = True,
) -> tuple[pd.DataFrame, int]:
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix in {".xlsx", ".xls"}:
        return pd.read_excel(path), 0

    if suffix != ".csv":
        raise ValueError(f"暂不支持的日志文件格式: {suffix}")

    if skiprows is not None:
        return _try_read_csv(path, skiprows=skiprows), skiprows

    if auto_detect_skiprows:
        best_skiprows, best_df = detect_best_skiprows(path, aliases)
        return best_df, best_skiprows

    return _try_read_csv(path, skiprows=0), 0


def read_ioc_table(path: str | Path | None) -> pd.DataFrame:
    if not path:
        return pd.DataFrame()

    path = Path(path)
    if path.suffix.lower() in {".xlsx", ".xls"}:
        return pd.read_excel(path)
    if path.suffix.lower() == ".csv":
        return _try_read_csv(path, skiprows=0)
    raise ValueError(f"暂不支持的IOC文件格式: {path.suffix}")
