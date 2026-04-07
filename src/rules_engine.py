from __future__ import annotations

from collections import Counter
from urllib.parse import urlparse

import pandas as pd

from normalizer import clean_text, is_public_ip


def add_group_features(df: pd.DataFrame) -> pd.DataFrame:
    target_key = df.get("detail_domain", pd.Series([""] * len(df))).where(
        df.get("detail_domain", pd.Series([""] * len(df))) != "",
        df.get("dst_ip_norm", pd.Series([""] * len(df))),
    )
    df["target_key"] = target_key.fillna("")
    counts = Counter(zip(df.get("src_ip_norm", []), df["target_key"]))
    df["same_src_target_count"] = [counts[(src, tgt)] for src, tgt in zip(df.get("src_ip_norm", []), df["target_key"])]
    return df


def hit_off_hours(row: pd.Series, config: dict) -> bool:
    ts = row.get("event_time")
    if pd.isna(ts):
        return False
    start = int(config["work_hours"]["start"])
    end = int(config["work_hours"]["end"])
    return not (start <= ts.hour < end)


def hit_risky_download(row: pd.Series, config: dict) -> bool:
    file_name = clean_text(row.get("download_file", "")).lower()
    url = clean_text(row.get("detail_url", "")).lower()
    path = urlparse(url).path.lower() if url else ""
    exts = [ext.lower() for ext in config["risky_file_extensions"]]
    return any(file_name.endswith(ext) or path.endswith(ext) for ext in exts)


def hit_plain_http(row: pd.Series) -> bool:
    url = clean_text(row.get("detail_url", "")).lower()
    return url.startswith("http://")


def hit_repeated_target(row: pd.Series, config: dict) -> bool:
    threshold = int(config["thresholds"]["repeated_target_count"])
    target = clean_text(row.get("target_key", ""))
    if not target:
        return False
    whitelist = [str(x).lower() for x in config.get("repeat_target_whitelist", [])]
    target_lower = target.lower()
    if any(target_lower == item or target_lower.endswith("." + item) for item in whitelist):
        return False
    return int(row.get("same_src_target_count", 0)) >= threshold


def hit_unknown_terminal_external(row: pd.Series, config: dict) -> bool:
    terminal = clean_text(row.get("terminal_type", ""))
    if not terminal or ("未知" not in terminal and "unknown" not in terminal.lower()):
        return False
    url = clean_text(row.get("detail_url", "")).lower()
    domain = clean_text(row.get("detail_domain", "")).lower()
    # 仅在缺乏正常域名/URL上下文、且直接对外访问公网IP时触发，避免把普通浏览日志全部打成异常
    if url or domain:
        return False
    if config.get("public_ip_only", True):
        dst_ip = clean_text(row.get("dst_ip_norm", ""))
        return is_public_ip(dst_ip)
    return True


def hit_suspicious_domain_keyword(row: pd.Series, config: dict) -> bool:
    domain = clean_text(row.get("detail_domain", "")).lower()
    url = clean_text(row.get("detail_url", "")).lower()
    text = f"{domain} {url}"
    if not text.strip():
        return False
    return any(k.lower() in text for k in config.get("suspicious_domain_keywords", []))


def hit_external_ip_direct_access(row: pd.Series) -> bool:
    dst_ip = clean_text(row.get("dst_ip_norm", ""))
    domain = clean_text(row.get("detail_domain", ""))
    if domain:
        return False
    return is_public_ip(dst_ip)


def apply_rules(row: pd.Series, config: dict) -> list[dict]:
    rules: list[dict] = []

    if hit_off_hours(row, config):
        rules.append({"rule": "OFF_HOURS_ACCESS", "weight": 15, "reason": "非工作时间访问"})
    if hit_risky_download(row, config):
        rules.append({"rule": "RISKY_FILE_DOWNLOAD", "weight": 30, "reason": "疑似下载可执行/压缩文件"})
    if hit_plain_http(row):
        rules.append({"rule": "PLAINTEXT_HTTP", "weight": 10, "reason": "使用HTTP明文访问"})
    if hit_repeated_target(row, config):
        rules.append({"rule": "REPEATED_SAME_TARGET", "weight": 20, "reason": "同源IP短时间重复访问同一目标"})
    if hit_unknown_terminal_external(row, config):
        rules.append({"rule": "UNKNOWN_TERMINAL_EXTERNAL", "weight": 10, "reason": "未知终端类型对外访问"})
    if hit_suspicious_domain_keyword(row, config):
        rules.append({"rule": "SUSPICIOUS_DOMAIN_KEYWORD", "weight": 25, "reason": "域名/URL包含可疑关键词"})
    if hit_external_ip_direct_access(row):
        rules.append({"rule": "EXTERNAL_IP_DIRECT_ACCESS", "weight": 15, "reason": "直接访问公网IP且无域名上下文"})

    return rules
