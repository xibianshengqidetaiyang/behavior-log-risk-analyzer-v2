from __future__ import annotations

from collections import defaultdict

import pandas as pd

from normalizer import normalize_domain, normalize_ip, normalize_url


def build_ioc_sets(ioc_df: pd.DataFrame, ioc_fields: dict, ioc_aliases: dict) -> dict:
    if ioc_df.empty:
        return {"sets": {"ipv4": set(), "domain": set(), "url": set(), "other": set()}, "meta": {}}

    def pick_col(key: str) -> str | None:
        preferred = ioc_fields.get(key)
        candidates = []
        if preferred:
            candidates.append(preferred)
        candidates.extend(ioc_aliases.get(key, []))
        norm_cols = {str(c).strip().lower(): c for c in ioc_df.columns}
        for cand in candidates:
            if cand in ioc_df.columns:
                return cand
            if str(cand).strip().lower() in norm_cols:
                return norm_cols[str(cand).strip().lower()]
        return None

    type_col = pick_col("type")
    value_col = pick_col("value")
    category_col = pick_col("category")
    suggestion_col = pick_col("suggestion")

    if not value_col:
        return {"sets": {"ipv4": set(), "domain": set(), "url": set(), "other": set()}, "meta": {}}

    ioc_sets = {"ipv4": set(), "domain": set(), "url": set(), "other": set()}
    meta = defaultdict(list)

    for _, row in ioc_df.iterrows():
        ioc_type = str(row.get(type_col, "")).strip().lower() if type_col else ""
        raw_value = row.get(value_col, "")
        category = row.get(category_col, "") if category_col else ""
        suggestion = row.get(suggestion_col, "") if suggestion_col else ""

        if ioc_type in {"ipv4", "ip", "ip地址", "ipv6"}:
            value = normalize_ip(raw_value)
            bucket = "ipv4"
        elif ioc_type in {"domain", "域名"}:
            value = normalize_domain(raw_value)
            bucket = "domain"
        elif ioc_type in {"url", "链接"}:
            value = normalize_url(raw_value)
            bucket = "url"
        else:
            raw_text = str(raw_value).strip()
            if raw_text.startswith("http://") or raw_text.startswith("https://"):
                value = normalize_url(raw_text)
                bucket = "url"
            elif "." in raw_text and not raw_text.replace(".", "").isdigit():
                value = normalize_domain(raw_text)
                bucket = "domain"
            else:
                value = normalize_ip(raw_text)
                bucket = "ipv4" if value and value[0].isdigit() else "other"

        if not value:
            continue

        ioc_sets[bucket].add(value)
        meta[value].append({
            "ioc_type": ioc_type,
            "ioc_value": value,
            "category": str(category).strip(),
            "suggestion": str(suggestion).strip(),
        })

    return {"sets": ioc_sets, "meta": dict(meta)}


def match_row(row: pd.Series, ioc_bundle: dict) -> list[dict]:
    ioc_sets = ioc_bundle["sets"]
    meta = ioc_bundle["meta"]
    hits: list[dict] = []

    checks = [
        ("src_ip", row.get("src_ip_norm", ""), "ipv4"),
        ("dst_ip", row.get("dst_ip_norm", ""), "ipv4"),
        ("domain", row.get("detail_domain", ""), "domain"),
        ("url", row.get("detail_url", ""), "url"),
    ]

    seen = set()
    for field_name, value, bucket in checks:
        if not value:
            continue
        if value in ioc_sets.get(bucket, set()):
            for item in meta.get(value, []):
                key = (field_name, item.get("ioc_value"), item.get("category"))
                if key in seen:
                    continue
                seen.add(key)
                hits.append({"matched_field": field_name, **item})
    return hits
