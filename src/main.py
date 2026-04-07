from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from header_mapper import resolve_columns
from loader import load_yaml, read_ioc_table, read_log_table
from matcher import build_ioc_sets, match_row
from normalizer import extract_detail_fields, normalize_domain, normalize_ip, normalize_url
from reporter import save_results
from rules_engine import add_group_features, apply_rules
from scorer import score_hits


CANONICAL_REQUIRED = ["src_ip", "dst_ip", "time"]
OPTIONAL_FIELDS = ["detail", "domain", "url", "username", "app_type", "app_name", "action", "terminal_type", "location", "row_id"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="上网行为日志威胁初筛工具 V2")
    parser.add_argument("--log", required=True, help="日志 CSV/XLSX 路径")
    parser.add_argument("--ioc", default=None, help="IOC Excel/CSV 路径，可不传")
    parser.add_argument("--output-dir", default="output", help="输出目录")
    parser.add_argument("--skiprows", type=int, default=None, help="手动指定 CSV 跳过行数")
    parser.add_argument("--no-auto-skiprows", action="store_true", help="关闭 CSV 表头自动识别")
    parser.add_argument("--rules", default="config/rules.yaml", help="规则配置路径")
    parser.add_argument("--fields", default="config/fields.yaml", help="字段配置路径")
    parser.add_argument("--aliases", default="config/header_aliases.yaml", help="表头别名配置路径")

    parser.add_argument("--src-ip-col", default=None)
    parser.add_argument("--dst-ip-col", default=None)
    parser.add_argument("--time-col", default=None)
    parser.add_argument("--detail-col", default=None)
    parser.add_argument("--domain-col", default=None)
    parser.add_argument("--url-col", default=None)
    parser.add_argument("--username-col", default=None)
    parser.add_argument("--app-type-col", default=None)
    parser.add_argument("--app-name-col", default=None)
    parser.add_argument("--action-col", default=None)
    parser.add_argument("--terminal-type-col", default=None)
    parser.add_argument("--location-col", default=None)
    parser.add_argument("--row-id-col", default=None)
    return parser.parse_args()


def build_overrides(args: argparse.Namespace) -> dict:
    return {
        "src_ip": args.src_ip_col,
        "dst_ip": args.dst_ip_col,
        "time": args.time_col,
        "detail": args.detail_col,
        "domain": args.domain_col,
        "url": args.url_col,
        "username": args.username_col,
        "app_type": args.app_type_col,
        "app_name": args.app_name_col,
        "action": args.action_col,
        "terminal_type": args.terminal_type_col,
        "location": args.location_col,
        "row_id": args.row_id_col,
    }


def build_canonical_df(raw_df: pd.DataFrame, mapping: dict[str, str]) -> pd.DataFrame:
    df = pd.DataFrame(index=raw_df.index)

    # required
    df["src_ip_norm"] = raw_df[mapping["src_ip"]].apply(normalize_ip)
    df["dst_ip_norm"] = raw_df[mapping["dst_ip"]].apply(normalize_ip)
    df["event_time"] = pd.to_datetime(raw_df[mapping["time"]], errors="coerce")

    # optional direct columns
    for canonical in ["username", "app_type", "app_name", "action", "terminal_type", "location", "row_id"]:
        if canonical in mapping:
            df[canonical] = raw_df[mapping[canonical]].astype(str)
        else:
            df[canonical] = ""

    # detail / domain / url
    if "detail" in mapping:
        detail_expanded = raw_df[mapping["detail"]].apply(extract_detail_fields).apply(pd.Series)
        detail_expanded["detail_domain"] = detail_expanded["detail_domain"].apply(normalize_domain)
        detail_expanded["detail_url"] = detail_expanded["detail_url"].apply(normalize_url)
        df = pd.concat([df, detail_expanded], axis=1)
    else:
        df["detail_domain"] = ""
        df["detail_url"] = ""
        df["src_port"] = None
        df["dst_port"] = None
        df["protocol"] = ""
        df["download_file"] = ""

    if "domain" in mapping:
        direct_domain = raw_df[mapping["domain"]].apply(normalize_domain)
        df["detail_domain"] = df["detail_domain"].where(df["detail_domain"] != "", direct_domain)

    if "url" in mapping:
        direct_url = raw_df[mapping["url"]].apply(normalize_url)
        df["detail_url"] = df["detail_url"].where(df["detail_url"] != "", direct_url)
        need_domain = df["detail_domain"] == ""
        df.loc[need_domain, "detail_domain"] = df.loc[need_domain, "detail_url"].apply(normalize_domain)

    if "row_id" not in mapping:
        df["row_id"] = [i + 1 for i in range(len(df))]

    return df


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parent.parent

    rules_cfg = load_yaml(project_root / args.rules)
    fields_cfg = load_yaml(project_root / args.fields)
    aliases_cfg = load_yaml(project_root / args.aliases)

    raw_log_df, used_skiprows = read_log_table(
        args.log,
        aliases=aliases_cfg["log"],
        skiprows=args.skiprows,
        auto_detect_skiprows=not args.no_auto_skiprows,
    )
    ioc_df = read_ioc_table(args.ioc)

    overrides = build_overrides(args)
    resolver = resolve_columns(
        raw_log_df,
        aliases=aliases_cfg["log"],
        exact_fields=fields_cfg.get("log", {}),
        overrides=overrides,
        required_fields=CANONICAL_REQUIRED,
    )
    if resolver.missing_required:
        raise ValueError(f"缺少必需字段映射: {resolver.missing_required}. 请检查表头或使用 --xxx-col 手动指定。")

    df = build_canonical_df(raw_log_df, resolver.mapping)
    df = add_group_features(df)

    ioc_bundle = build_ioc_sets(ioc_df, fields_cfg.get("ioc", {}), aliases_cfg.get("ioc", {}))

    all_ioc_hits = []
    all_rule_hits = []
    scores = []
    levels = []
    matched_iocs_text = []
    matched_rules_text = []
    review_advice = []
    rule_names = []

    for _, row in df.iterrows():
        ioc_hits = match_row(row, ioc_bundle)
        rule_hits = apply_rules(row, rules_cfg)
        score, level = score_hits(ioc_hits, rule_hits, rules_cfg)

        ioc_texts = []
        for hit in ioc_hits:
            category = f"[{hit.get('category')}]" if hit.get("category") else ""
            ioc_texts.append(f"{hit.get('matched_field')}:{hit.get('ioc_value')}{category}")

        rule_texts = [f"{r['rule']}({r['reason']})" for r in rule_hits]

        advice_parts = []
        suggestions = [h.get("suggestion", "") for h in ioc_hits if h.get("suggestion")]
        if suggestions:
            advice_parts.extend(sorted(set(suggestions)))
        if level == "High":
            advice_parts.append("建议优先联动终端/边界设备进行人工复核")
        elif level == "Medium":
            advice_parts.append("建议结合业务白名单与访问上下文做人工确认")
        else:
            advice_parts.append("建议保留观察")

        all_ioc_hits.append(ioc_hits)
        all_rule_hits.append(rule_hits)
        scores.append(score)
        levels.append(level)
        matched_iocs_text.append("; ".join(ioc_texts))
        matched_rules_text.append("; ".join(rule_texts))
        review_advice.append("；".join(dict.fromkeys(advice_parts)))
        rule_names.append([r["rule"] for r in rule_hits])

    df["ioc_hit_count"] = [len(x) for x in all_ioc_hits]
    df["rule_hit_count"] = [len(x) for x in all_rule_hits]
    df["risk_score"] = scores
    df["risk_level"] = levels
    df["matched_iocs"] = matched_iocs_text
    df["matched_rules"] = matched_rules_text
    df["review_advice"] = review_advice
    df["rule_names"] = rule_names

    output_dir = project_root / args.output_dir
    csv_path, report_path = save_results(df, output_dir)

    print(f"[+] Loaded {len(df)} log rows")
    print(f"[+] Loaded {len(ioc_df)} IOC entries")
    print(f"[+] Used skiprows: {used_skiprows}")
    print(f"[+] Resolved columns: {resolver.mapping}")
    print(f"[+] IOC hits: {(df['ioc_hit_count'] > 0).sum()}")
    print(f"[+] Rule hits: {(df['rule_hit_count'] > 0).sum()}")
    print(f"[+] High risk: {(df['risk_level'] == 'High').sum()}")
    print(f"[+] Medium risk: {(df['risk_level'] == 'Medium').sum()}")
    print(f"[+] Results saved to {csv_path}")
    print(f"[+] Report saved to {report_path}")


if __name__ == "__main__":
    main()
