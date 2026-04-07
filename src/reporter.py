from __future__ import annotations

from collections import Counter
from pathlib import Path

import pandas as pd


def save_results(df: pd.DataFrame, output_dir: str | Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    export_candidates = [
        "row_id", "username", "src_ip_norm", "dst_ip_norm", "detail_domain", "detail_url",
        "app_type", "app_name", "action", "terminal_type", "location", "event_time",
        "ioc_hit_count", "rule_hit_count", "risk_score", "risk_level", "matched_iocs",
        "matched_rules", "review_advice",
    ]
    existing = [c for c in export_candidates if c in df.columns]
    csv_path = output_dir / "results.csv"
    df[existing].to_csv(csv_path, index=False, encoding="utf-8-sig")

    report_path = output_dir / "report.md"
    high_df = df[df["risk_level"] == "High"].sort_values(["risk_score", "ioc_hit_count"], ascending=False)
    medium_df = df[df["risk_level"] == "Medium"].sort_values(["risk_score", "ioc_hit_count"], ascending=False)
    rule_counter = Counter(rule for rules in df["rule_names"] for rule in rules)

    lines = [
        "# 上网行为日志威胁初筛报告（V2）",
        "",
        "## 一、总体情况",
        "",
        f"- 日志总量：{len(df)}",
        f"- IOC命中行数：{int((df['ioc_hit_count'] > 0).sum())}",
        f"- 规则命中行数：{int((df['rule_hit_count'] > 0).sum())}",
        f"- High：{int((df['risk_level'] == 'High').sum())}",
        f"- Medium：{int((df['risk_level'] == 'Medium').sum())}",
        f"- Low：{int((df['risk_level'] == 'Low').sum())}",
        "",
        "## 二、规则命中统计",
        "",
    ]

    if rule_counter:
        for rule, count in rule_counter.most_common():
            lines.append(f"- {rule}: {count}")
    else:
        lines.append("- 本次未命中任何异常规则")

    lines.extend([
        "",
        "## 三、高风险样本 Top 10",
        "",
    ])

    if high_df.empty:
        lines.append("- 本次未发现高风险样本")
    else:
        for _, row in high_df.head(10).iterrows():
            lines.append(
                f"- 行 {row.get('row_id', '')} | 用户 {row.get('username', '')} | "
                f"源IP {row.get('src_ip_norm', '')} -> 目标 {row.get('detail_domain', '') or row.get('dst_ip_norm', '')} | "
                f"评分 {row.get('risk_score', 0)} | 命中IOC {row.get('matched_iocs', '')} | 规则 {row.get('matched_rules', '')}"
            )

    lines.extend([
        "",
        "## 四、人工复核建议",
        "",
    ])

    if high_df.empty and medium_df.empty:
        lines.append("- 本次未发现需重点复核的高/中风险样本，可保留结果并持续观察。")
    else:
        lines.append("- 优先核查 High 风险样本对应终端、访问上下文、下载行为及是否存在终端告警。")
        lines.append("- 对 Medium 风险样本结合业务背景、白名单、时间特征进行人工判定。")
        lines.append("- 对规则命中但未命中 IOC 的样本，建议与代理、防火墙、终端日志做交叉验证。")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return csv_path, report_path
