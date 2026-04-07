from __future__ import annotations

IOC_FIELD_WEIGHTS = {
    "src_ip": 70,
    "dst_ip": 70,
    "domain": 60,
    "url": 80,
}


def score_hits(ioc_hits: list[dict], rule_hits: list[dict], config: dict) -> tuple[int, str]:
    score = 0
    for hit in ioc_hits:
        score += IOC_FIELD_WEIGHTS.get(hit.get("matched_field", ""), 50)
    for rule in rule_hits:
        score += int(rule.get("weight", 0))

    if score >= int(config["thresholds"]["high_risk_score"]):
        return score, "High"
    if score >= int(config["thresholds"]["medium_risk_score"]):
        return score, "Medium"
    return score, "Low"
