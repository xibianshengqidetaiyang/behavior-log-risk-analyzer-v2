from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass
class ColumnResolverResult:
    mapping: dict[str, str]
    missing_required: list[str]


def _norm(value: str) -> str:
    return str(value).strip().lower()


def resolve_columns(
    df: pd.DataFrame,
    aliases: dict,
    exact_fields: dict | None = None,
    overrides: dict | None = None,
    required_fields: list[str] | None = None,
) -> ColumnResolverResult:
    exact_fields = exact_fields or {}
    overrides = overrides or {}
    required_fields = required_fields or []

    actual_columns = list(df.columns)
    actual_norm_map = {_norm(c): c for c in actual_columns}
    mapping: dict[str, str] = {}

    for canonical in aliases:
        chosen = None

        override = overrides.get(canonical)
        if override and override in actual_columns:
            chosen = override
        elif override and _norm(override) in actual_norm_map:
            chosen = actual_norm_map[_norm(override)]

        if not chosen:
            exact = exact_fields.get(canonical)
            if exact and exact in actual_columns:
                chosen = exact
            elif exact and _norm(exact) in actual_norm_map:
                chosen = actual_norm_map[_norm(exact)]

        if not chosen:
            for alias in aliases.get(canonical, []):
                if alias in actual_columns:
                    chosen = alias
                    break
                alias_norm = _norm(alias)
                if alias_norm in actual_norm_map:
                    chosen = actual_norm_map[alias_norm]
                    break

        if chosen:
            mapping[canonical] = chosen

    missing_required = [f for f in required_fields if f not in mapping]
    return ColumnResolverResult(mapping=mapping, missing_required=missing_required)
