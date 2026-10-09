"""Derive risk context (environment, data sensitivity) from real AWS signals.

Context drives part of the risk score (production +15, sensitive data +18), so it must
come from evidence rather than assumption. Every value set here records its provenance
in ``asset.context["context_sources"]`` so the score explanation can say *why*.

Policy, in decreasing order of trust:
1. ``tag``      - the customer labelled the resource (Environment=prod, DataClassification=...).
2. ``resource`` - the resource type itself implies the property (a Secrets Manager secret
                  holds secret material; an RDS instance holds application data).
Names are never used as evidence: ``prod-logs`` proves nothing.

Values already present on the asset (set by a collector or a fixture) are never
overwritten, so explicit declarations always win over derived ones.
"""

from collections.abc import Iterable, Mapping
from typing import Any

from app.core.domain import Asset

ENVIRONMENT_TAG_KEYS = frozenset({"environment", "env", "stage", "tier"})
PRODUCTION_VALUES = frozenset({"prod", "production", "prd", "live"})

CLASSIFICATION_TAG_KEYS = frozenset(
    {"dataclassification", "data-classification", "data_classification", "classification"}
)
SENSITIVE_CLASSIFICATIONS = frozenset(
    {"confidential", "restricted", "sensitive", "secret", "pii", "phi", "pci", "personal"}
)
SENSITIVE_FLAG_KEYS = frozenset({"contains-pii", "contains_pii", "containspii", "pii", "phi"})
TRUTHY = frozenset({"true", "yes", "1", "y"})

# Resource types whose very purpose is to hold sensitive material.
SENSITIVE_RESOURCE_TYPES = frozenset({"secret", "rds_instance"})


def tags_to_dict(raw: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None) -> dict[str, str]:
    """Normalise the AWS tag shapes ([{Key,Value}], [{key,value}] or {k: v}) to a dict."""
    if not raw or not isinstance(raw, Mapping | list | tuple):
        return {}
    if isinstance(raw, Mapping):
        return {str(key): str(value) for key, value in raw.items()}
    result: dict[str, str] = {}
    for item in raw:
        key = item.get("Key", item.get("key"))
        if key is not None:
            result[str(key)] = str(item.get("Value", item.get("value", "")))
    return result


def _lookup(tags: Mapping[str, str], keys: frozenset[str]) -> tuple[str, str] | None:
    for key, value in tags.items():
        if key.strip().lower() in keys:
            return key, value.strip()
    return None


def environment_from_tags(tags: Mapping[str, str]) -> tuple[str, str] | None:
    """Return (environment, source) when a tag marks the resource as production."""
    found = _lookup(tags, ENVIRONMENT_TAG_KEYS)
    if found and found[1].lower() in PRODUCTION_VALUES:
        return "production", f"tag {found[0]}={found[1]}"
    return None


def sensitivity_from_tags(tags: Mapping[str, str]) -> str | None:
    """Return a provenance string when a tag marks the resource as holding sensitive data."""
    found = _lookup(tags, CLASSIFICATION_TAG_KEYS)
    if found and found[1].lower() in SENSITIVE_CLASSIFICATIONS:
        return f"tag {found[0]}={found[1]}"
    flag = _lookup(tags, SENSITIVE_FLAG_KEYS)
    if flag and flag[1].lower() in TRUTHY:
        return f"tag {flag[0]}={flag[1]}"
    return None


def enrich_context(assets: list[Asset]) -> dict[str, int]:
    """Fill ``environment`` and ``sensitive_data`` context in place; return coverage counters."""
    stats = {"assets": len(assets), "production": 0, "sensitive_data": 0, "tagged": 0}
    for asset in assets:
        context = asset.context
        tags = tags_to_dict(context.get("tags"))
        if tags:
            stats["tagged"] += 1
        sources: dict[str, str] = dict(context.get("context_sources") or {})

        if "environment" not in context:
            derived = environment_from_tags(tags)
            if derived:
                context["environment"], sources["production_asset"] = derived
        if context.get("environment") == "production":
            stats["production"] += 1

        if "sensitive_data" not in sources:
            tag_source = sensitivity_from_tags(tags)
            if tag_source and context.get("sensitive_data") is not False:
                context["sensitive_data"] = True
                sources["sensitive_data"] = tag_source
            elif (
                asset.resource_type in SENSITIVE_RESOURCE_TYPES
                and context.get("sensitive_data") is not False
            ):
                context["sensitive_data"] = True
                sources["sensitive_data"] = f"resource type {asset.resource_type}"
        if context.get("sensitive_data"):
            stats["sensitive_data"] += 1

        if sources:
            context["context_sources"] = sources
    return stats
