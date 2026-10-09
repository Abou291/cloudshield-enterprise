import pytest

from app.core.domain import Asset, Severity
from app.services.context import enrich_context, tags_to_dict
from app.services.risk import RiskEngine


def asset(resource_type: str = "s3_bucket", **context) -> Asset:
    return Asset(resource_id="r", resource_type=resource_type, name="r", context=context)


def test_tags_to_dict_accepts_every_aws_shape() -> None:
    assert tags_to_dict([{"Key": "a", "Value": "1"}]) == {"a": "1"}
    assert tags_to_dict([{"key": "a", "value": "1"}]) == {"a": "1"}
    assert tags_to_dict({"a": 1}) == {"a": "1"}
    assert tags_to_dict(None) == {}
    assert tags_to_dict("garbage") == {}


@pytest.mark.parametrize("value", ["prod", "Production", "PRD", "live"])
def test_production_tag_sets_environment_with_provenance(value: str) -> None:
    item = asset(tags={"Environment": value})
    stats = enrich_context([item])
    assert item.context["environment"] == "production"
    assert item.context["context_sources"]["production_asset"] == f"tag Environment={value}"
    assert stats["production"] == 1


@pytest.mark.parametrize("value", ["dev", "staging", "test", ""])
def test_non_production_tag_does_not_mark_production(value: str) -> None:
    item = asset(tags={"env": value})
    enrich_context([item])
    assert "environment" not in item.context


def test_resource_name_is_never_evidence_of_production() -> None:
    item = Asset(resource_id="arn:aws:s3:::prod-bucket", resource_type="s3_bucket", name="prod")
    enrich_context([item])
    assert "environment" not in item.context
    assert not item.context.get("sensitive_data")


@pytest.mark.parametrize(
    "tags",
    [
        {"DataClassification": "Confidential"},
        {"data-classification": "pii"},
        {"contains-pii": "true"},
    ],
)
def test_classification_tags_mark_sensitive_data(tags: dict[str, str]) -> None:
    item = asset(tags=tags)
    enrich_context([item])
    assert item.context["sensitive_data"] is True
    assert item.context["context_sources"]["sensitive_data"].startswith("tag ")


def test_public_classification_is_not_sensitive() -> None:
    item = asset(tags={"DataClassification": "public"})
    enrich_context([item])
    assert not item.context.get("sensitive_data")


@pytest.mark.parametrize("resource_type", ["secret", "rds_instance"])
def test_resource_types_that_hold_data_are_sensitive_by_type(resource_type: str) -> None:
    item = asset(resource_type)
    enrich_context([item])
    assert item.context["sensitive_data"] is True
    assert item.context["context_sources"]["sensitive_data"] == f"resource type {resource_type}"


def test_explicit_declarations_are_never_overwritten() -> None:
    item = asset(environment="development", sensitive_data=False, tags={"Environment": "prod"})
    enrich_context([item])
    assert item.context["environment"] == "development"
    assert item.context["sensitive_data"] is False


def test_enrichment_without_tags_leaves_demo_assets_untouched() -> None:
    item = asset(environment="production", internet_exposed=True, sensitive_data=True)
    before = dict(item.context)
    enrich_context([item])
    assert item.context == before


def test_risk_reasons_show_where_context_came_from() -> None:
    item = asset(tags={"Environment": "prod", "DataClassification": "restricted"})
    enrich_context([item])
    result = RiskEngine().score(Severity.MEDIUM, item, confidence=0.9)
    assert "Production asset +15 (tag Environment=prod)" in result.reasons
    assert "Sensitive data +18 (tag DataClassification=restricted)" in result.reasons
    assert result.score == 20 + 15 + 18 + 9


def test_declared_context_keeps_the_original_reason_text() -> None:
    item = asset(internet_exposed=True)
    result = RiskEngine().score(Severity.LOW, item, confidence=0.5)
    assert "Internet exposure +22" in result.reasons
