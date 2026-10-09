from app.cli import anonymize, check_expectations
from app.core.domain import Asset
from app.services.rules import RuleEngine
from app.services.scans import APP_ROOT


def findings():
    asset = Asset(
        resource_id="arn:aws:s3:::secret-name",
        resource_type="s3_bucket",
        account_id="123456789012",
        name="secret-name",
        attributes={"public": True},
    )
    return RuleEngine.from_directory(APP_ROOT / "rules").evaluate([asset])


def test_anonymize_hides_identifiers_but_keeps_rule_ids():
    original = findings()
    hidden = anonymize(original)
    assert [item.rule_id for item in hidden] == [item.rule_id for item in original]
    for item in hidden:
        assert "123456789012" not in item.account_id
        assert "secret-name" not in item.resource_id
        assert item.evidence == {}
    assert original[0].resource_id == "arn:aws:s3:::secret-name"


def test_expectations_report_missing_and_extra_rules():
    missing, unexpected = check_expectations(findings(), {"S3-001", "NET-001"})
    assert missing == {"NET-001"}
    assert unexpected == set()
