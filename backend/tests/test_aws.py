from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from app.core.domain import Asset
from app.scanners.aws import AwsInventoryProvider
from app.services.rules import RuleEngine
from app.services.scans import APP_ROOT


def provider_with_client(service):
    # Explicit fake credentials prevent any environment/metadata credential discovery.
    session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106
        region_name="eu-west-3",
    )
    client = session.client(service)
    provider = AwsInventoryProvider.__new__(AwsInventoryProvider)
    provider.region = "eu-west-3"
    provider.account_id = "111111111111"
    provider.client = Mock(return_value=client)
    return provider, client


@pytest.mark.parametrize(
    "protocol,lower,upper,expected",
    [
        ("tcp", 20, 25, {"NET-001"}),
        ("6", 1, 65535, {"NET-001", "NET-002"}),
        ("-1", None, None, {"NET-001", "NET-002"}),
        ("udp", 22, 22, set()),
        ("tcp", 443, 443, set()),
        ("tcp", 3389, 3389, {"NET-002"}),
    ],
)
def test_network_port_ranges_and_protocols(protocol, lower, upper, expected):
    provider, client = provider_with_client("ec2")
    permission = {"IpProtocol": protocol, "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    if lower is not None:
        permission.update(FromPort=lower, ToPort=upper)
    with Stubber(client) as stub:
        stub.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-123",
                        "GroupName": "test",
                        "IpPermissions": [permission],
                    }
                ]
            },
            {},
        )
        assets = provider._collect_security_groups()
        stub.assert_no_pending_responses()
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)
    assert {finding.rule_id for finding in findings} == expected


def test_scoped_cidr_does_not_trigger_public_finding():
    asset = Asset(
        resource_id="sg-test",
        resource_type="security_group_rule",
        name="private",
        attributes={"from_port": 22, "source_cidr": "10.0.0.0/8"},
    )
    assert RuleEngine.from_directory(APP_ROOT / "rules").evaluate([asset]) == []


def test_iam_pagination_and_inactive_keys():
    provider, client = provider_with_client("iam")
    now = datetime.now(UTC)
    user = {
        "Path": "/",
        "UserName": "alice",
        "UserId": "A" * 16,
        "Arn": "arn:aws:iam::111111111111:user/alice",
        "CreateDate": now,
    }
    with Stubber(client) as stub:
        stub.add_response(
            "get_account_summary",
            {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
            {},
        )
        stub.add_response("list_users", {"Users": [user], "IsTruncated": False}, {})
        stub.add_response(
            "list_mfa_devices", {"MFADevices": [], "IsTruncated": False}, {"UserName": "alice"}
        )
        stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "alice",
                        "AccessKeyId": "A" * 20,
                        "Status": "Inactive",
                        "CreateDate": now - timedelta(days=400),
                    }
                ],
                "IsTruncated": False,
            },
            {"UserName": "alice"},
        )
        stub.add_response(
            "list_attached_user_policies",
            {"AttachedPolicies": [], "IsTruncated": True, "Marker": "next-page"},
            {"UserName": "alice"},
        )
        stub.add_response(
            "list_attached_user_policies",
            {
                "AttachedPolicies": [
                    {
                        "PolicyName": "AdministratorAccess",
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    }
                ],
                "IsTruncated": False,
            },
            {"UserName": "alice", "Marker": "next-page"},
        )
        assets = provider._collect_iam()
        stub.assert_no_pending_responses()
    assert assets[0].resource_type == "iam_account"
    assert assets[0].attributes["root_mfa_enabled"] is True
    assert assets[1].attributes["administrator_access"] is True
    assert assets[1].attributes["oldest_access_key_days"] == 0


def test_identity_binding_and_external_id(monkeypatch):
    bootstrap = Mock()
    assumed = Mock()
    bootstrap.client.return_value.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "fake",
            "SecretAccessKey": "fake",
            "SessionToken": "fake",
        }
    }
    assumed.client.return_value.get_caller_identity.return_value = {"Account": "222222222222"}
    session_factory = Mock(side_effect=[bootstrap, assumed])
    monkeypatch.setattr("app.scanners.aws.boto3.Session", session_factory)
    with pytest.raises(ValueError, match="does not match"):
        AwsInventoryProvider(
            "eu-west-3",
            "arn:aws:iam::111111111111:role/scanner",
            "external-id-value",
            "111111111111",
            "corp-sso",
        )
    assert session_factory.call_args_list[0].kwargs == {
        "profile_name": "corp-sso",
        "region_name": "eu-west-3",
    }
    bootstrap.client.return_value.assume_role.assert_called_once_with(
        RoleArn="arn:aws:iam::111111111111:role/scanner",
        RoleSessionName="aegisshield-readonly-scan",
        ExternalId="external-id-value",
    )
    assert isinstance(assumed.client.call_args.kwargs["config"], Config)


def test_s3_bucket_pagination_and_region_normalization():
    provider, client = provider_with_client("s3")
    with Stubber(client) as stub:
        stub.add_response("list_buckets", {"Buckets": [], "ContinuationToken": "next"}, {})
        stub.add_response(
            "list_buckets", {"Buckets": [{"Name": "sample-bucket"}]}, {"ContinuationToken": "next"}
        )
        stub.add_response(
            "get_bucket_policy_status",
            {"PolicyStatus": {"IsPublic": True}},
            {"Bucket": "sample-bucket"},
        )
        stub.add_response(
            "get_bucket_encryption",
            {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}],
                }
            },
            {"Bucket": "sample-bucket"},
        )
        stub.add_response("get_bucket_logging", {}, {"Bucket": "sample-bucket"})
        stub.add_response(
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            },
            {"Bucket": "sample-bucket"},
        )
        stub.add_response(
            "get_bucket_location", {"LocationConstraint": "EU"}, {"Bucket": "sample-bucket"}
        )
        assets = provider._collect_s3()
        stub.assert_no_pending_responses()
    assert len(assets) == 1
    assert assets[0].region == "eu-west-1"
    assert assets[0].attributes == {
        "public": True,
        "encrypted": True,
        "logging_enabled": False,
        "block_public_access": True,
    }


@pytest.mark.parametrize(
    "operation,method",
    [
        ("get_bucket_policy_status", "_bucket_public"),
        ("get_bucket_encryption", "_bucket_encrypted"),
    ],
)
def test_s3_access_denied_is_not_treated_as_safe(operation, method):
    provider, client = provider_with_client("s3")
    with Stubber(client) as stub:
        stub.add_client_error(
            operation,
            service_error_code="AccessDenied",
            expected_params={"Bucket": "sample-bucket"},
        )
        with pytest.raises(ClientError):
            getattr(provider, method)(client, "sample-bucket")


def test_optional_service_failure_becomes_coverage_gap():
    provider = AwsInventoryProvider.__new__(AwsInventoryProvider)
    provider.account_id = "111111111111"
    provider.region = "eu-west-3"

    def denied():
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeDBInstances",
        )

    assets = provider._safe_collect("rds", denied)
    assert len(assets) == 1
    assert assets[0].resource_type == "coverage_gap"
    assert assets[0].attributes["reason"] == "AccessDenied"


def test_ebs_unencrypted_volume_collected():
    provider, client = provider_with_client("ec2")
    with Stubber(client) as stub:
        stub.add_response(
            "describe_volumes",
            {
                "Volumes": [
                    {
                        "VolumeId": "vol-1234567890abcdef0",
                        "Size": 8,
                        "SnapshotId": "",
                        "AvailabilityZone": "eu-west-3a",
                        "State": "available",
                        "CreateTime": datetime.now(UTC),
                        "VolumeType": "gp3",
                        "Encrypted": False,
                        "Iops": 3000,
                    }
                ]
            },
            {},
        )
        assets = provider._collect_ebs()
    assert assets[0].resource_type == "ebs_volume"
    assert assets[0].attributes["encrypted"] is False


def test_guardduty_missing_detector_collected_as_disabled():
    provider, client = provider_with_client("guardduty")
    with Stubber(client) as stub:
        stub.add_response("list_detectors", {"DetectorIds": []}, {})
        assets = provider._collect_guardduty()
    assert assets[0].resource_type == "guardduty_detector"
    assert assets[0].attributes["enabled"] is False


def test_cloudtrail_not_logging_collected():
    provider, client = provider_with_client("cloudtrail")
    with Stubber(client) as stub:
        stub.add_response(
            "describe_trails",
            {
                "trailList": [
                    {
                        "Name": "org-trail",
                        "S3BucketName": "logs",
                        "TrailARN": "arn:aws:cloudtrail:eu-west-3:111111111111:trail/org-trail",
                        "LogFileValidationEnabled": False,
                        "IsMultiRegionTrail": False,
                    }
                ]
            },
            {"includeShadowTrails": False},
        )
        stub.add_response(
            "get_trail_status",
            {"IsLogging": False},
            {"Name": "arn:aws:cloudtrail:eu-west-3:111111111111:trail/org-trail"},
        )
        assets = provider._collect_cloudtrail()
    assert assets[0].attributes["logging"] is False
    assert assets[0].attributes["multi_region"] is False
