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
        stub.add_response(
            "list_groups_for_user",
            {"Groups": [], "IsTruncated": False},
            {"UserName": "alice"},
        )
        stub.add_response(
            "list_user_policies",
            {"PolicyNames": [], "IsTruncated": False},
            {"UserName": "alice"},
        )
        assets = provider._collect_iam()
        stub.assert_no_pending_responses()
    assert assets[0].resource_type == "iam_account"
    assert assets[0].attributes["root_mfa_enabled"] is True
    assert assets[1].attributes["administrator_access"] is True
    assert assets[1].attributes["group_administrator_access"] is False
    assert assets[1].attributes["inline_wildcard_admin"] is False
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
            "get_bucket_acl",
            {
                "Owner": {"ID": "owner"},
                "Grants": [
                    {
                        "Grantee": {
                            "Type": "CanonicalUser",
                            "ID": "owner",
                        },
                        "Permission": "FULL_CONTROL",
                    }
                ],
            },
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
            "get_bucket_location", {"LocationConstraint": "EU"}, {"Bucket": "sample-bucket"}
        )
        stub.add_response(
            "get_bucket_versioning",
            {"Status": "Enabled"},
            {"Bucket": "sample-bucket"},
        )
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
        assets = provider._collect_s3()
        stub.assert_no_pending_responses()
    assert len(assets) == 1
    assert assets[0].region == "eu-west-1"
    assert assets[0].attributes == {
        "public": True,
        "public_policy": True,
        "public_acl": False,
        "encrypted": True,
        "logging_enabled": False,
        "versioning_enabled": True,
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


def test_iam_password_policy_missing_collected():
    provider, client = provider_with_client("iam")
    with Stubber(client) as stub:
        stub.add_client_error(
            "get_account_password_policy",
            service_error_code="NoSuchEntity",
        )
        assets = provider._collect_iam_password_policy()
        stub.assert_no_pending_responses()
    assert assets[0].resource_type == "iam_password_policy"
    assert assets[0].attributes["configured"] is False


def test_ebs_default_encryption_disabled_collected():
    provider, client = provider_with_client("ec2")
    with Stubber(client) as stub:
        stub.add_response(
            "get_ebs_encryption_by_default",
            {"EbsEncryptionByDefault": False},
            {},
        )
        assets = provider._collect_ebs_default_encryption()
        stub.assert_no_pending_responses()
    assert assets[0].resource_type == "ebs_account_settings"
    assert assets[0].attributes["encryption_by_default"] is False


def test_vpc_without_flow_logs_collected():
    provider, client = provider_with_client("ec2")
    with Stubber(client) as stub:
        stub.add_response(
            "describe_vpcs",
            {
                "Vpcs": [
                    {
                        "CidrBlock": "10.0.0.0/16",
                        "DhcpOptionsId": "dopt-12345678",
                        "State": "available",
                        "VpcId": "vpc-12345678",
                        "OwnerId": "111111111111",
                        "InstanceTenancy": "default",
                        "IsDefault": False,
                    }
                ]
            },
            {},
        )
        stub.add_response("describe_flow_logs", {"FlowLogs": []}, {})
        assets = provider._collect_vpc_flow_logs()
        stub.assert_no_pending_responses()
    assert assets[0].resource_type == "vpc"
    assert assets[0].attributes["flow_logs_enabled"] is False


def test_securityhub_not_subscribed_collected_as_disabled():
    provider, client = provider_with_client("securityhub")
    with Stubber(client) as stub:
        stub.add_client_error(
            "describe_hub",
            service_error_code="InvalidAccessException",
        )
        assets = provider._collect_securityhub()
        stub.assert_no_pending_responses()
    assert assets[0].resource_type == "securityhub"
    assert assets[0].attributes["enabled"] is False


def test_config_without_recorder_collected_as_disabled():
    provider = AwsInventoryProvider.__new__(AwsInventoryProvider)
    provider.account_id = "111111111111"
    provider.region = "eu-west-3"
    client = Mock()
    client.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": []
    }
    client.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": []
    }
    provider.client = Mock(return_value=client)
    assets = provider._collect_config()
    assert assets[0].resource_type == "aws_config_recorder"
    assert assets[0].attributes["recording"] is False


def test_customer_kms_key_without_rotation_collected():
    provider = AwsInventoryProvider.__new__(AwsInventoryProvider)
    provider.account_id = "111111111111"
    provider.region = "eu-west-3"
    client = Mock()
    paginator = Mock()
    paginator.paginate.return_value = [
        {"Keys": [{"KeyId": "key-1", "KeyArn": "arn:aws:kms:eu-west-3:111111111111:key/key-1"}]}
    ]
    client.get_paginator.return_value = paginator
    client.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "key-1",
            "Arn": "arn:aws:kms:eu-west-3:111111111111:key/key-1",
            "KeyManager": "CUSTOMER",
            "KeyState": "Enabled",
            "KeySpec": "SYMMETRIC_DEFAULT",
        }
    }
    client.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}
    provider.client = Mock(return_value=client)
    assets = provider._collect_kms()
    assert assets[0].resource_type == "kms_key"
    assert assets[0].attributes["rotation_supported"] is True
    assert assets[0].attributes["rotation_enabled"] is False


def test_public_lambda_function_url_collected():
    provider = AwsInventoryProvider.__new__(AwsInventoryProvider)
    provider.account_id = "111111111111"
    provider.region = "eu-west-3"
    client = Mock()
    functions = Mock()
    urls = Mock()
    functions.paginate.return_value = [
        {
            "Functions": [
                {
                    "FunctionName": "public-api",
                    "FunctionArn": "arn:aws:lambda:eu-west-3:111111111111:function:public-api",
                }
            ]
        }
    ]
    urls.paginate.return_value = [
        {
            "FunctionUrlConfigs": [
                {
                    "FunctionUrl": "https://example.lambda-url.eu-west-3.on.aws/",
                    "FunctionArn": "arn:aws:lambda:eu-west-3:111111111111:function:public-api",
                    "AuthType": "NONE",
                }
            ]
        }
    ]

    def paginator_for(operation):
        return functions if operation == "list_functions" else urls

    client.get_paginator.side_effect = paginator_for
    provider.client = Mock(return_value=client)
    assets = provider._collect_lambda_function_urls()
    assert assets[0].resource_type == "lambda_function_url"
    assert assets[0].attributes["public_without_auth"] is True


def test_enabled_region_discovery_is_sorted_and_deduplicated():
    provider = AwsInventoryProvider.__new__(AwsInventoryProvider)
    provider.region = "eu-west-3"
    client = Mock()
    client.describe_regions.return_value = {
        "Regions": [
            {"RegionName": "us-east-1"},
            {"RegionName": "eu-west-3"},
            {"RegionName": "us-east-1"},
        ]
    }
    provider.client = Mock(return_value=client)
    assert provider._enabled_regions() == ["eu-west-3", "us-east-1"]
    client.describe_regions.assert_called_once_with(AllRegions=False)


def test_multi_region_collect_runs_global_once_and_regional_per_region():
    provider = AwsInventoryProvider.__new__(AwsInventoryProvider)
    provider.account_id = "111111111111"
    provider.region = "eu-west-3"
    provider.scan_all_regions = True
    provider._enabled_regions = Mock(return_value=["eu-west-3", "us-east-1"])
    provider._collect_iam = Mock(return_value=[])
    provider._collect_iam_password_policy = Mock(return_value=[])
    provider._collect_iam_roles = Mock(return_value=[])
    provider._collect_s3 = Mock(return_value=[])
    regional_names = [
        "_collect_security_groups",
        "_collect_ec2_instances",
        "_collect_ebs",
        "_collect_ebs_default_encryption",
        "_collect_vpc_flow_logs",
        "_collect_rds",
        "_collect_cloudtrail",
        "_collect_guardduty",
        "_collect_securityhub",
        "_collect_config",
        "_collect_kms",
        "_collect_lambda_function_urls",
        "_collect_ecr",
        "_collect_secrets_manager",
        "_collect_eks",
        "_collect_load_balancers",
        "_collect_dynamodb",
        "_collect_cloudwatch_logs",
        "_collect_sqs",
        "_collect_sns",
        "_collect_inspector2",
        "_collect_macie",
        "_collect_backup",
        "_collect_access_analyzer",
        "_collect_ebs_snapshots",
        "_collect_rds_snapshots",
        "_collect_cloudtrail_security_events",
        "_collect_guardduty_findings",
    ]
    for name in regional_names:
        setattr(provider, name, Mock(return_value=[]))

    assert provider.collect() == []
    provider._collect_iam.assert_called_once()
    provider._collect_iam_password_policy.assert_called_once()
    provider._collect_iam_roles.assert_called_once()
    provider._collect_s3.assert_called_once()
    for name in regional_names:
        assert getattr(provider, name).call_count == 2
    assert provider.region == "eu-west-3"


def test_wildcard_policy_detector_requires_allow_action_and_resource() -> None:
    assert AwsInventoryProvider._policy_allows_wildcard_admin(
        {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    )
    assert not AwsInventoryProvider._policy_allows_wildcard_admin(
        {"Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"}}
    )
    assert not AwsInventoryProvider._policy_allows_wildcard_admin(
        {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}
    )


def test_iam_user_group_and_inline_admin_are_flagged() -> None:
    provider = AwsInventoryProvider.__new__(AwsInventoryProvider)
    provider.account_id = "111111111111"
    provider.region = "eu-west-3"
    iam = Mock()
    provider.client = Mock(return_value=iam)

    paginators = {}
    for operation in [
        "list_users",
        "list_mfa_devices",
        "list_access_keys",
        "list_attached_user_policies",
        "list_groups_for_user",
        "list_attached_group_policies",
        "list_user_policies",
    ]:
        paginators[operation] = Mock()
    paginators["list_users"].paginate.return_value = Mock(
        search=Mock(
            return_value=[
                {
                    "UserName": "alice",
                    "Arn": "arn:aws:iam::111111111111:user/alice",
                }
            ]
        )
    )
    paginators["list_mfa_devices"].paginate.return_value = [
        {"MFADevices": [{"SerialNumber": "mfa"}]}
    ]
    paginators["list_access_keys"].paginate.return_value = [
        {"AccessKeyMetadata": []}
    ]
    paginators["list_attached_user_policies"].paginate.return_value = [
        {"AttachedPolicies": []}
    ]
    paginators["list_groups_for_user"].paginate.return_value = [
        {"Groups": [{"GroupName": "admins"}]}
    ]
    paginators["list_attached_group_policies"].paginate.return_value = [
        {
            "AttachedPolicies": [
                {
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "PolicyName": "AdministratorAccess",
                }
            ]
        }
    ]
    paginators["list_user_policies"].paginate.return_value = [
        {"PolicyNames": ["inline-admin"]}
    ]
    iam.get_paginator.side_effect = lambda operation: paginators[operation]
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
    }
    iam.get_user_policy.return_value = {
        "PolicyDocument": {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
    }

    assets = provider._collect_iam()
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)

    user = next(asset for asset in assets if asset.resource_type == "iam_user")
    assert user.attributes["group_administrator_access"] is True
    assert user.attributes["inline_wildcard_admin"] is True
    assert {"IAM-009", "IAM-010"} <= {finding.rule_id for finding in findings}
