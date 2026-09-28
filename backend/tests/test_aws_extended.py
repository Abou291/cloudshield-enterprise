from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from app.scanners.aws import AwsInventoryProvider
from app.services.rules import RuleEngine
from app.services.scans import APP_ROOT


def provider_with_mock_client() -> tuple[AwsInventoryProvider, Mock]:
    provider = AwsInventoryProvider.__new__(AwsInventoryProvider)
    provider.account_id = "111111111111"
    provider.region = "eu-west-3"
    client = Mock()
    provider.client = Mock(return_value=client)
    return provider, client


def test_iam_admin_role_collected_and_flagged() -> None:
    provider, client = provider_with_mock_client()
    roles = Mock()
    attached = Mock()
    roles.paginate.return_value = [
        {
            "Roles": [
                {
                    "RoleName": "admin-role",
                    "Arn": "arn:aws:iam::111111111111:role/admin-role",
                    "Path": "/",
                    "MaxSessionDuration": 3600,
                }
            ]
        }
    ]
    attached.paginate.return_value = [
        {
            "AttachedPolicies": [
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                }
            ]
        }
    ]

    def paginator(operation: str) -> Mock:
        return roles if operation == "list_roles" else attached

    client.get_paginator.side_effect = paginator
    assets = provider._collect_iam_roles()
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)

    assert assets[0].attributes["administrator_access"] is True
    assert {finding.rule_id for finding in findings} == {"IAM-007"}


def test_ec2_imdsv2_not_required_is_flagged() -> None:
    provider, client = provider_with_mock_client()
    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1234567890abcdef0",
                            "PublicIpAddress": "203.0.113.10",
                            "MetadataOptions": {
                                "HttpEndpoint": "enabled",
                                "HttpTokens": "optional",
                            },
                            "State": {"Name": "running"},
                        }
                    ]
                }
            ]
        }
    ]
    client.get_paginator.return_value = paginator

    assets = provider._collect_ec2_instances()
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)

    assert assets[0].context["internet_exposed"] is True
    assert {finding.rule_id for finding in findings} == {"EC2-001"}


def test_ecr_scan_on_push_disabled_is_flagged() -> None:
    provider, client = provider_with_mock_client()
    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "repositories": [
                {
                    "repositoryArn": "arn:aws:ecr:eu-west-3:111111111111:repository/app",
                    "repositoryName": "app",
                    "imageScanningConfiguration": {"scanOnPush": False},
                    "encryptionConfiguration": {"encryptionType": "AES256"},
                }
            ]
        }
    ]
    client.get_paginator.return_value = paginator

    assets = provider._collect_ecr()
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)

    assert assets[0].attributes["scan_on_push"] is False
    assert {finding.rule_id for finding in findings} == {"ECR-001"}


def test_old_secret_without_rotation_is_flagged() -> None:
    provider, client = provider_with_mock_client()
    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "SecretList": [
                {
                    "ARN": "arn:aws:secretsmanager:eu-west-3:111111111111:secret:db",
                    "Name": "db",
                    "RotationEnabled": False,
                    "LastChangedDate": datetime.now(UTC) - timedelta(days=365),
                }
            ]
        }
    ]
    client.get_paginator.return_value = paginator

    assets = provider._collect_secrets_manager()
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)

    assert assets[0].attributes["age_since_change_days"] >= 364
    assert {finding.rule_id for finding in findings} == {"SEC-001"}


def test_public_eks_endpoint_and_missing_audit_logs_are_flagged() -> None:
    provider, client = provider_with_mock_client()
    paginator = Mock()
    paginator.paginate.return_value = [{"clusters": ["prod"]}]
    client.get_paginator.return_value = paginator
    client.describe_cluster.return_value = {
        "cluster": {
            "name": "prod",
            "arn": "arn:aws:eks:eu-west-3:111111111111:cluster/prod",
            "resourcesVpcConfig": {
                "endpointPublicAccess": True,
                "publicAccessCidrs": ["0.0.0.0/0"],
            },
            "logging": {"clusterLogging": []},
        }
    }

    assets = provider._collect_eks()
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)

    assert assets[0].attributes["public_endpoint_open_world"] is True
    assert {finding.rule_id for finding in findings} == {"EKS-001", "EKS-002"}


def test_internet_load_balancer_without_tls_is_flagged() -> None:
    provider, client = provider_with_mock_client()
    load_balancers = Mock()
    listeners = Mock()
    load_balancers.paginate.return_value = [
        {
            "LoadBalancers": [
                {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-3:111111111111:loadbalancer/app/web/123",
                    "LoadBalancerName": "web",
                    "Scheme": "internet-facing",
                    "Type": "application",
                }
            ]
        }
    ]
    listeners.paginate.return_value = [
        {"Listeners": [{"Protocol": "HTTP", "Port": 80}]}
    ]

    def paginator(operation: str) -> Mock:
        return load_balancers if operation == "describe_load_balancers" else listeners

    client.get_paginator.side_effect = paginator
    assets = provider._collect_load_balancers()
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)

    assert assets[0].attributes["tls_listener"] is False
    assert {finding.rule_id for finding in findings} == {"LB-001"}
