from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from app.core.domain import Asset
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
                    "LoadBalancerArn": (
                        "arn:aws:elasticloadbalancing:eu-west-3:111111111111:"
                        "loadbalancer/app/web/123"
                    ),
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


def test_policy_grants_full_admin_detection() -> None:
    from app.scanners.aws_extended import policy_grants_full_admin

    admin = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    listed = {"Statement": {"Effect": "Allow", "Action": ["s3:Get*", "*"], "Resource": ["*"]}}
    scoped = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    conditional = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            }
        ]
    }
    denied = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    assert policy_grants_full_admin(admin) is True
    assert policy_grants_full_admin(listed) is True
    as_text = '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    assert policy_grants_full_admin(as_text) is True
    assert policy_grants_full_admin(scoped) is False
    assert policy_grants_full_admin(conditional) is False
    assert policy_grants_full_admin(denied) is False
    assert policy_grants_full_admin("not json") is False
    assert policy_grants_full_admin(None) is False


def test_wildcard_customer_policy_is_flagged_high() -> None:
    provider, client = provider_with_mock_client()
    policies = Mock()
    policies.paginate.return_value = [
        {
            "Policies": [
                {
                    "Arn": "arn:aws:iam::111111111111:policy/oops",
                    "PolicyName": "oops",
                    "DefaultVersionId": "v1",
                    "AttachmentCount": 2,
                }
            ]
        }
    ]
    client.get_paginator.return_value = policies
    client.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        }
    }
    assets = provider._collect_iam_policies()
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)
    assert {finding.rule_id for finding in findings} == {"IAM-010"}
    policies.paginate.assert_called_once_with(Scope="Local", OnlyAttached=True)


def _asset(resource_type: str, name: str, resource_id: str, **attributes) -> Asset:
    return Asset(
        resource_id=resource_id,
        resource_type=resource_type,
        name=name,
        attributes=attributes,
    )


def test_instance_with_admin_role_via_profile_is_linked_and_flagged() -> None:
    admin_role = _asset("iam_role", "admin-role", "arn:role", administrator_access=True)
    profile = _asset(
        "iam_instance_profile", "web", "arn:profile/web", role_names=["admin-role"]
    )
    exposed = _asset(
        "ec2_instance",
        "i-1",
        "i-1",
        instance_profile_arn="arn:profile/web",
        admin_instance_profile=False,
        public_ip_assigned=True,
        imdsv2_required=True,
        metadata_endpoint_enabled=True,
    )
    private = _asset(
        "ec2_instance",
        "i-2",
        "i-2",
        instance_profile_arn="arn:profile/web",
        admin_instance_profile=False,
        public_ip_assigned=False,
    )
    unrelated = _asset(
        "ec2_instance",
        "i-3",
        "i-3",
        instance_profile_arn=None,
        admin_instance_profile=False,
        public_ip_assigned=True,
    )
    assets = [admin_role, profile, exposed, private, unrelated]
    AwsInventoryProvider._link_instance_privileges(assets)

    assert exposed.context["privileged"] is True
    assert private.attributes["admin_instance_profile"] is True
    assert unrelated.attributes["admin_instance_profile"] is False
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)
    flagged = {(f.rule_id, f.resource_id) for f in findings}
    assert ("EC2-003", "i-1") in flagged
    assert ("EC2-003", "i-2") not in flagged
    assert ("EC2-003", "i-3") not in flagged


def test_certificate_close_to_expiry_is_flagged() -> None:
    provider, client = provider_with_mock_client()
    certificates = Mock()
    certificates.paginate.return_value = [
        {
            "CertificateSummaryList": [
                {"CertificateArn": "arn:soon"},
                {"CertificateArn": "arn:later"},
            ]
        }
    ]
    client.get_paginator.return_value = certificates
    now = datetime.now(UTC)
    details = {
        "arn:soon": {"DomainName": "a.example", "NotAfter": now + timedelta(days=10)},
        "arn:later": {"DomainName": "b.example", "NotAfter": now + timedelta(days=200)},
    }
    client.describe_certificate.side_effect = lambda CertificateArn: {
        "Certificate": details[CertificateArn]
    }
    assets = provider._collect_acm_certificates()
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)
    assert [(f.rule_id, f.resource_id) for f in findings] == [("ACM-001", "arn:soon")]


def test_bucket_acl_public_detection_and_new_iam_rules() -> None:
    provider, client = provider_with_mock_client()
    client.get_bucket_acl.return_value = {
        "Grants": [
            {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}},
        ]
    }
    assert provider._bucket_acl_public(client, "b") is True
    client.get_bucket_acl.return_value = {"Grants": [{"Grantee": {"ID": "owner"}}]}
    assert provider._bucket_acl_public(client, "b") is False

    user = _asset(
        "iam_user",
        "dev",
        "arn:user/dev",
        mfa_enabled=True,
        console_access=True,
        active_access_keys=1,
    )
    findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate([user])
    assert {f.rule_id for f in findings} == {"IAM-008"}
