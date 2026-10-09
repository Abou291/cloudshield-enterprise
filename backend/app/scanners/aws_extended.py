import json
from datetime import UTC, datetime

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from app.core.domain import Asset
from app.services.context import tags_to_dict


def policy_grants_full_admin(document: object) -> bool:
    """True when an unconditional Allow statement grants Action * on Resource *."""
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            return False
    if not isinstance(document, dict):
        return False
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    def includes_wildcard(value: object) -> bool:
        return value == "*" or (isinstance(value, list) and "*" in value)

    return any(
        isinstance(statement, dict)
        and statement.get("Effect") == "Allow"
        and not statement.get("Condition")
        and includes_wildcard(statement.get("Action"))
        and includes_wildcard(statement.get("Resource"))
        for statement in statements
    )


class AwsExtendedCollectorsMixin:
    """Additional read-only posture collectors kept separate from the core scanner."""

    account_id: str
    region: str

    def client(self, service: str, region: str | None = None) -> BaseClient:
        raise NotImplementedError

    def _collect_iam_roles(self) -> list[Asset]:
        iam = self.client("iam")
        assets: list[Asset] = []
        for page in iam.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                attached = [
                    policy
                    for policy_page in iam.get_paginator(
                        "list_attached_role_policies"
                    ).paginate(RoleName=role_name)
                    for policy in policy_page.get("AttachedPolicies", [])
                ]
                administrator = any(
                    policy.get("PolicyArn", "").endswith("/AdministratorAccess")
                    for policy in attached
                )
                assets.append(
                    Asset(
                        resource_id=role["Arn"],
                        resource_type="iam_role",
                        account_id=self.account_id,
                        region="global",
                        name=role_name,
                        attributes={
                            "administrator_access": administrator,
                            "max_session_duration": int(
                                role.get("MaxSessionDuration", 3600)
                            ),
                            "service_linked": role.get("Path", "").startswith(
                                "/aws-service-role/"
                            ),
                        },
                        context={"privileged": administrator},
                    )
                )
        return assets

    def _collect_ec2_instances(self) -> list[Asset]:
        ec2 = self.client("ec2")
        assets: list[Asset] = []
        for page in ec2.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    metadata = instance.get("MetadataOptions", {})
                    public = bool(instance.get("PublicIpAddress"))
                    assets.append(
                        Asset(
                            resource_id=instance["InstanceId"],
                            resource_type="ec2_instance",
                            account_id=self.account_id,
                            region=self.region,
                            name=instance["InstanceId"],
                            attributes={
                                "imdsv2_required": metadata.get("HttpTokens")
                                == "required",
                                "metadata_endpoint_enabled": metadata.get(
                                    "HttpEndpoint", "enabled"
                                )
                                == "enabled",
                                "public_ip_assigned": public,
                                "state": instance.get("State", {}).get(
                                    "Name", "unknown"
                                ),
                                "instance_profile_arn": instance.get(
                                    "IamInstanceProfile", {}
                                ).get("Arn"),
                                "admin_instance_profile": False,
                            },
                            context={
                                "internet_exposed": public,
                                "tags": tags_to_dict(instance.get("Tags")),
                            },
                        )
                    )
        return assets

    def _collect_ecr(self) -> list[Asset]:
        ecr = self.client("ecr")
        assets: list[Asset] = []
        for page in ecr.get_paginator("describe_repositories").paginate():
            for repository in page.get("repositories", []):
                scan_config = repository.get("imageScanningConfiguration", {})
                encryption = repository.get("encryptionConfiguration", {})
                assets.append(
                    Asset(
                        resource_id=repository["repositoryArn"],
                        resource_type="ecr_repository",
                        account_id=self.account_id,
                        region=self.region,
                        name=repository["repositoryName"],
                        attributes={
                            "scan_on_push": bool(scan_config.get("scanOnPush", False)),
                            "encryption_type": encryption.get(
                                "encryptionType", "AES256"
                            ),
                        },
                    )
                )
        return assets

    def _collect_secrets_manager(self) -> list[Asset]:
        secrets = self.client("secretsmanager")
        assets: list[Asset] = []
        now = datetime.now(UTC)
        for page in secrets.get_paginator("list_secrets").paginate(
            IncludePlannedDeletion=False
        ):
            for secret in page.get("SecretList", []):
                changed_at = secret.get("LastChangedDate")
                if isinstance(changed_at, datetime) and changed_at.tzinfo is None:
                    changed_at = changed_at.replace(tzinfo=UTC)
                age_days = (
                    max(0, (now - changed_at).days)
                    if isinstance(changed_at, datetime)
                    else 0
                )
                assets.append(
                    Asset(
                        resource_id=secret["ARN"],
                        resource_type="secret",
                        account_id=self.account_id,
                        region=self.region,
                        name=secret.get("Name", secret["ARN"]),
                        attributes={
                            "rotation_enabled": bool(
                                secret.get("RotationEnabled", False)
                            ),
                            "age_since_change_days": age_days,
                            "customer_kms_key": bool(secret.get("KmsKeyId")),
                        },
                        context={
                            "sensitive_data": True,
                            "tags": tags_to_dict(secret.get("Tags")),
                        },
                    )
                )
        return assets

    def _collect_eks(self) -> list[Asset]:
        eks = self.client("eks")
        assets: list[Asset] = []
        for page in eks.get_paginator("list_clusters").paginate():
            for cluster_name in page.get("clusters", []):
                cluster = eks.describe_cluster(name=cluster_name).get("cluster", {})
                network = cluster.get("resourcesVpcConfig", {})
                public_cidrs = network.get("publicAccessCidrs", [])
                public_endpoint = bool(network.get("endpointPublicAccess", False))
                public_open = public_endpoint and any(
                    cidr in {"0.0.0.0/0", "::/0"} for cidr in public_cidrs
                )
                enabled_logs = {
                    log_type
                    for entry in cluster.get("logging", {}).get("clusterLogging", [])
                    if entry.get("enabled")
                    for log_type in entry.get("types", [])
                }
                assets.append(
                    Asset(
                        resource_id=cluster.get("arn")
                        or f"eks:{self.region}:{cluster_name}",
                        resource_type="eks_cluster",
                        account_id=self.account_id,
                        region=self.region,
                        name=cluster_name,
                        attributes={
                            "public_endpoint": public_endpoint,
                            "public_access_cidrs": public_cidrs,
                            "public_endpoint_open_world": public_open,
                            "audit_logging_enabled": "audit" in enabled_logs,
                            "enabled_log_types": sorted(enabled_logs),
                        },
                        context={
                            "internet_exposed": public_open,
                            "tags": tags_to_dict(cluster.get("tags")),
                        },
                    )
                )
        return assets

    def _collect_load_balancers(self) -> list[Asset]:
        elbv2 = self.client("elbv2")
        assets: list[Asset] = []
        for page in elbv2.get_paginator("describe_load_balancers").paginate():
            for load_balancer in page.get("LoadBalancers", []):
                arn = load_balancer["LoadBalancerArn"]
                protocols = {
                    listener.get("Protocol", "")
                    for listener_page in elbv2.get_paginator(
                        "describe_listeners"
                    ).paginate(LoadBalancerArn=arn)
                    for listener in listener_page.get("Listeners", [])
                }
                internet_facing = load_balancer.get("Scheme") == "internet-facing"
                tags = self._load_balancer_tags(elbv2, arn)
                tls_listener = bool(protocols & {"HTTPS", "TLS"})
                assets.append(
                    Asset(
                        resource_id=arn,
                        resource_type="load_balancer",
                        account_id=self.account_id,
                        region=self.region,
                        name=load_balancer.get(
                            "LoadBalancerName", arn.rsplit("/", 1)[-1]
                        ),
                        attributes={
                            "internet_facing": internet_facing,
                            "tls_listener": tls_listener,
                            "listener_protocols": sorted(protocols),
                            "type": load_balancer.get("Type", "unknown"),
                        },
                        context={"internet_exposed": internet_facing, "tags": tags},
                    )
                )
        return assets

    @staticmethod
    def _load_balancer_tags(elbv2: BaseClient, arn: str) -> dict[str, str]:
        """Tags are optional context; a missing permission must not drop the load balancer."""
        denied = {"AccessDenied", "AccessDeniedException"}
        try:
            response = elbv2.describe_tags(ResourceArns=[arn])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in denied:
                return {}
            raise
        descriptions = response.get("TagDescriptions") if isinstance(response, dict) else None
        if not isinstance(descriptions, list) or not descriptions:
            return {}
        return tags_to_dict(descriptions[0].get("Tags"))

    def _collect_iam_policies(self) -> list[Asset]:
        """Attached customer-managed policies, flagging those that grant Action * on Resource *."""
        iam = self.client("iam")
        assets: list[Asset] = []
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for policy in page.get("Policies", []):
                version = iam.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
                ).get("PolicyVersion", {})
                full_admin = policy_grants_full_admin(version.get("Document"))
                assets.append(
                    Asset(
                        resource_id=policy["Arn"],
                        resource_type="iam_policy",
                        account_id=self.account_id,
                        region="global",
                        name=policy.get("PolicyName", policy["Arn"]),
                        attributes={
                            "full_admin": full_admin,
                            "attachment_count": int(policy.get("AttachmentCount", 0)),
                        },
                        context={"privileged": full_admin},
                    )
                )
        return assets

    def _collect_instance_profiles(self) -> list[Asset]:
        iam = self.client("iam")
        assets: list[Asset] = []
        for page in iam.get_paginator("list_instance_profiles").paginate():
            for profile in page.get("InstanceProfiles", []):
                assets.append(
                    Asset(
                        resource_id=profile["Arn"],
                        resource_type="iam_instance_profile",
                        account_id=self.account_id,
                        region="global",
                        name=profile.get("InstanceProfileName", profile["Arn"]),
                        attributes={
                            "role_names": [
                                role["RoleName"] for role in profile.get("Roles", [])
                            ]
                        },
                    )
                )
        return assets

    @staticmethod
    def _link_instance_privileges(assets: list[Asset]) -> None:
        """Mark EC2 instances whose instance profile carries a role with AdministratorAccess."""
        admin_roles = {
            asset.name
            for asset in assets
            if asset.resource_type == "iam_role"
            and asset.attributes.get("administrator_access")
        }
        admin_profiles = {
            asset.resource_id
            for asset in assets
            if asset.resource_type == "iam_instance_profile"
            and admin_roles & set(asset.attributes.get("role_names", []))
        }
        for asset in assets:
            if (
                asset.resource_type == "ec2_instance"
                and asset.attributes.get("instance_profile_arn") in admin_profiles
            ):
                asset.attributes["admin_instance_profile"] = True
                asset.context["privileged"] = True

    def _collect_acm_certificates(self) -> list[Asset]:
        acm = self.client("acm")
        assets: list[Asset] = []
        now = datetime.now(UTC)
        for page in acm.get_paginator("list_certificates").paginate():
            for summary in page.get("CertificateSummaryList", []):
                arn = summary["CertificateArn"]
                detail = acm.describe_certificate(CertificateArn=arn).get("Certificate", {})
                expires = detail.get("NotAfter")
                if not isinstance(expires, datetime):
                    continue
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=UTC)
                assets.append(
                    Asset(
                        resource_id=arn,
                        resource_type="acm_certificate",
                        account_id=self.account_id,
                        region=self.region,
                        name=detail.get("DomainName", arn),
                        attributes={
                            "days_to_expiry": (expires - now).days,
                            "in_use": bool(detail.get("InUseBy")),
                            "imported": detail.get("Type") == "IMPORTED",
                        },
                    )
                )
        return assets
