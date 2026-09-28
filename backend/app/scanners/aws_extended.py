from datetime import UTC, datetime

from botocore.client import BaseClient

from app.core.domain import Asset


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
                            },
                            context={"internet_exposed": public},
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
                        context={"sensitive_data": True},
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
                        context={"internet_exposed": public_open},
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
                        context={"internet_exposed": internet_facing},
                    )
                )
        return assets
