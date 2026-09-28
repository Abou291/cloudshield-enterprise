from datetime import UTC, datetime

from botocore.client import BaseClient
from botocore.exceptions import ClientError

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
                inline_wildcard_admin = False
                for policy_page in iam.get_paginator("list_role_policies").paginate(
                    RoleName=role_name
                ):
                    for policy_name in policy_page.get("PolicyNames", []):
                        document = iam.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name,
                        ).get("PolicyDocument", {})
                        if self._policy_allows_wildcard_admin(document):
                            inline_wildcard_admin = True
                assets.append(
                    Asset(
                        resource_id=role["Arn"],
                        resource_type="iam_role",
                        account_id=self.account_id,
                        region="global",
                        name=role_name,
                        attributes={
                            "administrator_access": administrator,
                            "inline_wildcard_admin": inline_wildcard_admin,
                            "max_session_duration": int(
                                role.get("MaxSessionDuration", 3600)
                            ),
                            "service_linked": role.get("Path", "").startswith(
                                "/aws-service-role/"
                            ),
                        },
                        context={"privileged": administrator or inline_wildcard_admin},
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


    def _collect_dynamodb(self) -> list[Asset]:
        dynamodb = self.client("dynamodb")
        assets: list[Asset] = []
        for page in dynamodb.get_paginator("list_tables").paginate():
            for table_name in page.get("TableNames", []):
                table = dynamodb.describe_table(TableName=table_name).get("Table", {})
                backups = dynamodb.describe_continuous_backups(TableName=table_name)
                pitr = (
                    backups.get("ContinuousBackupsDescription", {})
                    .get("PointInTimeRecoveryDescription", {})
                    .get("PointInTimeRecoveryStatus")
                    == "ENABLED"
                )
                sse = table.get("SSEDescription", {})
                assets.append(
                    Asset(
                        resource_id=table.get("TableArn")
                        or f"dynamodb:{self.region}:{table_name}",
                        resource_type="dynamodb_table",
                        account_id=self.account_id,
                        region=self.region,
                        name=table_name,
                        attributes={
                            "point_in_time_recovery": pitr,
                            "sse_status": sse.get("Status", "ENABLED"),
                            "kms_managed": sse.get("SSEType") == "KMS",
                        },
                        context={"sensitive_data": True},
                    )
                )
        return assets

    def _collect_cloudwatch_logs(self) -> list[Asset]:
        logs = self.client("logs")
        assets: list[Asset] = []
        for page in logs.get_paginator("describe_log_groups").paginate():
            for group in page.get("logGroups", []):
                name = group["logGroupName"]
                assets.append(
                    Asset(
                        resource_id=group.get("arn")
                        or f"logs:{self.region}:{name}",
                        resource_type="cloudwatch_log_group",
                        account_id=self.account_id,
                        region=self.region,
                        name=name,
                        attributes={
                            "retention_configured": "retentionInDays" in group,
                            "retention_days": int(group.get("retentionInDays", 0)),
                            "customer_kms_key": bool(group.get("kmsKeyId")),
                        },
                        context={"sensitive_data": True},
                    )
                )
        return assets

    def _collect_sqs(self) -> list[Asset]:
        sqs = self.client("sqs")
        assets: list[Asset] = []
        for page in sqs.get_paginator("list_queues").paginate():
            for queue_url in page.get("QueueUrls", []):
                attributes = sqs.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=[
                        "QueueArn",
                        "KmsMasterKeyId",
                        "SqsManagedSseEnabled",
                    ],
                ).get("Attributes", {})
                encrypted = bool(attributes.get("KmsMasterKeyId")) or (
                    attributes.get("SqsManagedSseEnabled", "").lower() == "true"
                )
                arn = attributes.get("QueueArn", queue_url)
                assets.append(
                    Asset(
                        resource_id=arn,
                        resource_type="sqs_queue",
                        account_id=self.account_id,
                        region=self.region,
                        name=queue_url.rsplit("/", 1)[-1],
                        attributes={
                            "encrypted_at_rest": encrypted,
                            "customer_kms_key": bool(attributes.get("KmsMasterKeyId")),
                        },
                        context={"sensitive_data": True},
                    )
                )
        return assets

    def _collect_sns(self) -> list[Asset]:
        sns = self.client("sns")
        assets: list[Asset] = []
        for page in sns.get_paginator("list_topics").paginate():
            for topic in page.get("Topics", []):
                arn = topic["TopicArn"]
                attributes = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
                assets.append(
                    Asset(
                        resource_id=arn,
                        resource_type="sns_topic",
                        account_id=self.account_id,
                        region=self.region,
                        name=arn.rsplit(":", 1)[-1],
                        attributes={
                            "encrypted_at_rest": bool(attributes.get("KmsMasterKeyId")),
                            "customer_kms_key": bool(attributes.get("KmsMasterKeyId")),
                        },
                        context={"sensitive_data": True},
                    )
                )
        return assets


    def _collect_inspector2(self) -> list[Asset]:
        inspector = self.client("inspector2")
        response = inspector.batch_get_account_status(accountIds=[self.account_id])
        accounts = response.get("accounts", [])
        account = accounts[0] if accounts else {}
        status = str(account.get("status", "DISABLED")).upper()
        resource_state = account.get("resourceState", {})
        enabled_resources = sorted(
            key
            for key, value in resource_state.items()
            if isinstance(value, dict)
            and str(value.get("status", "")).upper() == "ENABLED"
        )
        return [
            Asset(
                resource_id=f"inspector2:{self.account_id}:{self.region}",
                resource_type="inspector_account",
                account_id=self.account_id,
                region=self.region,
                name="Amazon Inspector",
                attributes={
                    "enabled": status == "ENABLED",
                    "status": status,
                    "enabled_resource_types": enabled_resources,
                },
            )
        ]

    def _collect_macie(self) -> list[Asset]:
        macie = self.client("macie2")
        try:
            session = macie.get_macie_session()
            status = str(session.get("status", "DISABLED")).upper()
            frequency = session.get("findingPublishingFrequency")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            status = "DISABLED"
            frequency = None
        return [
            Asset(
                resource_id=f"macie:{self.account_id}:{self.region}",
                resource_type="macie_account",
                account_id=self.account_id,
                region=self.region,
                name="Amazon Macie",
                attributes={
                    "enabled": status == "ENABLED",
                    "status": status,
                    "finding_publishing_frequency": frequency,
                },
            )
        ]

    def _collect_backup(self) -> list[Asset]:
        backup = self.client("backup")
        plans: list[dict] = []
        for page in backup.get_paginator("list_backup_plans").paginate(
            IncludeDeleted=False
        ):
            plans.extend(page.get("BackupPlansList", []))
        return [
            Asset(
                resource_id=f"aws-backup:{self.account_id}:{self.region}",
                resource_type="backup_account",
                account_id=self.account_id,
                region=self.region,
                name="AWS Backup",
                attributes={
                    "active_plan_count": len(plans),
                    "has_active_plan": bool(plans),
                    "plan_names": sorted(
                        str(plan.get("BackupPlanName", "unnamed")) for plan in plans
                    ),
                },
            )
        ]


    def _collect_access_analyzer(self) -> list[Asset]:
        analyzer = self.client("accessanalyzer")
        analyzers: list[dict] = []
        token: str | None = None
        while True:
            kwargs = {"nextToken": token} if token else {}
            response = analyzer.list_analyzers(**kwargs)
            analyzers.extend(response.get("analyzers", []))
            token = response.get("nextToken")
            if not token:
                break
        active = [
            item for item in analyzers if str(item.get("status", "")).upper() == "ACTIVE"
        ]
        return [
            Asset(
                resource_id=f"access-analyzer:{self.account_id}:{self.region}",
                resource_type="access_analyzer",
                account_id=self.account_id,
                region=self.region,
                name="IAM Access Analyzer",
                attributes={
                    "enabled": bool(active),
                    "active_analyzer_count": len(active),
                    "analyzer_types": sorted(
                        {
                            str(item.get("type", "UNKNOWN"))
                            for item in active
                        }
                    ),
                },
            )
        ]

    def _collect_ebs_snapshots(self) -> list[Asset]:
        ec2 = self.client("ec2")
        assets: list[Asset] = []
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            for snapshot in page.get("Snapshots", []):
                snapshot_id = snapshot["SnapshotId"]
                permissions = ec2.describe_snapshot_attribute(
                    SnapshotId=snapshot_id,
                    Attribute="createVolumePermission",
                ).get("CreateVolumePermissions", [])
                public = any(
                    permission.get("Group") == "all" for permission in permissions
                )
                assets.append(
                    Asset(
                        resource_id=snapshot_id,
                        resource_type="ebs_snapshot",
                        account_id=self.account_id,
                        region=self.region,
                        name=snapshot_id,
                        attributes={
                            "public": public,
                            "encrypted": bool(snapshot.get("Encrypted", False)),
                        },
                        context={"internet_exposed": public, "sensitive_data": True},
                    )
                )
        return assets

    def _collect_rds_snapshots(self) -> list[Asset]:
        rds = self.client("rds")
        assets: list[Asset] = []
        for page in rds.get_paginator("describe_db_snapshots").paginate(
            SnapshotType="manual"
        ):
            for snapshot in page.get("DBSnapshots", []):
                identifier = snapshot["DBSnapshotIdentifier"]
                response = rds.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=identifier
                )
                attributes = response.get("DBSnapshotAttributesResult", {}).get(
                    "DBSnapshotAttributes", []
                )
                public = any(
                    item.get("AttributeName") == "restore"
                    and "all" in item.get("AttributeValues", [])
                    for item in attributes
                )
                assets.append(
                    Asset(
                        resource_id=snapshot.get("DBSnapshotArn") or identifier,
                        resource_type="rds_snapshot",
                        account_id=self.account_id,
                        region=self.region,
                        name=identifier,
                        attributes={
                            "public": public,
                            "encrypted": bool(snapshot.get("Encrypted", False)),
                        },
                        context={"internet_exposed": public, "sensitive_data": True},
                    )
                )
        return assets
