from collections.abc import Callable
from datetime import UTC, datetime

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.core.domain import Asset
from app.scanners.aws_extended import AwsExtendedCollectorsMixin


class AwsInventoryProvider(AwsExtendedCollectorsMixin):
    """Read-only AWS collector with fail-soft optional service coverage."""

    def __init__(
        self,
        region: str,
        role_arn: str | None = None,
        external_id: str | None = None,
        expected_account_id: str | None = None,
        profile_name: str | None = None,
        scan_all_regions: bool = False,
    ) -> None:
        self.client_config = Config(
            connect_timeout=5,
            read_timeout=15,
            retries={"mode": "standard", "total_max_attempts": 3},
        )
        session = boto3.Session(profile_name=profile_name, region_name=region)
        if role_arn:
            sts = session.client("sts", config=self.client_config)
            parameters = {
                "RoleArn": role_arn,
                "RoleSessionName": "aegisshield-readonly-scan",
            }
            if external_id:
                parameters["ExternalId"] = external_id
            credentials = sts.assume_role(**parameters)["Credentials"]
            session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=region,
            )
        self.session = session
        self.region = region
        self.scan_all_regions = scan_all_regions
        self.account_id = self.client("sts").get_caller_identity()["Account"]
        if expected_account_id and self.account_id != expected_account_id:
            raise ValueError("AWS identity does not match the configured account")

    def client(self, service: str, region: str | None = None) -> BaseClient:
        return self.session.client(
            service,
            region_name=region or self.region,
            config=self.client_config,
        )

    def collect(self) -> list[Asset]:
        global_collectors: list[tuple[str, Callable[[], list[Asset]]]] = [
            ("iam", self._collect_iam),
            ("iam-password-policy", self._collect_iam_password_policy),
            ("iam-roles", self._collect_iam_roles),
            ("s3", self._collect_s3),
        ]
        regional_collectors: list[tuple[str, Callable[[], list[Asset]]]] = [
            ("ec2-security-groups", self._collect_security_groups),
            ("ec2-instances", self._collect_ec2_instances),
            ("ebs", self._collect_ebs),
            ("ebs-default-encryption", self._collect_ebs_default_encryption),
            ("vpc-flow-logs", self._collect_vpc_flow_logs),
            ("rds", self._collect_rds),
            ("cloudtrail", self._collect_cloudtrail),
            ("guardduty", self._collect_guardduty),
            ("securityhub", self._collect_securityhub),
            ("config", self._collect_config),
            ("kms", self._collect_kms),
            ("lambda-function-urls", self._collect_lambda_function_urls),
            ("ecr", self._collect_ecr),
            ("secrets-manager", self._collect_secrets_manager),
            ("eks", self._collect_eks),
            ("load-balancers", self._collect_load_balancers),
            ("dynamodb", self._collect_dynamodb),
            ("cloudwatch-logs", self._collect_cloudwatch_logs),
            ("sqs", self._collect_sqs),
            ("sns", self._collect_sns),
        ]
        assets: list[Asset] = []
        for service, collector in global_collectors:
            assets.extend(self._safe_collect(service, collector))

        regions = [self.region]
        if self.scan_all_regions:
            try:
                regions = self._enabled_regions()
            except (ClientError, BotoCoreError) as exc:
                assets.extend(self._coverage_gap("region-discovery", exc))

        configured_region = self.region
        try:
            for region in regions:
                self.region = region
                for service, collector in regional_collectors:
                    assets.extend(self._safe_collect(service, collector))
        finally:
            self.region = configured_region
        return assets

    def _enabled_regions(self) -> list[str]:
        response = self.client("ec2").describe_regions(AllRegions=False)
        regions = sorted(
            {
                item["RegionName"]
                for item in response.get("Regions", [])
                if item.get("RegionName")
            }
        )
        return regions or [self.region]

    def _safe_collect(
        self,
        service: str,
        collector: Callable[[], list[Asset]],
    ) -> list[Asset]:
        try:
            return collector()
        except (ClientError, BotoCoreError) as exc:
            return self._coverage_gap(service, exc)

    def _coverage_gap(
        self,
        service: str,
        exc: ClientError | BotoCoreError,
    ) -> list[Asset]:
        reason = type(exc).__name__
        if isinstance(exc, ClientError):
            reason = exc.response.get("Error", {}).get("Code", "ClientError")
        return [
            Asset(
                resource_id=f"coverage:{service}:{self.region}",
                resource_type="coverage_gap",
                account_id=self.account_id,
                region=self.region,
                name=service,
                attributes={"service": service, "reason": reason, "available": False},
            )
        ]

    def _collect_iam(self) -> list[Asset]:
        iam = self.client("iam")
        summary = iam.get_account_summary().get("SummaryMap", {})
        assets: list[Asset] = [
            Asset(
                resource_id=f"arn:aws:iam::{self.account_id}:root",
                resource_type="iam_account",
                account_id=self.account_id,
                region="global",
                name="root",
                attributes={
                    "root_mfa_enabled": bool(summary.get("AccountMFAEnabled", 0)),
                    "root_access_keys_present": bool(
                        summary.get("AccountAccessKeysPresent", 0)
                    ),
                },
                context={"privileged": True},
            )
        ]
        for user in iam.get_paginator("list_users").paginate().search("Users[]"):
            username = user["UserName"]
            mfa_enabled = any(
                page["MFADevices"]
                for page in iam.get_paginator("list_mfa_devices").paginate(
                    UserName=username
                )
            )
            keys = [
                key
                for page in iam.get_paginator("list_access_keys").paginate(
                    UserName=username
                )
                for key in page["AccessKeyMetadata"]
                if key["Status"] == "Active"
            ]
            oldest_key_days = max(
                (
                    (datetime.now(UTC) - key["CreateDate"]).days
                    for key in keys
                ),
                default=0,
            )
            attached = [
                policy
                for page in iam.get_paginator(
                    "list_attached_user_policies"
                ).paginate(UserName=username)
                for policy in page["AttachedPolicies"]
            ]
            administrator = any(
                policy["PolicyArn"].endswith("/AdministratorAccess")
                for policy in attached
            )
            assets.append(
                Asset(
                    resource_id=user["Arn"],
                    resource_type="iam_user",
                    account_id=self.account_id,
                    region="global",
                    name=username,
                    attributes={
                        "mfa_enabled": mfa_enabled,
                        "oldest_access_key_days": oldest_key_days,
                        "administrator_access": administrator,
                    },
                    context={"privileged": administrator},
                )
            )
        return assets

    def _collect_iam_password_policy(self) -> list[Asset]:
        iam = self.client("iam")
        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
            configured = True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
            policy = {}
            configured = False
        return [
            Asset(
                resource_id=f"arn:aws:iam::{self.account_id}:password-policy",
                resource_type="iam_password_policy",
                account_id=self.account_id,
                region="global",
                name="IAM account password policy",
                attributes={
                    "configured": configured,
                    "minimum_length": int(policy.get("MinimumPasswordLength", 0)),
                    "require_symbols": bool(policy.get("RequireSymbols", False)),
                    "require_numbers": bool(policy.get("RequireNumbers", False)),
                    "require_uppercase": bool(policy.get("RequireUppercaseCharacters", False)),
                    "require_lowercase": bool(policy.get("RequireLowercaseCharacters", False)),
                    "max_password_age": int(policy.get("MaxPasswordAge", 0)),
                },
            )
        ]

    def _collect_s3(self) -> list[Asset]:
        s3 = self.client("s3")
        assets: list[Asset] = []
        buckets = (
            bucket
            for page in s3.get_paginator("list_buckets").paginate()
            for bucket in page.get("Buckets", [])
        )
        for bucket in buckets:
            name = bucket["Name"]
            public = self._bucket_public(s3, name)
            encrypted = self._bucket_encrypted(s3, name)
            logging = bool(s3.get_bucket_logging(Bucket=name).get("LoggingEnabled"))
            assets.append(
                Asset(
                    resource_id=f"arn:aws:s3:::{name}",
                    resource_type="s3_bucket",
                    account_id=self.account_id,
                    region=self._bucket_region(s3, name),
                    name=name,
                    attributes={
                        "public": public,
                        "encrypted": encrypted,
                        "logging_enabled": logging,
                        "versioning_enabled": self._bucket_versioning_enabled(s3, name),
                        "block_public_access": self._bucket_public_access_block(
                            s3, name
                        ),
                    },
                    context={"internet_exposed": public},
                )
            )
        return assets

    def _collect_security_groups(self) -> list[Asset]:
        ec2 = self.client("ec2")
        assets: list[Asset] = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for group in page["SecurityGroups"]:
                for permission in group.get("IpPermissions", []):
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")
                    protocol = permission.get("IpProtocol")
                    cidrs = [
                        item["CidrIp"]
                        for item in permission.get("IpRanges", [])
                    ]
                    cidrs += [
                        item["CidrIpv6"]
                        for item in permission.get("Ipv6Ranges", [])
                    ]
                    for cidr in cidrs:
                        assets.append(
                            Asset(
                                resource_id=(
                                    f"{group['GroupId']}:{protocol}:"
                                    f"{from_port}:{to_port}:{cidr}"
                                ),
                                resource_type="security_group_rule",
                                account_id=self.account_id,
                                region=self.region,
                                name=group.get("GroupName", group["GroupId"]),
                                attributes={
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "protocol": protocol,
                                    "source_cidr": cidr,
                                },
                                context={
                                    "internet_exposed": cidr
                                    in {"0.0.0.0/0", "::/0"}
                                },
                            )
                        )
        return assets

    def _collect_ebs(self) -> list[Asset]:
        ec2 = self.client("ec2")
        assets: list[Asset] = []
        for page in ec2.get_paginator("describe_volumes").paginate():
            for volume in page.get("Volumes", []):
                assets.append(
                    Asset(
                        resource_id=volume["VolumeId"],
                        resource_type="ebs_volume",
                        account_id=self.account_id,
                        region=self.region,
                        name=volume["VolumeId"],
                        attributes={
                            "encrypted": bool(volume.get("Encrypted", False)),
                            "state": volume.get("State", "unknown"),
                        },
                    )
                )
        return assets

    def _collect_ebs_default_encryption(self) -> list[Asset]:
        ec2 = self.client("ec2")
        response = ec2.get_ebs_encryption_by_default()
        return [
            Asset(
                resource_id=f"ec2:ebs-default-encryption:{self.region}",
                resource_type="ebs_account_settings",
                account_id=self.account_id,
                region=self.region,
                name="EBS default encryption",
                attributes={
                    "encryption_by_default": bool(
                        response.get("EbsEncryptionByDefault", False)
                    )
                },
            )
        ]

    def _collect_vpc_flow_logs(self) -> list[Asset]:
        ec2 = self.client("ec2")
        vpcs = [
            vpc
            for page in ec2.get_paginator("describe_vpcs").paginate()
            for vpc in page.get("Vpcs", [])
        ]
        if not vpcs:
            return []
        flow_logged_resources = {
            flow_log.get("ResourceId")
            for page in ec2.get_paginator("describe_flow_logs").paginate()
            for flow_log in page.get("FlowLogs", [])
            if flow_log.get("FlowLogStatus", "ACTIVE") == "ACTIVE"
        }
        return [
            Asset(
                resource_id=vpc["VpcId"],
                resource_type="vpc",
                account_id=self.account_id,
                region=self.region,
                name=vpc["VpcId"],
                attributes={
                    "flow_logs_enabled": vpc["VpcId"] in flow_logged_resources,
                    "is_default": bool(vpc.get("IsDefault", False)),
                },
            )
            for vpc in vpcs
        ]

    def _collect_rds(self) -> list[Asset]:
        rds = self.client("rds")
        assets: list[Asset] = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            for database in page.get("DBInstances", []):
                arn = database.get("DBInstanceArn") or database["DBInstanceIdentifier"]
                public = bool(database.get("PubliclyAccessible", False))
                assets.append(
                    Asset(
                        resource_id=arn,
                        resource_type="rds_instance",
                        account_id=self.account_id,
                        region=self.region,
                        name=database["DBInstanceIdentifier"],
                        attributes={
                            "publicly_accessible": public,
                            "storage_encrypted": bool(
                                database.get("StorageEncrypted", False)
                            ),
                            "deletion_protection": bool(
                                database.get("DeletionProtection", False)
                            ),
                            "multi_az": bool(database.get("MultiAZ", False)),
                            "backup_retention_days": int(
                                database.get("BackupRetentionPeriod", 0)
                            ),
                        },
                        context={"internet_exposed": public},
                    )
                )
        return assets

    def _collect_cloudtrail(self) -> list[Asset]:
        cloudtrail = self.client("cloudtrail")
        assets: list[Asset] = []
        trails = cloudtrail.describe_trails(includeShadowTrails=False).get(
            "trailList", []
        )
        if not trails:
            return [
                Asset(
                    resource_id=f"cloudtrail:none:{self.region}",
                    resource_type="cloudtrail",
                    account_id=self.account_id,
                    region=self.region,
                    name="No CloudTrail trail",
                    attributes={
                        "logging": False,
                        "multi_region": False,
                        "log_file_validation": False,
                    },
                )
            ]
        for trail in trails:
            identifier = trail.get("TrailARN") or trail["Name"]
            status = cloudtrail.get_trail_status(Name=identifier)
            assets.append(
                Asset(
                    resource_id=identifier,
                    resource_type="cloudtrail",
                    account_id=self.account_id,
                    region=self.region,
                    name=trail["Name"],
                    attributes={
                        "logging": bool(status.get("IsLogging", False)),
                        "multi_region": bool(
                            trail.get("IsMultiRegionTrail", False)
                        ),
                        "log_file_validation": bool(
                            trail.get("LogFileValidationEnabled", False)
                        ),
                    },
                )
            )
        return assets

    def _collect_guardduty(self) -> list[Asset]:
        guardduty = self.client("guardduty")
        detector_ids: list[str] = []
        token: str | None = None
        while True:
            kwargs = {"NextToken": token} if token else {}
            response = guardduty.list_detectors(**kwargs)
            detector_ids.extend(response.get("DetectorIds", []))
            token = response.get("NextToken")
            if not token:
                break
        if not detector_ids:
            return [
                Asset(
                    resource_id=f"guardduty:none:{self.region}",
                    resource_type="guardduty_detector",
                    account_id=self.account_id,
                    region=self.region,
                    name="GuardDuty",
                    attributes={"enabled": False},
                )
            ]
        assets: list[Asset] = []
        for detector_id in detector_ids:
            detector = guardduty.get_detector(DetectorId=detector_id)
            assets.append(
                Asset(
                    resource_id=f"guardduty:{detector_id}",
                    resource_type="guardduty_detector",
                    account_id=self.account_id,
                    region=self.region,
                    name=detector_id,
                    attributes={
                        "enabled": detector.get("Status") == "ENABLED",
                        "publishing_frequency": detector.get(
                            "FindingPublishingFrequency"
                        ),
                    },
                )
            )
        return assets

    def _collect_securityhub(self) -> list[Asset]:
        securityhub = self.client("securityhub")
        try:
            response = securityhub.describe_hub()
            enabled = bool(response.get("HubArn"))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in {
                "InvalidAccessException",
                "ResourceNotFoundException",
            }:
                raise
            enabled = False
        return [
            Asset(
                resource_id=f"securityhub:{self.region}",
                resource_type="securityhub",
                account_id=self.account_id,
                region=self.region,
                name="AWS Security Hub",
                attributes={"enabled": enabled},
            )
        ]

    def _collect_config(self) -> list[Asset]:
        config = self.client("config")
        recorders = config.describe_configuration_recorders().get(
            "ConfigurationRecorders", []
        )
        statuses = {
            status.get("name"): status
            for status in config.describe_configuration_recorder_status().get(
                "ConfigurationRecordersStatus", []
            )
        }
        if not recorders:
            return [
                Asset(
                    resource_id=f"config:none:{self.region}",
                    resource_type="aws_config_recorder",
                    account_id=self.account_id,
                    region=self.region,
                    name="AWS Config",
                    attributes={"recording": False, "all_supported": False},
                )
            ]
        return [
            Asset(
                resource_id=f"config:{recorder.get('name', 'default')}:{self.region}",
                resource_type="aws_config_recorder",
                account_id=self.account_id,
                region=self.region,
                name=recorder.get("name", "default"),
                attributes={
                    "recording": bool(
                        statuses.get(recorder.get("name"), {}).get(
                            "recording", False
                        )
                    ),
                    "all_supported": bool(
                        recorder.get("recordingGroup", {}).get(
                            "allSupported", False
                        )
                    ),
                },
            )
            for recorder in recorders
        ]

    def _collect_kms(self) -> list[Asset]:
        kms = self.client("kms")
        assets: list[Asset] = []
        for page in kms.get_paginator("list_keys").paginate():
            for key in page.get("Keys", []):
                key_id = key["KeyId"]
                metadata = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                if metadata.get("KeyManager") != "CUSTOMER":
                    continue
                symmetric = metadata.get("KeySpec") == "SYMMETRIC_DEFAULT"
                enabled = metadata.get("KeyState") == "Enabled"
                rotation_supported = symmetric and enabled
                rotation_enabled = False
                if rotation_supported:
                    rotation_enabled = bool(
                        kms.get_key_rotation_status(KeyId=key_id).get(
                            "KeyRotationEnabled", False
                        )
                    )
                assets.append(
                    Asset(
                        resource_id=metadata.get("Arn") or key.get("KeyArn") or key_id,
                        resource_type="kms_key",
                        account_id=self.account_id,
                        region=self.region,
                        name=key_id,
                        attributes={
                            "enabled": enabled,
                            "rotation_supported": rotation_supported,
                            "rotation_enabled": rotation_enabled,
                        },
                    )
                )
        return assets

    def _collect_lambda_function_urls(self) -> list[Asset]:
        lambda_client = self.client("lambda")
        assets: list[Asset] = []
        for page in lambda_client.get_paginator("list_functions").paginate():
            for function in page.get("Functions", []):
                function_name = function["FunctionName"]
                paginator = lambda_client.get_paginator(
                    "list_function_url_configs"
                )
                for url_page in paginator.paginate(FunctionName=function_name):
                    for config in url_page.get("FunctionUrlConfigs", []):
                        public = config.get("AuthType") == "NONE"
                        assets.append(
                            Asset(
                                resource_id=config.get("FunctionUrl")
                                or function.get("FunctionArn")
                                or function_name,
                                resource_type="lambda_function_url",
                                account_id=self.account_id,
                                region=self.region,
                                name=function_name,
                                attributes={
                                    "auth_type": config.get("AuthType"),
                                    "public_without_auth": public,
                                },
                                context={"internet_exposed": public},
                            )
                        )
        return assets

    @staticmethod
    def _bucket_public(s3: BaseClient, name: str) -> bool:
        try:
            status = s3.get_bucket_policy_status(Bucket=name)
            return bool(status.get("PolicyStatus", {}).get("IsPublic"))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
                return False
            raise

    @staticmethod
    def _bucket_encrypted(s3: BaseClient, name: str) -> bool:
        try:
            s3.get_bucket_encryption(Bucket=name)
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchEncryptionConfiguration",
            }:
                return False
            raise

    @staticmethod
    def _bucket_versioning_enabled(s3: BaseClient, name: str) -> bool:
        response = s3.get_bucket_versioning(Bucket=name)
        return response.get("Status") == "Enabled"

    @staticmethod
    def _bucket_public_access_block(s3: BaseClient, name: str) -> bool:
        try:
            configuration = s3.get_public_access_block(
                Bucket=name
            ).get("PublicAccessBlockConfiguration", {})
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {
                "NoSuchPublicAccessBlockConfiguration",
                "NoSuchPublicAccessBlock",
            }:
                return False
            raise
        required = {
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        }
        return all(bool(configuration.get(key, False)) for key in required)

    @staticmethod
    def _bucket_region(s3: BaseClient, name: str) -> str:
        location = s3.get_bucket_location(Bucket=name).get(
            "LocationConstraint"
        )
        return "eu-west-1" if location == "EU" else location or "us-east-1"
