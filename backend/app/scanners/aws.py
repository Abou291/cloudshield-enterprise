from collections.abc import Callable
from datetime import UTC, datetime

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.core.domain import Asset


class AwsInventoryProvider:
    """Read-only AWS collector with fail-soft optional service coverage."""

    def __init__(
        self,
        region: str,
        role_arn: str | None = None,
        external_id: str | None = None,
        expected_account_id: str | None = None,
        profile_name: str | None = None,
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
        self.account_id = self.client("sts").get_caller_identity()["Account"]
        if expected_account_id and self.account_id != expected_account_id:
            raise ValueError("AWS identity does not match the configured account")

    def client(self, service: str) -> BaseClient:
        return self.session.client(service, config=self.client_config)

    def collect(self) -> list[Asset]:
        collectors: list[tuple[str, Callable[[], list[Asset]]]] = [
            ("iam", self._collect_iam),
            ("s3", self._collect_s3),
            ("ec2-security-groups", self._collect_security_groups),
            ("ebs", self._collect_ebs),
            ("rds", self._collect_rds),
            ("cloudtrail", self._collect_cloudtrail),
            ("guardduty", self._collect_guardduty),
        ]
        assets: list[Asset] = []
        for service, collector in collectors:
            assets.extend(self._safe_collect(service, collector))
        return assets

    def _safe_collect(
        self,
        service: str,
        collector: Callable[[], list[Asset]],
    ) -> list[Asset]:
        try:
            return collector()
        except (ClientError, BotoCoreError) as exc:
            reason = type(exc).__name__
            if isinstance(exc, ClientError):
                reason = exc.response.get("Error", {}).get("Code", "ClientError")
            return [
                Asset(
                    resource_id=f"coverage:{service}",
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
