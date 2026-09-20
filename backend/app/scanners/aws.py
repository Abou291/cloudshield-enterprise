from datetime import UTC, datetime

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from app.core.domain import Asset


class AwsInventoryProvider:
    """Read-only AWS collector for the deliberately narrow V1 surface."""

    def __init__(self, region: str, role_arn: str | None = None) -> None:
        session = boto3.Session(region_name=region)
        if role_arn:
            sts = session.client("sts")
            credentials = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="cloudshield-readonly-scan",
            )["Credentials"]
            session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=region,
            )
        self.session = session
        self.region = region
        self.account_id = self.session.client("sts").get_caller_identity()["Account"]

    def collect(self) -> list[Asset]:
        return [*self._collect_iam(), *self._collect_s3(), *self._collect_security_groups()]

    def _collect_iam(self) -> list[Asset]:
        iam = self.session.client("iam")
        assets: list[Asset] = []
        for user in iam.get_paginator("list_users").paginate().search("Users[]"):
            username = user["UserName"]
            mfa_enabled = bool(iam.list_mfa_devices(UserName=username)["MFADevices"])
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            oldest_key_days = max(
                ((datetime.now(UTC) - key["CreateDate"]).days for key in keys), default=0
            )
            attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            administrator = any(
                policy["PolicyArn"].endswith("/AdministratorAccess") for policy in attached
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
        s3 = self.session.client("s3")
        assets: list[Asset] = []
        for bucket in s3.list_buckets().get("Buckets", []):
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
                    },
                    context={"internet_exposed": public},
                )
            )
        return assets

    def _collect_security_groups(self) -> list[Asset]:
        ec2 = self.session.client("ec2")
        assets: list[Asset] = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for group in page["SecurityGroups"]:
                for permission in group.get("IpPermissions", []):
                    from_port = permission.get("FromPort")
                    cidrs = [item["CidrIp"] for item in permission.get("IpRanges", [])]
                    cidrs += [item["CidrIpv6"] for item in permission.get("Ipv6Ranges", [])]
                    for cidr in cidrs:
                        assets.append(
                            Asset(
                                resource_id=f"{group['GroupId']}:{from_port}:{cidr}",
                                resource_type="security_group_rule",
                                account_id=self.account_id,
                                region=self.region,
                                name=group.get("GroupName", group["GroupId"]),
                                attributes={"from_port": from_port, "source_cidr": cidr},
                                context={"internet_exposed": cidr in {"0.0.0.0/0", "::/0"}},
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
    def _bucket_region(s3: BaseClient, name: str) -> str:
        location = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
        return location or "us-east-1"
