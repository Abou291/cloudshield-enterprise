from importlib.metadata import PackageNotFoundError, version

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import AwsConnection, Settings
from app.scanners.aws import AwsInventoryProvider


def product_version() -> str:
    try:
        return version("aegisshield-api")
    except PackageNotFoundError:
        return "0.3.0"


def classify_aws_error(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, ProfileNotFound):
        return (
            "AWS_PROFILE_NOT_FOUND",
            "AWS profile not found on this PC. Configure AWS CLI/IAM Identity Center first.",
        )
    if isinstance(exc, NoCredentialsError):
        return (
            "AWS_CREDENTIALS_MISSING",
            "No usable AWS credentials were found. Sign in with the configured AWS profile.",
        )
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        messages = {
            "AccessDenied": (
                "AWS denied the requested action. Review the AssumeRole trust "
                "policy and scanner permissions."
            ),
            "AccessDeniedException": (
                "AWS denied the requested action. Review the scanner role permissions."
            ),
            "ExpiredToken": (
                "The AWS session has expired. Sign in to IAM Identity Center/SSO again."
            ),
            "ExpiredTokenException": (
                "The AWS session has expired. Sign in to IAM Identity Center/SSO again."
            ),
            "InvalidClientTokenId": (
                "The local AWS session is invalid. Refresh the AWS CLI/SSO login."
            ),
            "UnrecognizedClientException": "The local AWS session is invalid or expired.",
        }
        return code.upper(), messages.get(
            code,
            "AWS rejected the request. Review the local profile, trust policy, "
            "Region and read-only permissions.",
        )
    if isinstance(exc, BotoCoreError):
        return (
            "AWS_SDK_ERROR",
            "The AWS SDK could not complete the request. Check network access, "
            "Region and local AWS configuration.",
        )
    if isinstance(exc, ValueError):
        return "AWS_ACCOUNT_MISMATCH", str(exc)
    return "AWS_DIAGNOSTIC_FAILED", "AWS validation failed without exposing upstream details."


def base_diagnostics(db: Session, settings: Settings) -> dict:
    database_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        database_ok = False

    data_directory: str | None = None
    backup_count = 0
    if settings.desktop_config_path is not None:
        data_dir = settings.desktop_config_path.parent
        data_directory = str(data_dir)
        backup_dir = data_dir / "backups"
        if backup_dir.exists():
            backup_count = len(list(backup_dir.glob("aegisshield-*.db")))

    return {
        "version": product_version(),
        "backend": "ok",
        "database": "ok" if database_ok else "error",
        "database_engine": "sqlite" if settings.database_url.startswith("sqlite") else "postgresql",
        "desktop": settings.desktop_mode,
        "data_directory": data_directory,
        "backup_count": backup_count,
    }


def aws_diagnostics(connection: AwsConnection) -> dict:
    try:
        provider = AwsInventoryProvider(
            connection.region,
            connection.role_arn,
            connection.external_id,
            connection.account_id,
            connection.profile_name,
        )
    except Exception as exc:
        code, message = classify_aws_error(exc)
        return {
            "status": "error",
            "code": code,
            "message": message,
            "account_id": connection.account_id,
            "region": connection.region,
            "profile_name": connection.profile_name,
        }

    return {
        "status": "ok",
        "code": "AWS_READY",
        "message": "AWS profile, STS AssumeRole and account binding are valid.",
        "account_id": provider.account_id,
        "region": connection.region,
        "profile_name": connection.profile_name,
    }
