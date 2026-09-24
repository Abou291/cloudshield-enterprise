from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiPrincipal(BaseModel):
    key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    subject: str = Field(min_length=1, max_length=100)
    role: Literal["viewer", "operator"] = "viewer"


class AwsConnection(BaseModel):
    role_arn: str = Field(pattern=r"^arn:aws:iam::[0-9]{12}:role/.+$")
    external_id: str = Field(min_length=16, max_length=1224)
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    region: str = Field(default="eu-west-3", pattern=r"^[a-z]{2}-[a-z]+-[0-9]$")
    profile_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,128}$")

    @model_validator(mode="after")
    def validate_account(self) -> "AwsConnection":
        if self.role_arn.split(":")[4] != self.account_id:
            raise ValueError("Role ARN must belong to the configured account")
        return self


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CLOUDSHIELD_", env_file=".env", extra="ignore"
    )

    app_name: str = "AegisShield"
    env: Literal["development", "test", "production"] = "development"
    demo_mode: bool = True
    api_keys: list[ApiPrincipal] = Field(default_factory=list)
    aws_connections: dict[str, AwsConnection] = Field(default_factory=dict)
    database_url: str = "sqlite:///./cloudshield.db"
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    aws_region: str = "eu-west-3"
    aws_role_arn: str | None = None
    desktop_mode: bool = False
    desktop_config_path: Path | None = None
    instance_nonce: str | None = Field(default=None, min_length=16, max_length=128)
    ai_api_key: str | None = None
    ai_base_url: str = "https://api.openai.com/v1"
    ai_allowed_hosts: list[str] = ["api.openai.com"]
    ai_model: str = "gpt-4.1-mini"
    rate_limit_per_minute: int = Field(default=120, ge=10, le=10000)

    @model_validator(mode="after")
    def validate_security(self) -> "Settings":
        if self.env == "production" and self.demo_mode:
            raise ValueError("Production requires CLOUDSHIELD_DEMO_MODE=false")
        if not self.demo_mode and not self.api_keys:
            raise ValueError("Authenticated mode requires API key hashes")
        if self.demo_mode and self.api_keys:
            raise ValueError("Demo mode cannot be combined with API keys")

        hashes = [key.key_sha256 for key in self.api_keys]
        if len(hashes) != len(set(hashes)):
            raise ValueError("Each API key hash must be unique")
        if "*" in self.cors_origins:
            raise ValueError("Explicit CORS origins are required")

        parsed = urlparse(self.ai_base_url)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or not hostname:
            raise ValueError("AI provider URL must be an HTTP(S) URL")
        if self.env == "production":
            if parsed.scheme != "https":
                raise ValueError("Production AI provider must use HTTPS")
            allowed = {host.lower() for host in self.ai_allowed_hosts}
            if hostname not in allowed:
                raise ValueError(
                    "Production AI provider host must be explicitly allowlisted"
                )
        elif parsed.scheme == "http" and hostname not in {"localhost", "127.0.0.1"}:
            raise ValueError("Plain HTTP AI providers are allowed only on loopback")

        return self

    @field_validator("cors_origins", "ai_allowed_hosts", mode="before")
    @classmethod
    def split_string_lists(cls, value: object) -> object:
        if isinstance(value, str) and not value.startswith("["):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
