from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CLOUDSHIELD_", env_file=".env", extra="ignore"
    )

    app_name: str = "CloudShield Enterprise"
    env: str = "development"
    database_url: str = "sqlite:///./cloudshield.db"
    cors_origins: list[str] = ["http://localhost:5173"]
    aws_region: str = "eu-west-3"
    aws_role_arn: str | None = None

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_cors_origins(cls, value: object) -> object:
        if isinstance(value, str) and not value.startswith("["):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()

