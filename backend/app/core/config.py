from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", "../.env"), env_file_encoding="utf-8", extra="ignore")
    app_name: str = "CTI Platform"
    app_env: Literal["development", "test", "staging", "production"] = "development"
    debug: bool = False
    secret_key: str = Field(default="development-only-secret-key-change-before-deploy-0000", min_length=32)
    access_token_expire_minutes: int = Field(default=30, ge=5, le=1440)
    database_url: str = "sqlite:///./cti.db"
    cors_origins: str = "http://localhost:5173"
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None
    deepseek_api_key: str | None = None
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-flash"
    nvd_api_key: str | None = None
    log_level: str = "INFO"

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, value: str) -> str:
        if value.startswith("REPLACE_WITH"):
            raise ValueError("Substitua o valor de exemplo de SECRET_KEY")
        if value.startswith("development-only") and __import__("os").environ.get("APP_ENV") == "production":
            raise ValueError("Configure uma SECRET_KEY forte em produção")
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

@lru_cache
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
