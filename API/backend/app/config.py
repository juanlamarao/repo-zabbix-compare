from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Zabbix Upgrade Validator"
    database_url: str = "postgresql://zuv:zuv@db:5432/zuv"

    old_zabbix_url: str = ""
    old_zabbix_token: str = ""
    new_zabbix_url: str = ""
    new_zabbix_token: str = ""

    verify_ssl: bool = True
    request_timeout_seconds: int = 90
    api_retries: int = 3
    hosts_per_batch: int = 5
    parallel_batches: int = 5
    collection_interval_seconds: int = 300
    action_alert_scan_limit: int = 100

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
