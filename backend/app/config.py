"""Application configuration.

Settings are read from environment variables so the same image runs in local,
staging and production environments. Pydantic's ``BaseSettings`` provides
validation and ``.env`` support.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FGAI_", env_file=".env", extra="ignore")

    app_name: str = "FirewallGuard AI"
    environment: str = "development"
    debug: bool = False

    # Storage and brokers
    database_url: str = "postgresql+psycopg://fgai:fgai@localhost:5432/fgai"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # Object storage for uploaded TSRs and rendered reports
    storage_backend: str = "s3"          # s3 | local
    s3_bucket: str = "firewallguard-tsr"
    local_storage_dir: str = "/var/lib/firewallguard/storage"

    # Authentication
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 60
    refresh_token_ttl_days: int = 14

    # MFA (TOTP)
    mfa_issuer: str = "FirewallGuard AI"
    mfa_token_ttl_minutes: int = 5      # life of the interim token between password and TOTP
    mfa_backup_code_count: int = 10

    # Account lockout
    lockout_threshold: int = 5          # failed logins before lock
    lockout_minutes: int = 15           # how long the account stays locked

    # Rate limiting (per client IP, fixed one-minute window)
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 240        # general API budget
    auth_rate_limit_per_minute: int = 12    # stricter budget for auth endpoints

    max_tsr_size_mb: int = 64

    # Scheduled scans
    scan_max_retries: int = 3                    # retry attempts on failure
    scan_retry_backoff_seconds: int = 30         # base for exponential backoff
    max_concurrent_scans_per_tenant: int = 3     # Redis-enforced concurrency cap
    schedule_tick_seconds: int = 60              # Celery Beat poll interval

    # Alerting
    smtp_host: str = "localhost"
    smtp_port: int = 587
    alert_from_address: str = "alerts@firewallguard.ai"

    # Credential encryption (Fernet). Generate with
    # `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
    # If unset, a key is derived from jwt_secret so local dev works without extra
    # configuration; production MUST set this to a stable, secret value.
    credential_encryption_key: str = ""

    # SonicOS API pull
    sonicos_verify_tls: bool = False        # appliance certs are usually self-signed
    sonicos_timeout_seconds: int = 30
    sonicos_api_base: str = "/api/sonicos"  # SonicOS REST base path
    sonicos_login_override: bool = True     # Gen7: send {"override": true} on login

    # Public URLs used for SSO redirects and Stripe return URLs
    public_app_url: str = "http://localhost:5173"
    public_api_url: str = "http://localhost:8000"

    # SSO
    sso_state_ttl_minutes: int = 10
    saml_verify_signature: bool = False     # see app/sso.py — off until xmlsec wired

    # Billing / Stripe
    stripe_api_key: str = ""                # empty => billing runs in local/dev mode
    stripe_webhook_secret: str = ""
    stripe_price_professional: str = ""
    stripe_price_msp: str = ""
    trial_days: int = 14

    # Plan limits (enforced at the API layer)
    plan_limits: dict = {
        "free": {"devices": 1, "schedules": 0, "integrations": 0},
        "professional": {"devices": 1000, "schedules": 1000, "integrations": 20},
        "msp": {"devices": 100000, "schedules": 100000, "integrations": 100},
    }

    # PSIRT auto-refresh
    psirt_portal_url: str = "https://psirt.global.sonicwall.com"
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    psirt_refresh_hour: int = 4             # daily refresh hour (UTC)

    # Data residency (Phase 4). Region code -> S3 bucket for that region's data.
    regions: list = ["us", "eu", "apac"]
    default_region: str = "us"
    region_buckets: dict = {
        "us": "firewallguard-tsr-us",
        "eu": "firewallguard-tsr-eu",
        "apac": "firewallguard-tsr-apac",
    }

    # Data retention (Phase 4). Days of analysis/TSR retention by plan tier;
    # 0 means unlimited. Per-org override via Organization.data_retention_days.
    retention_days: dict = {"free": 30, "professional": 90, "msp": 365}
    retention_purge_hour: int = 5           # daily purge hour (UTC)

    # Security headers (Phase 4)
    security_headers_enabled: bool = True
    hsts_max_age: int = 63072000            # 2 years
    content_security_policy: str = (
        "default-src 'self'; img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
