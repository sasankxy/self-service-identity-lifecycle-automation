"""Application settings, loaded from environment variables (see .env.example)."""
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ASYMMETRIC_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}
SYMMETRIC_ALGS = {"HS256", "HS384", "HS512"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"), env_file_encoding="utf-8", extra="ignore"
    )

    env: Literal["dev", "test", "prod"] = "dev"

    # --- infrastructure ---
    database_url: str = "postgresql+asyncpg://identityos:identityos@localhost:5432/identityos"
    redis_url: str = "redis://localhost:6379/0"

    # --- local SLM fallback (Ollama) ---
    slm_enabled: bool = False
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    slm_timeout_s: float = 25.0

    # --- agent layer (app/agents) ---
    agent_mode: Literal["legacy", "graph"] = "legacy"            # which assistant the chat UI uses; /agent/* is always served
    agent_checkpointer: Literal["postgres", "memory"] = "postgres"   # conversation state store (tests always use memory)

    # --- JWT ---
    jwt_algorithm: str = "HS256"
    jwt_secret_key: str = ""            # HS* algorithms
    jwt_private_key_path: str = ""      # RS*/ES*/EdDSA: PEM private key (signing)
    jwt_public_key_path: str = ""       # RS*/ES*/EdDSA: PEM public key (verification)
    jwt_issuer: str = "identityos"
    jwt_audience: str = "identityos-portal"
    access_token_ttl_minutes: int = Field(15, ge=1, le=60)
    refresh_token_ttl_days: int = Field(7, ge=1, le=90)          # sliding window
    session_absolute_max_days: int = Field(30, ge=1, le=365)     # hard cap on a session

    # --- cookies / CSRF ---
    cookie_secure: bool = False         # MUST be true in prod (HTTPS)
    cookie_samesite: Literal["lax", "strict"] = "lax"
    cookie_domain: str | None = None
    csrf_secret: str = ""

    # --- CORS / frontend ---
    # Frontend is served same-origin by FastAPI, so CORS is closed by default.
    cors_allowed_origins: str = ""      # comma separated, exact origins only
    frontend_dir: str = str(Path(__file__).resolve().parents[3] / "frontend")

    # --- signup policy ---
    allowed_email_domains: str = ""     # comma separated; empty = any domain
    password_min_length: int = 12

    # --- rate limiting (fixed window, Redis) ---
    login_rate_limit_per_email: int = 5
    login_rate_limit_per_ip: int = 30
    login_rate_limit_window_seconds: int = 900
    signup_rate_limit_per_ip: int = 5
    signup_rate_limit_window_seconds: int = 3600

    # --- cache TTLs ---
    principal_cache_ttl_seconds: int = 60

    # --- proactive governance (orphan / privilege-creep scan + due-request applier) ---
    governance_scan_interval_minutes: int = Field(60, ge=0, le=1440)     # 0 disables the background scheduler (never runs when ENV=test)
    governance_scan_initial_delay_seconds: int = Field(20, ge=0, le=3600)

    # Trust X-Forwarded-For only when running behind a known reverse proxy.
    trust_proxy_headers: bool = False

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def email_domains(self) -> set[str]:
        return {d.strip().lower() for d in self.allowed_email_domains.split(",") if d.strip()}

    @model_validator(mode="after")
    def _validate(self) -> "Settings":
        alg = self.jwt_algorithm
        if alg in SYMMETRIC_ALGS:
            if len(self.jwt_secret_key) < 32:
                raise ValueError("JWT_SECRET_KEY must be set (>= 32 chars) for HS* algorithms")
        elif alg in ASYMMETRIC_ALGS:
            if not (self.jwt_private_key_path and self.jwt_public_key_path):
                raise ValueError("JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH required for " + alg)
        else:
            raise ValueError(f"Unsupported JWT_ALGORITHM {alg!r} ('none' is never allowed)")
        if len(self.csrf_secret) < 32:
            raise ValueError("CSRF_SECRET must be set (>= 32 chars)")
        if self.env == "prod" and not self.cookie_secure:
            raise ValueError("COOKIE_SECURE must be true when ENV=prod")
        return self

    def signing_key(self) -> str:
        if self.jwt_algorithm in SYMMETRIC_ALGS:
            return self.jwt_secret_key
        return Path(self.jwt_private_key_path).read_text()

    def verification_key(self) -> str:
        if self.jwt_algorithm in SYMMETRIC_ALGS:
            return self.jwt_secret_key
        return Path(self.jwt_public_key_path).read_text()


@lru_cache
def get_settings() -> Settings:
    return Settings()
