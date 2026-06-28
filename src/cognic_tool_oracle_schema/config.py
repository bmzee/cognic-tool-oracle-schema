from __future__ import annotations

import os
from dataclasses import dataclass

_HARD_MAX_ROWS = 1000
_DEFAULT_MAX_ROWS = 200


class ConfigError(RuntimeError):
    """Raised at startup when required env is missing or dev_insecure is misused (fail-closed)."""


@dataclass(frozen=True)
class Config:
    oracle_dsn: str
    oracle_user: str
    oracle_password: str
    allowed_owners: frozenset[str]          # empty = trust the DB grant
    max_rows: int
    pool_max: int
    auth_mode: str                           # "jwt" | "dev_insecure"
    oauth_issuer: str | None
    oauth_jwks_uri: str | None
    oauth_audience: str | None
    required_scopes: frozenset[str]

    @staticmethod
    def from_env() -> "Config":
        def _req(k: str) -> str:
            v = os.environ.get(k)
            if not v:
                raise ConfigError(f"missing required env {k}")
            return v

        auth_mode = os.environ.get("COGNIC_AUTH_MODE", "jwt")
        if auth_mode == "dev_insecure" and os.environ.get("COGNIC_ENV") != "dev":
            raise ConfigError("COGNIC_AUTH_MODE=dev_insecure requires COGNIC_ENV=dev")
        if auth_mode not in ("jwt", "dev_insecure"):
            raise ConfigError(f"invalid COGNIC_AUTH_MODE {auth_mode!r}")

        owners_raw = os.environ.get("COGNIC_ORACLE_ALLOWED_OWNERS", "")
        allowed = frozenset(o.strip().upper() for o in owners_raw.split(",") if o.strip())

        try:
            max_rows = int(os.environ.get("COGNIC_ORACLE_MAX_ROWS", str(_DEFAULT_MAX_ROWS)))
        except ValueError as exc:
            raise ConfigError("COGNIC_ORACLE_MAX_ROWS must be an integer") from exc
        max_rows = max(1, min(max_rows, _HARD_MAX_ROWS))

        issuer = os.environ.get("COGNIC_OAUTH_ISSUER")
        jwks = os.environ.get("COGNIC_OAUTH_JWKS_URI")
        audience = os.environ.get("COGNIC_OAUTH_AUDIENCE")
        if auth_mode == "jwt" and not (issuer and jwks and audience):
            raise ConfigError(
                "COGNIC_AUTH_MODE=jwt requires COGNIC_OAUTH_ISSUER, "
                "COGNIC_OAUTH_JWKS_URI, COGNIC_OAUTH_AUDIENCE"
            )
        scopes = frozenset(
            s.strip() for s in os.environ.get("COGNIC_REQUIRED_SCOPES", "oracle_schema.read").split(",") if s.strip()
        )
        if not scopes:
            raise ConfigError("COGNIC_REQUIRED_SCOPES must contain at least one scope")
        return Config(
            oracle_dsn=_req("COGNIC_ORACLE_DSN"),
            oracle_user=_req("COGNIC_ORACLE_USER"),
            oracle_password=_req("COGNIC_ORACLE_PASSWORD"),
            allowed_owners=allowed, max_rows=max_rows,
            pool_max=int(os.environ.get("COGNIC_ORACLE_POOL_MAX", "4")),
            auth_mode=auth_mode, oauth_issuer=issuer, oauth_jwks_uri=jwks,
            oauth_audience=audience, required_scopes=scopes,
        )
