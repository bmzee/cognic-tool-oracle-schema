from __future__ import annotations

import asyncio

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken, TokenVerifier

from .config import Config


class DevTokenVerifier(TokenVerifier):
    """DEV-ONLY (reachable only via COGNIC_AUTH_MODE=dev_insecure + COGNIC_ENV=dev,
    enforced in Config.from_env). Accepts any non-empty bearer."""

    def __init__(self, cfg: Config) -> None:
        self._scopes = list(cfg.required_scopes)
        self._aud = cfg.oauth_audience or ""

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        return AccessToken(
            token=token, client_id="dev", scopes=self._scopes, expires_at=None, resource=self._aud
        )


class JwtTokenVerifier(TokenVerifier):
    """Resource-server verifier: validates RS256 signature against the AS JWKS,
    plus audience / issuer / exp / required scope."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._jwks = PyJWKClient(cfg.oauth_jwks_uri)  # type: ignore[arg-type]  # jwt-mode guarantees non-None

    def _verify_sync(self, token: str) -> dict:
        signing_key = self._jwks.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self._cfg.oauth_audience,
            issuer=self._cfg.oauth_issuer,
            options={"require": ["exp", "iat", "nbf"]},
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        try:
            claims = await asyncio.to_thread(self._verify_sync, token)
            granted = _scopes_from_claims(claims)
        except Exception:
            return None  # FastMCP treats None as unauthorized (fail-closed)
        if not self._cfg.required_scopes.issubset(granted):
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("azp") or claims.get("client_id") or "unknown"),
            scopes=sorted(granted),
            expires_at=claims.get("exp"),
            resource=self._cfg.oauth_audience,
        )


def _scopes_from_claims(claims: dict) -> set[str]:
    """Extract scopes from a 'scope' (space-delimited str) or 'scp' (list) claim.

    Raises ValueError on a malformed claim (non-str / non-str-list) so the
    verifier fails closed rather than bubbling a TypeError or accepting a
    mixed set.
    """
    raw = claims.get("scope") or claims.get("scp") or ""
    if isinstance(raw, str):
        return set(raw.split())
    if isinstance(raw, (list, tuple)) and all(isinstance(s, str) for s in raw):
        return set(raw)
    raise ValueError("malformed scope/scp claim")


def select_token_verifier(cfg: Config) -> TokenVerifier:
    return DevTokenVerifier(cfg) if cfg.auth_mode == "dev_insecure" else JwtTokenVerifier(cfg)
