"""Tests for build_server — the six-tool registration + fail-closed config wiring.

build_server constructs the FastMCP app from Config.from_env() (so missing /
invalid env fails closed at build time) and registers exactly the six read-only
Oracle schema-metadata tools behind the selected token verifier. Construction
must NOT connect to Oracle — the pool is initialised only when the FastMCP
lifespan enters at server startup, so these unit tests build with no live DB.
"""

from __future__ import annotations

import pytest

from cognic_tool_oracle_schema import oracle
from cognic_tool_oracle_schema.config import ConfigError
from cognic_tool_oracle_schema.server import build_server

_EXPECTED_TOOLS = {
    "list_schemas",
    "list_tables",
    "describe_table",
    "find_columns",
    "list_relationships",
    "get_constraints",
}


def _set_full_dev_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A complete, valid env: dev_insecure auth (so no oauth triple is required)
    plus the required oracle connection vars. The DSN points at a non-running
    localhost on purpose — build_server must succeed without connecting."""
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.setenv("COGNIC_ENV", "dev")
    monkeypatch.setenv("COGNIC_ORACLE_DSN", "localhost:1521/XEPDB1")
    monkeypatch.setenv("COGNIC_ORACLE_USER", "ro_user")
    monkeypatch.setenv("COGNIC_ORACLE_PASSWORD", "pw")


def test_build_server_returns_fastmcp(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp.server.fastmcp import FastMCP

    _set_full_dev_env(monkeypatch)
    assert isinstance(build_server(as_issuer="http://127.0.0.1:9000"), FastMCP)


@pytest.mark.asyncio
async def test_build_server_registers_exactly_the_six_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_full_dev_env(monkeypatch)
    mcp = build_server(as_issuer="http://127.0.0.1:9000")
    tools = await mcp.list_tools()
    assert {t.name for t in tools} == _EXPECTED_TOOLS


def test_build_server_does_not_init_pool_at_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_full_dev_env(monkeypatch)

    def _boom(_cfg: object) -> None:
        raise AssertionError("init_pool must not run during build_server")

    monkeypatch.setattr(oracle, "init_pool", _boom)
    # Must not raise — the pool is initialised only when the lifespan enters.
    assert build_server(as_issuer="http://127.0.0.1:9000") is not None


def test_build_server_fails_closed_jwt_without_oauth_triple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # oracle env present, jwt mode, but the oauth triple is missing → Config
    # fails closed before any FastMCP construction.
    monkeypatch.setenv("COGNIC_ORACLE_DSN", "localhost:1521/XEPDB1")
    monkeypatch.setenv("COGNIC_ORACLE_USER", "ro_user")
    monkeypatch.setenv("COGNIC_ORACLE_PASSWORD", "pw")
    monkeypatch.setenv("COGNIC_AUTH_MODE", "jwt")
    for k in ("COGNIC_OAUTH_ISSUER", "COGNIC_OAUTH_JWKS_URI", "COGNIC_OAUTH_AUDIENCE"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(ConfigError):
        build_server(as_issuer="http://127.0.0.1:9000")


def test_build_server_fails_closed_without_oracle_dsn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_full_dev_env(monkeypatch)
    monkeypatch.delenv("COGNIC_ORACLE_DSN", raising=False)
    with pytest.raises(ConfigError):
        build_server(as_issuer="http://127.0.0.1:9000")
