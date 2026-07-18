"""Tests for build_server — the seven-tool registration + fail-closed config wiring.

build_server constructs the FastMCP app from Config.from_env() (so missing /
invalid env fails closed at build time) and registers the six read-only Oracle
schema-metadata tools plus the governed run_readonly_query (v0.3.0, M8) behind
the selected token verifier. Construction must NOT connect to Oracle — the
pool is initialised only when the FastMCP lifespan enters at server startup,
so these unit tests build with no live DB.
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
    "run_readonly_query",
}


def _structured_of(call_tool_result: object) -> dict:
    """Narrow FastMCP.call_tool's (content, structuredContent) return for
    mypy; the structured envelope is what the kernel dispatcher consumes."""
    assert isinstance(call_tool_result, tuple)
    structured = call_tool_result[1]
    assert isinstance(structured, dict)
    return structured


def _set_full_dev_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A complete, valid env: dev_insecure auth (so no oauth triple is required)
    plus the required oracle connection vars. The DSN points at a non-running
    localhost on purpose — build_server must succeed without connecting."""
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.setenv("COGNIC_ENV", "dev")
    monkeypatch.setenv("COGNIC_ORACLE_DSN", "localhost:1521/XEPDB1")
    monkeypatch.setenv("COGNIC_ORACLE_USER", "ro_user")
    monkeypatch.setenv("COGNIC_ORACLE_PASSWORD_FILE", "/run/secrets/oracle-password")
    monkeypatch.delenv("COGNIC_ORACLE_PASSWORD", raising=False)


def test_build_server_returns_fastmcp(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp.server.fastmcp import FastMCP

    _set_full_dev_env(monkeypatch)
    assert isinstance(build_server(as_issuer="http://127.0.0.1:9000"), FastMCP)


@pytest.mark.asyncio
async def test_build_server_registers_exactly_the_seven_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_full_dev_env(monkeypatch)
    mcp = build_server(as_issuer="http://127.0.0.1:9000")
    tools = await mcp.list_tools()
    assert {t.name for t in tools} == _EXPECTED_TOOLS


@pytest.mark.asyncio
async def test_run_readonly_query_wire_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """The MCP-advertised input schema carries the kernel's wire keys.

    The kernel dispatcher stamps the signed query-context token onto the call
    as the ``_cognic_query_context`` argument (``dispatch.py:109`` +
    ``:495``), so the server-side schema MUST accept that exact key. The
    LLM-facing schema exclusion is kernel-side (``build_llm_tool_specs``) —
    this server-side schema is what the MCP host validates against.
    """
    _set_full_dev_env(monkeypatch)
    mcp = build_server(as_issuer="http://127.0.0.1:9000")
    tools = {t.name: t for t in await mcp.list_tools()}
    tool = tools["run_readonly_query"]
    assert set(tool.inputSchema["properties"]) == {
        "scope_id",
        "sql",
        "max_rows",
        "_cognic_query_context",
    }
    assert set(tool.inputSchema["required"]) == {"scope_id", "sql"}
    # dict[str, Any] return annotation → structuredContent populated (the M6
    # finding-#17 realization).
    assert tool.outputSchema is not None


@pytest.mark.asyncio
async def test_run_readonly_query_call_by_wire_key_refuses_gracefully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An in-process call through the REAL registered tool, by the kernel's
    wire key, reaches the pipeline and refuses gracefully (no verifier keys
    configured → the agent-path-only guarantee) — no exception, no DB."""
    _set_full_dev_env(monkeypatch)
    monkeypatch.delenv("COGNIC_QUERY_CONTEXT_PUBLIC_KEYS", raising=False)
    mcp = build_server(as_issuer="http://127.0.0.1:9000")
    result = await mcp.call_tool(
        "run_readonly_query",
        {
            "scope_id": "retail_analytics",
            "sql": "SELECT 1 FROM dual",
            "_cognic_query_context": "not-a-real-token",
        },
    )
    structured = _structured_of(result)
    assert structured["ok"] is False
    assert structured["reason"] == "query_context_missing_or_invalid"


@pytest.mark.asyncio
async def test_run_readonly_query_call_without_token_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_full_dev_env(monkeypatch)
    monkeypatch.delenv("COGNIC_QUERY_CONTEXT_PUBLIC_KEYS", raising=False)
    mcp = build_server(as_issuer="http://127.0.0.1:9000")
    result = await mcp.call_tool(
        "run_readonly_query",
        {"scope_id": "retail_analytics", "sql": "SELECT 1 FROM dual"},
    )
    structured = _structured_of(result)
    assert structured["ok"] is False
    assert structured["reason"] == "query_context_missing_or_invalid"


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
    monkeypatch.setenv("COGNIC_ORACLE_PASSWORD_FILE", "/run/secrets/oracle-password")
    monkeypatch.delenv("COGNIC_ORACLE_PASSWORD", raising=False)
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
