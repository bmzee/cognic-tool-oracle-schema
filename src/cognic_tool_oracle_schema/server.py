"""Streamable-HTTP MCP server for cognic-tool-oracle-schema (FastMCP).

Resource-server OAuth mode: passing ``auth`` + ``token_verifier`` makes FastMCP
auto-publish Protected Resource Metadata and wrap ``/mcp`` with bearer auth.
The verifier is selected fail-closed by :func:`auth.select_token_verifier`
(real JWT/JWKS in ``jwt`` mode; the permissive ``DevTokenVerifier`` only when
``COGNIC_AUTH_MODE=dev_insecure`` + ``COGNIC_ENV=dev``, enforced in
:meth:`config.Config.from_env`).

Safety boundary (verbatim from the design source of truth, #108): *"This is a
schema-metadata tool, not a database query tool. It never executes
user-supplied SQL, never queries application tables, never returns application
rows, and never performs DML/DDL."* The six registered tools delegate to
:mod:`cognic_tool_oracle_schema.tools`, whose queries are fixed strings with
bind variables only.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from . import oracle, tools
from .auth import select_token_verifier
from .config import Config

_HOST = os.environ.get("COGNIC_MCP_HOST", "127.0.0.1")
_PORT = int(os.environ.get("COGNIC_MCP_PORT", "8765"))
_SERVER_URL = os.environ.get("COGNIC_MCP_SERVER_URL", "http://127.0.0.1:8765/mcp")


def build_server(*, as_issuer: str) -> FastMCP:
    """Construct the FastMCP app: fail-closed config, the selected verifier, the
    six read-only tools, and the Oracle-pool lifespan.

    ``Config.from_env()`` runs first so missing / invalid env fails closed at
    build time. Construction does NOT connect to Oracle — the pool is created
    only when the lifespan enters at server startup.
    """
    cfg = Config.from_env()

    @asynccontextmanager
    async def _pool_lifespan(_server: FastMCP) -> AsyncIterator[None]:
        # Runs at server startup (NOT during build_server). Open the async pool
        # on entry, close it on shutdown.
        oracle.init_pool(cfg)
        try:
            yield None
        finally:
            await oracle.close_pool()

    mcp = FastMCP(
        "cognic-tool-oracle-schema",
        host=_HOST,
        port=_PORT,
        streamable_http_path="/mcp",
        json_response=False,
        stateless_http=False,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(as_issuer),
            resource_server_url=AnyHttpUrl(_SERVER_URL),
            required_scopes=list(cfg.required_scopes),
        ),
        token_verifier=select_token_verifier(cfg),
        lifespan=_pool_lifespan,
    )

    @mcp.tool(name="list_schemas", description="List distinct Oracle schema owners (constrained to the allow-list when set).")
    async def list_schemas() -> dict:
        return await tools.list_schemas(cfg=cfg)

    @mcp.tool(name="list_tables", description="List tables (with comments) for one schema owner.")
    async def list_tables(owner: str) -> dict:
        return await tools.list_tables(cfg=cfg, owner=owner)

    @mcp.tool(name="describe_table", description="Describe a table's columns (type / nullability / default / comment).")
    async def describe_table(owner: str, table: str) -> dict:
        return await tools.describe_table(cfg=cfg, owner=owner, table=table)

    @mcp.tool(name="find_columns", description="Find columns by name LIKE pattern, optionally scoped to one owner.")
    async def find_columns(name_pattern: str, owner: str | None = None) -> dict:
        return await tools.find_columns(cfg=cfg, name_pattern=name_pattern, owner=owner)

    @mcp.tool(name="list_relationships", description="List foreign-key relationships for one owner (optionally one table).")
    async def list_relationships(owner: str, table: str | None = None) -> dict:
        return await tools.list_relationships(cfg=cfg, owner=owner, table=table)

    @mcp.tool(name="get_constraints", description="List all constraints (PK / UK / CK / FK) for one table.")
    async def get_constraints(owner: str, table: str) -> dict:
        return await tools.get_constraints(cfg=cfg, owner=owner, table=table)

    return mcp


if __name__ == "__main__":
    build_server(
        as_issuer=os.environ.get("COGNIC_MCP_AS_ISSUER", "http://127.0.0.1:9000")
    ).run(transport="streamable-http")
