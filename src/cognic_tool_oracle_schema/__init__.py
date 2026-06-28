"""cognic-tool-oracle-schema — Cognic AgentOS MCP tool pack.

SERVER_DESCRIPTOR is the inert entry-point object PluginRegistry.discover()
resolves the distribution from. The runtime MCP path runs the tool behind a
real HTTP server (see server.py) and NEVER EntryPoint.load()s this object; it
exists only for discovery + the `agentos verify` load-probe. Do NOT
import-poison this module.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _ServerDescriptor:
    """Inert marker. The real server lives in cognic_tool_oracle_schema.server."""

    cognic_pack_kind: str = "mcp_server"
    pack_id: str = "cognic-tool-oracle-schema"


SERVER_DESCRIPTOR = _ServerDescriptor()
