"""cognic-tool-oracle-schema smoke tests (inert descriptor)."""

from __future__ import annotations

from cognic_tool_oracle_schema import SERVER_DESCRIPTOR


def test_server_descriptor_is_marked() -> None:
    assert SERVER_DESCRIPTOR.cognic_pack_kind == "mcp_server"


def test_server_descriptor_pack_id_is_hyphenated() -> None:
    # The distribution name + manifest pack id are hyphenated; the inert
    # descriptor's pack_id must match (genesis-rename consistency).
    assert SERVER_DESCRIPTOR.pack_id == "cognic-tool-oracle-schema"
