"""cognic-tool-oracle-schema smoke tests."""

from __future__ import annotations

import pytest

from cognic_tool_oracle_schema import SERVER_DESCRIPTOR
from cognic_tool_oracle_schema.server import build_server


def test_server_descriptor_is_marked() -> None:
    assert SERVER_DESCRIPTOR.cognic_pack_kind == "mcp_server"


def test_server_descriptor_pack_id_is_hyphenated() -> None:
    # The distribution name + manifest pack id are hyphenated; the inert
    # descriptor's pack_id must match (genesis-rename consistency).
    assert SERVER_DESCRIPTOR.pack_id == "cognic-tool-oracle-schema"


def test_build_server_returns_fastmcp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.setenv("COGNIC_ENV", "dev")
    assert build_server(as_issuer="http://127.0.0.1:9000") is not None


def test_build_server_fails_closed_without_dev_optin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("COGNIC_AUTH_MODE", raising=False)
    monkeypatch.delenv("COGNIC_ENV", raising=False)
    with pytest.raises(RuntimeError):
        build_server(as_issuer="http://127.0.0.1:9000")
