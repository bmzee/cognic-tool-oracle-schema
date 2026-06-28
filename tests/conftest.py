"""Pytest config for cognic-tool-oracle-schema.

This is a FastMCP MCP-server pack with NO kernel runtime dependency. Its
tests use plain pytest + monkeypatch + fake cursors, so the AgentOS SDK
testing fixtures (``cognic_agentos.sdk.testing``) are intentionally NOT
re-exported here — the kernel is an author/CI-time dev dependency only
(``agentos validate/sign/verify``), not needed to run the pack's unit tests.
"""
