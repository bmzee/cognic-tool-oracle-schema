"""Pack-manifest contracts for v0.5.0 capability-class declarations."""

from __future__ import annotations

import pathlib
import tomllib

_ROOT = pathlib.Path(__file__).resolve().parents[1]

_EXPECTED_CAPABILITY_CLASSES = {
    "list_schemas": "unscoped",
    "list_tables": "unscoped",
    "describe_table": "unscoped",
    "find_columns": "unscoped",
    "list_relationships": "unscoped",
    "get_constraints": "unscoped",
    "run_readonly_query": "data_query",
}


def _manifest() -> dict:
    return tomllib.loads((_ROOT / "cognic-pack-manifest.toml").read_text())


def _pyproject() -> dict:
    return tomllib.loads((_ROOT / "pyproject.toml").read_text())


def test_version_is_0_5_1() -> None:
    assert _pyproject()["project"]["version"] == "0.5.1"


def test_sqlglot_pinned_pure_python() -> None:
    # Exact pin per the M8 B1 contract (pure-Python; NO sqlglotrs).
    deps = _pyproject()["project"]["dependencies"]
    assert "sqlglot==30.12.0" in deps
    assert not any("sqlglotrs" in d for d in deps)


def test_joserfc_and_cryptography_are_runtime_deps() -> None:
    # The pack-local query-context verifier has NO runtime kernel dependency;
    # joserfc + cryptography are the pack's own deps (M8 B1).
    deps = _pyproject()["project"]["dependencies"]
    assert any(d.startswith("joserfc") for d in deps)
    assert any(d.startswith("cryptography") for d in deps)


def test_data_governance_declares_the_m5_dlp_pre_hooks() -> None:
    # The v0.2.0 delta (M5, ADR-017): the AgentOS kernel's dlp_pre scan runs
    # these two cognic-hook-schema-guard hooks over the canonical call_tool
    # argument bytes BEFORE any token / session / transport work. Order and
    # ids must match the hook pack's [hooks].declarations exactly.
    dg = _manifest()["data_governance"]
    assert dg["dlp_pre_hooks"] == ["refuse_forbidden_schema_arg", "explode_schema_guard"]


def test_data_governance_contract_is_stable() -> None:
    # The pre-existing ADR-017 contract fields carry over unchanged from
    # v0.1.0 (Appendix A.2 of the M5 plan).
    dg = _manifest()["data_governance"]
    assert dg["data_classes"] == ["internal"]
    assert dg["purpose"] == "operational_telemetry"
    assert dg["retention_policy"] == "none"
    assert dg["egress_allow_list"] == []


def test_risk_tier_stays_read_only() -> None:
    # Cross-checked against [data_governance] by the kernel validator; the
    # DLP binding adds governance, not risk.
    assert _manifest()["risk_tier"]["tier"] == "read_only"


def test_every_exposed_tool_declares_a_capability_class() -> None:
    """Every exposed tool declares the class enforced by AgentOS dispatch."""
    tools = _manifest()["tool"]["cognic"]["tools"]
    declared = {tool["name"]: tool["capability_class"] for tool in tools}
    assert declared == _EXPECTED_CAPABILITY_CLASSES
