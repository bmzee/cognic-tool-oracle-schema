"""Pack-manifest contract tests (v0.2.0 — the M5 DLP hook binding)."""

from __future__ import annotations

import pathlib
import tomllib

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _manifest() -> dict:
    return tomllib.loads((_ROOT / "cognic-pack-manifest.toml").read_text())


def _pyproject() -> dict:
    return tomllib.loads((_ROOT / "pyproject.toml").read_text())


def test_version_is_0_2_0() -> None:
    assert _pyproject()["project"]["version"] == "0.2.0"


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
