"""Live-XE integration tests for run_readonly_query (env-gated, M8 v0.3.0).

Runs only with ``COGNIC_RUN_ORACLE_INTEGRATION=1`` against the seeded compose
XE (see docker-compose.oracle.yml). The v0.3.0 seed additions create:

* ``AGENT_RO`` — the proxy DB identity, ``GRANT CONNECT THROUGH cognic``,
  with SELECT on the governed view ONLY (the engine backstop);
* ``COGNIC.V_EMPLOYEE_DIRECTORY`` — the governed view over
  ``COGNIC.EMPLOYEES`` (no salary/email columns).

NOTE (first-boot seeds): gvenzl applies seed_schema.sql once, on the FIRST
boot of a fresh volume. If the volume predates v0.3.0, re-seed with
``docker compose -f docker-compose.oracle.yml down -v`` then ``up -d``.

Tokens are minted in-test (throwaway RSA keypair via tests/_token_helpers —
the same attached-JWS wire form the kernel mints); the cross-repo kernel-mint
pin lives in tests/test_kernel_wire_pin.py.
"""

from __future__ import annotations

import pathlib
import time

import pytest

from cognic_tool_oracle_schema import readonly_query
from cognic_tool_oracle_schema.config import Config
from cognic_tool_oracle_schema.readonly_query import ReplayCache
from tests._token_helpers import (
    args_sha256_for,
    claims_dict,
    generate_keypair,
    mint,
    write_keys_env,
)

pytestmark = pytest.mark.oracle

_GOVERNED_VIEW = "COGNIC.V_EMPLOYEE_DIRECTORY"


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def keys_env(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, keypair: tuple[bytes, bytes]
) -> None:
    write_keys_env(tmp_path, monkeypatch, keypair[1])


def _live_token(
    keypair: tuple[bytes, bytes],
    *,
    sql: str,
    scope_id: str = "retail_analytics",
    objects: list[str] | None = None,
    max_rows: int | None = None,
) -> str:
    now = int(time.time())
    payload = claims_dict(
        scope_id=scope_id,
        objects=objects if objects is not None else [_GOVERNED_VIEW],
        args_sha256=args_sha256_for(scope_id, sql, max_rows),
        iat=now,
        exp=now + 120,
    )
    return mint(payload, keypair[0])


async def _run(cfg: Config, keypair: tuple[bytes, bytes], sql: str, **kwargs) -> dict:
    token = _live_token(keypair, sql=sql, **kwargs)
    return await readonly_query.run(
        cfg=cfg,
        scope_id=kwargs.get("scope_id", "retail_analytics"),
        sql=sql,
        max_rows=kwargs.get("max_rows"),
        token=token,
        _replay=ReplayCache(),
    )


@pytest.mark.asyncio
async def test_proxy_auth_session_runs_as_token_identity(
    cfg: Config, keys_env: None, keypair: tuple[bytes, bytes]
) -> None:
    """The session RUNS AS the token's proxy_db_identity: SESSION_USER is
    AGENT_RO while PROXY_USER is the authenticating app account (cognic)."""
    sql = (
        "SELECT SYS_CONTEXT('USERENV','SESSION_USER') AS session_user_name, "
        "SYS_CONTEXT('USERENV','PROXY_USER') AS proxy_user_name FROM dual"
    )
    result = await _run(cfg, keypair, sql, objects=["DUAL"])
    assert result["ok"] is True, result
    row = result["rows"][0]
    assert row["SESSION_USER_NAME"] == "AGENT_RO"
    assert row["PROXY_USER_NAME"] == cfg.oracle_user.upper()


@pytest.mark.asyncio
async def test_governed_view_select_returns_rows(
    cfg: Config, keys_env: None, keypair: tuple[bytes, bytes]
) -> None:
    sql = "SELECT employee_id, full_name FROM cognic.v_employee_directory ORDER BY employee_id"
    result = await _run(cfg, keypair, sql)
    assert result["ok"] is True, result
    assert result["row_count"] >= 2
    names = [r["FULL_NAME"] for r in result["rows"]]
    assert "Ada Lovelace" in names
    # governed view exposes NO salary/email columns
    assert all("SALARY" not in r and "EMAIL" not in r for r in result["rows"])


@pytest.mark.asyncio
async def test_row_bound_enforced_live(
    cfg: Config, keys_env: None, keypair: tuple[bytes, bytes]
) -> None:
    sql = "SELECT employee_id FROM cognic.v_employee_directory ORDER BY employee_id"
    result = await _run(cfg, keypair, sql, max_rows=1)
    assert result["ok"] is True, result
    assert result["row_count"] == 1
    assert result["truncated"] is True


@pytest.mark.asyncio
async def test_engine_backstop_refuses_ungranted_base_table(
    cfg: Config, keys_env: None, keypair: tuple[bytes, bytes]
) -> None:
    """Even when a (misconfigured) token scope names the base table, the
    proxy identity's grants are the engine backstop: AGENT_RO has SELECT on
    the governed view only, so the base table raises ORA-00942 and the
    envelope stays graceful."""
    sql = "SELECT salary FROM cognic.employees"
    result = await _run(cfg, keypair, sql, objects=["COGNIC.EMPLOYEES"])
    assert result["ok"] is False
    assert result["reason"] == "query_execution_failed"
    assert "ORA-00942" not in result["message"]  # class name at most, never DB text


@pytest.mark.asyncio
async def test_out_of_scope_object_refused_before_touching_db(
    cfg: Config, keys_env: None, keypair: tuple[bytes, bytes]
) -> None:
    sql = "SELECT salary FROM cognic.employees"
    result = await _run(cfg, keypair, sql)  # token objects = governed view only
    assert result["ok"] is False
    assert result["reason"] == "agent_sql_object_out_of_scope"
