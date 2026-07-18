"""Envelope tests for the run_readonly_query orchestrator (arms 1-7).

Fake-connect / no-DB: the Oracle leg is a recorded async factory so every
refusal arm is proven to short-circuit BEFORE any connection is attempted
(arms 1-6 are PURE pre-checks). Every refusal returns the graceful
``{ok: false, reason, message}`` envelope — never exception text.
"""

from __future__ import annotations

import logging
import os
import pathlib
from datetime import UTC, datetime
from typing import Any
from typing import get_args

import pytest

from cognic_tool_oracle_schema import credential, readonly_query
from cognic_tool_oracle_schema.config import Config
from cognic_tool_oracle_schema.credential import CredentialRead
from cognic_tool_oracle_schema.readonly_query import RefusalReason, ReplayCache
from tests._token_helpers import (
    NOW,
    args_sha256_for,
    claims_dict,
    generate_keypair,
    mint,
    write_keys_env,
)

_SQL = "SELECT full_name FROM cognic.v_employee_directory"
_SCOPE = "retail_analytics"
_OBJECTS = ["COGNIC.V_EMPLOYEE_DIRECTORY"]
_CREDENTIAL_VALUE = "fixture-only-query-credential"
_ROTATION_REF = "2026-07-18T00:00:00+00:00"


def _cfg(oracle_password_file: str = "/run/secrets/oracle-password") -> Config:
    return Config(
        oracle_dsn="localhost:1521/XEPDB1",
        oracle_user="app_user",
        oracle_password_file=oracle_password_file,
        allowed_owners=frozenset(),
        max_rows=200,
        pool_max=4,
        auth_mode="dev_insecure",
        oauth_issuer=None,
        oauth_jwks_uri=None,
        oauth_audience=None,
        required_scopes=frozenset({"oracle_schema.read"}),
    )


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def keys_env(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, keypair: tuple[bytes, bytes]
) -> None:
    write_keys_env(tmp_path, monkeypatch, keypair[1])


@pytest.fixture(autouse=True)
def credential_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        readonly_query,
        "read_credential",
        lambda _path: CredentialRead(
            password=_CREDENTIAL_VALUE,
            rotation_ref=_ROTATION_REF,
        ),
    )


class _FakeCursor:
    def __init__(
        self,
        rows: list[tuple],
        description: list[tuple],
        callproc_raises: Exception | None = None,
    ) -> None:
        self._rows = rows
        self.description = description
        self.callproc_raises = callproc_raises
        self.executed: list[str] = []
        self.operations: list[tuple[Any, ...]] = []

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    async def execute(self, sql: str) -> None:
        self.operations.append(("execute", sql))
        self.executed.append(sql)

    async def callproc(self, name: str, parameters: list[str]) -> None:
        self.operations.append(("callproc", name, tuple(parameters)))
        if self.callproc_raises is not None:
            raise self.callproc_raises

    async def fetchall(self) -> list[tuple]:
        return self._rows


class _FakeConn:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor
        self.call_timeout: int | None = None
        self.closed = False

    def cursor(self) -> _FakeCursor:
        return self._cursor

    async def close(self) -> None:
        self.closed = True


class _ConnectRecorder:
    """Async stand-in for oracledb.connect_async; records connect kwargs."""

    def __init__(
        self,
        rows: list[tuple] | None = None,
        description: list[tuple] | None = None,
        raises: Exception | list[Exception | None] | None = None,
        callproc_raises: Exception | None = None,
    ) -> None:
        self.rows = rows if rows is not None else []
        self.description = description if description is not None else []
        self.raises = raises
        self.callproc_raises = callproc_raises
        self.calls: list[dict[str, Any]] = []
        self.conns: list[_FakeConn] = []

    async def __call__(self, **kwargs: Any) -> _FakeConn:
        self.calls.append(kwargs)
        failure = self.raises[len(self.calls) - 1] if isinstance(self.raises, list) else self.raises
        if failure is not None:
            raise failure
        conn = _FakeConn(
            _FakeCursor(
                self.rows,
                self.description,
                callproc_raises=self.callproc_raises,
            )
        )
        self.conns.append(conn)
        return conn


def _minted(
    keypair: tuple[bytes, bytes],
    *,
    sql: str = _SQL,
    scope_id: str = _SCOPE,
    max_rows: int | None = None,
    **claim_overrides: Any,
) -> str:
    payload = claims_dict(
        scope_id=scope_id,
        objects=claim_overrides.pop("objects", list(_OBJECTS)),
        args_sha256=claim_overrides.pop("args_sha256", args_sha256_for(scope_id, sql, max_rows)),
        **claim_overrides,
    )
    return mint(payload, keypair[0])


async def _call(
    *,
    token: str,
    connect: _ConnectRecorder,
    sql: str = _SQL,
    scope_id: str = _SCOPE,
    max_rows: int | None = None,
    replay: ReplayCache | None = None,
    now: int = NOW,
    cfg: Config | None = None,
) -> dict[str, Any]:
    return await readonly_query.run(
        cfg=cfg if cfg is not None else _cfg(),
        scope_id=scope_id,
        sql=sql,
        max_rows=max_rows,
        token=token,
        _now=lambda: now,
        _connect=connect,
        _replay=replay if replay is not None else ReplayCache(),
    )


def _assert_refusal(result: dict[str, Any], reason: str) -> None:
    assert result["ok"] is False
    assert result["reason"] == reason
    assert isinstance(result["message"], str) and result["message"]
    # graceful — never a traceback dump
    assert "Traceback" not in result["message"]
    assert set(result.keys()) == {"ok", "reason", "message"}


def test_refusal_reason_vocabulary_is_closed() -> None:
    assert get_args(RefusalReason) == (
        "query_context_missing_or_invalid",
        "query_context_replayed",
        "query_context_args_mismatch",
        "sql_parse_failed",
        "sql_not_select_only",
        "agent_sql_object_out_of_scope",
        "query_identity_stamp_failed",
        "query_execution_failed",
    )


# --- arm 1: verify ---------------------------------------------------------------


class TestArm1Verify:
    async def test_keys_env_unset_refuses(
        self, monkeypatch: pytest.MonkeyPatch, keypair: tuple[bytes, bytes]
    ) -> None:
        monkeypatch.delenv("COGNIC_QUERY_CONTEXT_PUBLIC_KEYS", raising=False)
        connect = _ConnectRecorder()
        result = await _call(token=_minted(keypair), connect=connect)
        _assert_refusal(result, "query_context_missing_or_invalid")
        assert connect.calls == []

    async def test_keys_env_blank_refuses(
        self, monkeypatch: pytest.MonkeyPatch, keypair: tuple[bytes, bytes]
    ) -> None:
        monkeypatch.setenv("COGNIC_QUERY_CONTEXT_PUBLIC_KEYS", " , ")
        connect = _ConnectRecorder()
        result = await _call(token=_minted(keypair), connect=connect)
        _assert_refusal(result, "query_context_missing_or_invalid")

    async def test_keys_path_unreadable_refuses(
        self,
        tmp_path: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
        keypair: tuple[bytes, bytes],
    ) -> None:
        monkeypatch.setenv("COGNIC_QUERY_CONTEXT_PUBLIC_KEYS", str(tmp_path / "missing.pem"))
        connect = _ConnectRecorder()
        result = await _call(token=_minted(keypair), connect=connect)
        _assert_refusal(result, "query_context_missing_or_invalid")

    async def test_keys_file_empty_refuses(
        self,
        tmp_path: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
        keypair: tuple[bytes, bytes],
    ) -> None:
        empty = tmp_path / "empty.pem"
        empty.write_bytes(b"")
        monkeypatch.setenv("COGNIC_QUERY_CONTEXT_PUBLIC_KEYS", str(empty))
        connect = _ConnectRecorder()
        result = await _call(token=_minted(keypair), connect=connect)
        _assert_refusal(result, "query_context_missing_or_invalid")

    async def test_token_absent_refuses(self, keys_env: None) -> None:
        connect = _ConnectRecorder()
        result = await _call(token="", connect=connect)
        _assert_refusal(result, "query_context_missing_or_invalid")
        assert connect.calls == []

    async def test_token_garbage_refuses(self, keys_env: None) -> None:
        connect = _ConnectRecorder()
        result = await _call(token="not-a-jws", connect=connect)
        _assert_refusal(result, "query_context_missing_or_invalid")

    async def test_token_expired_refuses(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        connect = _ConnectRecorder()
        token = _minted(keypair)
        result = await _call(token=token, connect=connect, now=NOW + 10_000)
        _assert_refusal(result, "query_context_missing_or_invalid")

    async def test_token_wrong_audience_refuses(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        connect = _ConnectRecorder()
        token = _minted(keypair, aud="cognic-tool-oracle-schema/list_tables")
        result = await _call(token=token, connect=connect)
        _assert_refusal(result, "query_context_missing_or_invalid")

    async def test_second_rotation_key_verifies(
        self,
        tmp_path: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
        keypair: tuple[bytes, bytes],
    ) -> None:
        other = generate_keypair()
        # env lists [new, old]; the token is signed with the OLD key
        write_keys_env(tmp_path, monkeypatch, other[1], keypair[1])
        connect = _ConnectRecorder(rows=[("Ada",)], description=[("FULL_NAME",)])
        result = await _call(token=_minted(keypair), connect=connect)
        assert result["ok"] is True


# --- arm 2: replay ---------------------------------------------------------------


class TestArm2Replay:
    async def test_same_jti_twice_refuses_second(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        replay = ReplayCache()
        token = _minted(keypair, jti="a" * 32)
        connect = _ConnectRecorder(rows=[("Ada",)], description=[("FULL_NAME",)])
        first = await _call(token=token, connect=connect, replay=replay)
        assert first["ok"] is True
        second = await _call(token=token, connect=connect, replay=replay)
        _assert_refusal(second, "query_context_replayed")
        # only the FIRST call reached the DB
        assert len(connect.calls) == 1

    async def test_distinct_jtis_both_pass(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        replay = ReplayCache()
        connect = _ConnectRecorder(rows=[], description=[])
        r1 = await _call(token=_minted(keypair, jti="b" * 32), connect=connect, replay=replay)
        r2 = await _call(token=_minted(keypair, jti="c" * 32), connect=connect, replay=replay)
        assert r1["ok"] is True and r2["ok"] is True

    async def test_cache_evicts_expired_jtis(self) -> None:
        cache = ReplayCache()
        assert cache.check_and_insert("j1", exp=NOW + 10, now=NOW) is True
        # after exp the entry is evicted on read — a NEW token could reuse the
        # jti string, but a REAL replay of the old token refuses at arm 1
        # (expired) before the cache is consulted.
        assert cache.check_and_insert("j1", exp=NOW + 200, now=NOW + 60) is True
        assert cache.check_and_insert("j1", exp=NOW + 200, now=NOW + 61) is False

    async def test_expired_token_never_enters_replay_cache(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        replay = ReplayCache()
        token = _minted(keypair, jti="d" * 32)
        connect = _ConnectRecorder()
        result = await _call(token=token, connect=connect, now=NOW + 10_000)
        _assert_refusal(result, "query_context_missing_or_invalid")
        assert replay.check_and_insert("d" * 32, exp=NOW + 10_120, now=NOW) is True


# --- arm 3: args digest ------------------------------------------------------------


class TestArm3ArgsDigest:
    async def test_different_sql_refuses_mismatch(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        # token minted for SQL A, called with SQL B
        token = _minted(keypair, sql="SELECT 1 FROM dual")
        connect = _ConnectRecorder()
        result = await _call(token=token, connect=connect, sql="SELECT 2 FROM dual")
        _assert_refusal(result, "query_context_args_mismatch")
        assert connect.calls == []

    async def test_different_scope_id_refuses_mismatch(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        # scope_id is part of the digest basis; the token's OWN scope_id claim
        # matches but the digest was minted over another scope_id argument.
        token = _minted(keypair, args_sha256=args_sha256_for("other_scope", _SQL))
        connect = _ConnectRecorder()
        result = await _call(token=token, connect=connect)
        _assert_refusal(result, "query_context_args_mismatch")

    async def test_max_rows_added_after_mint_refuses_mismatch(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        # minted WITHOUT max_rows; called WITH max_rows → basis differs
        token = _minted(keypair, max_rows=None)
        connect = _ConnectRecorder()
        result = await _call(token=token, connect=connect, max_rows=50)
        _assert_refusal(result, "query_context_args_mismatch")

    async def test_max_rows_present_in_both_passes(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        token = _minted(keypair, max_rows=50)
        connect = _ConnectRecorder(rows=[], description=[])
        result = await _call(token=token, connect=connect, max_rows=50)
        assert result["ok"] is True


# --- arms 4-5 through the envelope ---------------------------------------------------


class TestArm4And5Envelope:
    async def test_non_select_refuses_envelope(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        sql = "DELETE FROM cognic.v_employee_directory"
        token = _minted(keypair, sql=sql)
        connect = _ConnectRecorder()
        result = await _call(token=token, connect=connect, sql=sql)
        _assert_refusal(result, "sql_not_select_only")
        assert connect.calls == []

    async def test_parse_error_refuses_envelope(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        sql = "SELEKT foo FRUM bar"
        token = _minted(keypair, sql=sql)
        connect = _ConnectRecorder()
        result = await _call(token=token, connect=connect, sql=sql)
        _assert_refusal(result, "sql_parse_failed")

    async def test_out_of_scope_object_refuses(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        sql = "SELECT * FROM cognic.employees"
        token = _minted(keypair, sql=sql)
        connect = _ConnectRecorder()
        result = await _call(token=token, connect=connect, sql=sql)
        _assert_refusal(result, "agent_sql_object_out_of_scope")
        assert "COGNIC.EMPLOYEES" in result["message"]
        assert connect.calls == []

    async def test_out_of_scope_object_buried_in_join_refuses(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        sql = (
            "SELECT d.full_name FROM cognic.v_employee_directory d "
            "JOIN (SELECT employee_id FROM cognic.salaries_raw) s "
            "ON s.employee_id = d.employee_id"
        )
        token = _minted(keypair, sql=sql)
        connect = _ConnectRecorder()
        result = await _call(token=token, connect=connect, sql=sql)
        _assert_refusal(result, "agent_sql_object_out_of_scope")
        assert "COGNIC.SALARIES_RAW" in result["message"]

    async def test_in_scope_cte_query_passes(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        sql = (
            "WITH top_e AS (SELECT full_name FROM cognic.v_employee_directory) SELECT * FROM top_e"
        )
        token = _minted(keypair, sql=sql)
        connect = _ConnectRecorder(rows=[("Ada",)], description=[("FULL_NAME",)])
        result = await _call(token=token, connect=connect, sql=sql)
        assert result["ok"] is True


# --- arms 6-7: bound + execution -----------------------------------------------------


class TestArm6And7Execution:
    async def test_success_envelope_shape(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        connect = _ConnectRecorder(
            rows=[("Ada Lovelace",), ("Alan Turing",)], description=[("FULL_NAME",)]
        )
        result = await _call(token=_minted(keypair), connect=connect)
        assert result == {
            "ok": True,
            "rows": [{"FULL_NAME": "Ada Lovelace"}, {"FULL_NAME": "Alan Turing"}],
            "row_count": 2,
            "truncated": False,
            "credential_rotation_ref": _ROTATION_REF,
        }

    async def test_executed_sql_carries_fetch_first_bound(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        connect = _ConnectRecorder(rows=[], description=[])
        token = _minted(keypair, max_rows=7)
        result = await _call(token=token, connect=connect, max_rows=7)
        assert result["ok"] is True
        executed = connect.conns[0].cursor().executed
        assert len(executed) == 1
        assert "FETCH FIRST 7 ROWS ONLY" in executed[0]

    async def test_truncated_true_when_bound_filled(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        rows = [(i,) for i in range(3)]
        connect = _ConnectRecorder(rows=rows, description=[("N",)])
        token = _minted(keypair, max_rows=3)
        result = await _call(token=token, connect=connect, max_rows=3)
        assert result["ok"] is True
        assert result["truncated"] is True
        assert result["row_count"] == 3

    async def test_proxy_auth_connect_user_string(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        connect = _ConnectRecorder(rows=[], description=[])
        result = await _call(token=_minted(keypair), connect=connect)
        assert result["ok"] is True
        assert connect.calls[0]["user"] == "app_user[AGENT_RO]"
        assert connect.calls[0]["password"] == _CREDENTIAL_VALUE
        assert connect.calls[0]["dsn"] == "localhost:1521/XEPDB1"

    async def test_verified_subject_is_stamped_before_user_sql(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        connect = _ConnectRecorder(rows=[], description=[])

        result = await _call(token=_minted(keypair), connect=connect)

        assert result["ok"] is True
        assert connect.conns[0].cursor().operations == [
            ("callproc", "dbms_session.set_identifier", ("analyst.amir",)),
            ("execute", connect.conns[0].cursor().executed[0]),
        ]

    async def test_identity_stamp_failure_refuses_before_sql_and_closes_connection(
        self,
        keys_env: None,
        keypair: tuple[bytes, bytes],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        connect = _ConnectRecorder(
            callproc_raises=RuntimeError(_CREDENTIAL_VALUE),
        )

        with caplog.at_level(logging.WARNING, logger=readonly_query.__name__):
            result = await _call(token=_minted(keypair), connect=connect)

        _assert_refusal(result, "query_identity_stamp_failed")
        assert connect.conns[0].cursor().executed == []
        assert connect.conns[0].closed is True
        assert _CREDENTIAL_VALUE not in repr(result)
        assert all(_CREDENTIAL_VALUE not in repr(vars(record)) for record in caplog.records)

    async def test_oversized_verified_subject_refuses_before_connect(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        connect = _ConnectRecorder()
        token = _minted(keypair, sub="é" * 33)

        result = await _call(token=token, connect=connect)

        _assert_refusal(result, "query_identity_stamp_failed")
        assert connect.calls == []

    async def test_success_rotation_reference_comes_from_file_mtime(
        self,
        tmp_path: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
        keys_env: None,
        keypair: tuple[bytes, bytes],
    ) -> None:
        credential_path = tmp_path / "password"
        credential_path.write_text(_CREDENTIAL_VALUE, encoding="utf-8")
        mtime = 1_767_225_600
        os.utime(credential_path, (mtime, mtime))
        monkeypatch.setattr(readonly_query, "read_credential", credential.read_credential)
        connect = _ConnectRecorder()

        result = await _call(
            token=_minted(keypair),
            connect=connect,
            cfg=_cfg(str(credential_path)),
        )

        assert result["ok"] is True
        assert (
            result["credential_rotation_ref"] == datetime.fromtimestamp(mtime, tz=UTC).isoformat()
        )

    async def test_auth_failure_rereads_once_retries_once_then_refuses(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keys_env: None,
        keypair: tuple[bytes, bytes],
    ) -> None:
        class _OracleError:
            full_code = "ORA-01017"

        reads: list[str] = []

        def _read(path: str) -> CredentialRead:
            reads.append(path)
            return CredentialRead(
                password=f"attempt-{len(reads)}",
                rotation_ref=f"rotation-{len(reads)}",
            )

        monkeypatch.setattr(readonly_query, "read_credential", _read)
        connect = _ConnectRecorder(
            raises=[RuntimeError(_OracleError()), RuntimeError(_OracleError())]
        )

        result = await _call(token=_minted(keypair), connect=connect)

        _assert_refusal(result, "query_execution_failed")
        assert len(reads) == 2
        assert len(connect.calls) == 2

    async def test_call_timeout_applied_and_connection_closed(
        self,
        keys_env: None,
        keypair: tuple[bytes, bytes],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("COGNIC_ORACLE_QUERY_TIMEOUT_S", "12")
        connect = _ConnectRecorder(rows=[], description=[])
        result = await _call(token=_minted(keypair), connect=connect)
        assert result["ok"] is True
        conn = connect.conns[0]
        assert conn.call_timeout == 12_000
        assert conn.closed is True

    async def test_db_error_refuses_gracefully_without_leaking_text(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        connect = _ConnectRecorder(
            raises=RuntimeError("ORA-01017: invalid username/password secret-dsn-details")
        )
        result = await _call(token=_minted(keypair), connect=connect)
        _assert_refusal(result, "query_execution_failed")
        # exception CLASS name at most — never str(exc)
        assert "ORA-01017" not in result["message"]
        assert "secret-dsn-details" not in result["message"]
        assert "RuntimeError" in result["message"]

    async def test_malformed_proxy_identity_refuses_before_connect(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        token = _minted(keypair, proxy_db_identity="x] AS SYSDBA --")
        connect = _ConnectRecorder()
        result = await _call(token=token, connect=connect)
        _assert_refusal(result, "query_execution_failed")
        assert connect.calls == []

    async def test_connection_closed_even_when_execute_raises(
        self, keys_env: None, keypair: tuple[bytes, bytes]
    ) -> None:
        class _BoomCursor(_FakeCursor):
            async def execute(self, sql: str) -> None:
                raise RuntimeError("ORA-00942: table or view does not exist")

        class _BoomConnect(_ConnectRecorder):
            async def __call__(self, **kwargs: Any) -> _FakeConn:
                self.calls.append(kwargs)
                conn = _FakeConn(_BoomCursor([], []))
                self.conns.append(conn)
                return conn

        connect = _BoomConnect()
        result = await _call(token=_minted(keypair), connect=connect)
        _assert_refusal(result, "query_execution_failed")
        assert connect.conns[0].closed is True
