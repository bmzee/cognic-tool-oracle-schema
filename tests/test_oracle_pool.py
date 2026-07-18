from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cognic_tool_oracle_schema import oracle
from cognic_tool_oracle_schema.config import Config


def _cfg(path: Path) -> Config:
    return Config(
        oracle_dsn="localhost:1521/XEPDB1",
        oracle_user="ro_user",
        oracle_password_file=str(path),
        allowed_owners=frozenset(),
        max_rows=200,
        pool_max=4,
        auth_mode="dev_insecure",
        oauth_issuer=None,
        oauth_jwks_uri=None,
        oauth_audience=None,
        required_scopes=frozenset({"oracle_schema.read"}),
    )


class _OracleError:
    def __init__(self, full_code: str) -> None:
        self.full_code = full_code


def _db_error(full_code: str) -> Exception:
    return RuntimeError(_OracleError(full_code))


class _Cursor:
    def __init__(
        self,
        rows: list[tuple[Any, ...]],
        on_execute: Callable[[], None] | None = None,
    ) -> None:
        self._rows = rows
        self._on_execute = on_execute

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    async def execute(self, sql: str, binds: dict[str, Any]) -> None:
        if self._on_execute is not None:
            self._on_execute()

    async def fetchmany(self, limit: int) -> list[tuple[Any, ...]]:
        return self._rows[:limit]


class _Connection:
    def __init__(self, cursor: _Cursor) -> None:
        self._cursor = cursor

    def cursor(self) -> _Cursor:
        return self._cursor


class _Acquire:
    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    async def __aenter__(self) -> _Connection:
        return self._connection

    async def __aexit__(self, *exc: object) -> None:
        return None


class _Pool:
    def __init__(self, cursor: _Cursor) -> None:
        self._connection = _Connection(cursor)
        self.closed = False

    def acquire(self) -> _Acquire:
        return _Acquire(self._connection)

    async def close(self) -> None:
        self.closed = True


def test_init_pool_reads_password_from_the_configured_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "password"
    path.write_text("initial-file-value", encoding="utf-8")
    calls: list[dict[str, Any]] = []

    def _create_pool(**kwargs: Any) -> _Pool:
        calls.append(kwargs)
        return _Pool(_Cursor([]))

    monkeypatch.setattr(oracle.oracledb, "create_pool_async", _create_pool)

    oracle.init_pool(_cfg(path))

    assert calls == [
        {
            "user": "ro_user",
            "password": "initial-file-value",
            "dsn": "localhost:1521/XEPDB1",
            "min": 1,
            "max": 4,
            "increment": 1,
        }
    ]


@pytest.mark.asyncio
async def test_fetch_rebuilds_once_from_a_fresh_read_after_auth_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "password"
    path.write_text("before-rotation", encoding="utf-8")

    def _rotate_then_fail() -> None:
        path.write_text("after-rotation", encoding="utf-8")
        raise _db_error("ORA-01017")

    original = _Pool(_Cursor([], on_execute=_rotate_then_fail))
    created: list[dict[str, Any]] = []

    def _create_pool(**kwargs: Any) -> _Pool:
        created.append(kwargs)
        return _Pool(_Cursor([("ok",)]))

    monkeypatch.setattr(oracle, "_pool", original)
    monkeypatch.setattr(oracle.oracledb, "create_pool_async", _create_pool)

    result = await oracle.fetch("select 1 from dual", {}, limit=1, cfg=_cfg(path))

    assert result == ([("ok",)], False)
    assert original.closed is True
    assert [call["password"] for call in created] == ["after-rotation"]


@pytest.mark.asyncio
async def test_fetch_propagates_a_second_auth_failure_without_another_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "password"
    path.write_text("current-file-value", encoding="utf-8")

    def _fail_auth() -> None:
        raise _db_error("ORA-01017")

    original = _Pool(_Cursor([], on_execute=_fail_auth))
    created: list[dict[str, Any]] = []

    def _create_pool(**kwargs: Any) -> _Pool:
        created.append(kwargs)
        return _Pool(_Cursor([], on_execute=_fail_auth))

    monkeypatch.setattr(oracle, "_pool", original)
    monkeypatch.setattr(oracle.oracledb, "create_pool_async", _create_pool)

    with pytest.raises(RuntimeError) as caught:
        await oracle.fetch("select 1 from dual", {}, limit=1, cfg=_cfg(path))

    assert getattr(caught.value.args[0], "full_code") == "ORA-01017"
    assert len(created) == 1


@pytest.mark.asyncio
async def test_fetch_does_not_rebuild_for_non_authentication_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "password"
    path.write_text("current-file-value", encoding="utf-8")

    def _fail_query() -> None:
        raise RuntimeError("query-shape-failure")

    created: list[dict[str, Any]] = []
    monkeypatch.setattr(oracle, "_pool", _Pool(_Cursor([], on_execute=_fail_query)))
    monkeypatch.setattr(
        oracle.oracledb,
        "create_pool_async",
        lambda **kwargs: created.append(kwargs),
    )

    with pytest.raises(RuntimeError, match="query-shape-failure"):
        await oracle.fetch("select 1 from dual", {}, limit=1, cfg=_cfg(path))

    assert created == []


@pytest.mark.asyncio
async def test_fetch_propagates_no_argument_non_authentication_failure_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "password"
    path.write_text("current-file-value", encoding="utf-8")
    failure = RuntimeError()

    def _fail_query() -> None:
        raise failure

    monkeypatch.setattr(oracle, "_pool", _Pool(_Cursor([], on_execute=_fail_query)))

    with pytest.raises(RuntimeError) as caught:
        await oracle.fetch("select 1 from dual", {}, limit=1, cfg=_cfg(path))

    assert caught.value is failure
