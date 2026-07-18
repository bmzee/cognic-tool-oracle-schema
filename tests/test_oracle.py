import pytest

from cognic_tool_oracle_schema import oracle
from cognic_tool_oracle_schema.config import Config


def _cfg(
    *,
    oracle_dsn: str = "localhost:1521/XEPDB1",
    oracle_user: str = "ro_user",
    oracle_password_file: str = "/run/secrets/oracle-password",
    allowed_owners: frozenset[str] = frozenset(),
    max_rows: int = 200,
    pool_max: int = 4,
    auth_mode: str = "dev_insecure",
    oauth_issuer: str | None = None,
    oauth_jwks_uri: str | None = None,
    oauth_audience: str | None = None,
    required_scopes: frozenset[str] = frozenset({"oracle_schema.read"}),
) -> Config:
    """Build a Config; any field overridable via keyword (typed for mypy)."""
    return Config(
        oracle_dsn=oracle_dsn,
        oracle_user=oracle_user,
        oracle_password_file=oracle_password_file,
        allowed_owners=allowed_owners,
        max_rows=max_rows,
        pool_max=pool_max,
        auth_mode=auth_mode,
        oauth_issuer=oauth_issuer,
        oauth_jwks_uri=oauth_jwks_uri,
        oauth_audience=oauth_audience,
        required_scopes=required_scopes,
    )


class _FakeCursor:
    """Sync-context-manager cursor with async ``execute``/``fetchmany``.

    Records ``execute`` calls so SQL + binds are available for assertions, and
    returns ``rows[:n]`` from ``fetchmany`` (the bounded-fetch seam).
    """

    def __init__(self, rows):
        self._rows = rows
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    async def execute(self, sql, binds):
        self.executed.append((sql, binds))

    async def fetchmany(self, n):
        return self._rows[:n]


class _FakeConn:
    """Fake connection whose ``cursor()`` is a sync context manager."""

    def __init__(self, rows):
        self.cursor_obj = _FakeCursor(rows)

    def cursor(self):
        return self.cursor_obj


class _FakeAcquire:
    """Async context manager returned by ``pool.acquire()``."""

    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *exc):
        return False


class _FakePool:
    """Mimics the oracledb async pool surface used by ``oracle.fetch``."""

    def __init__(self, rows):
        self._conn = _FakeConn(rows)

    def acquire(self):
        return _FakeAcquire(self._conn)


def test_guard_owner_allows_when_no_allowlist():
    assert oracle.guard_owner("hr", _cfg(allowed_owners=frozenset())) == "HR"


def test_guard_owner_refuses_outside_allowlist():
    with pytest.raises(oracle.OwnerNotAllowed):
        oracle.guard_owner("SECRET", _cfg(allowed_owners=frozenset({"HR"})))


@pytest.mark.asyncio
async def test_fetch_sets_truncated_when_over_limit(monkeypatch):
    # fake pool/cursor returning limit+1 rows; assert truncated True + rows trimmed to limit
    rows = await oracle.fetch(
        "select 1 from dual",
        {},
        limit=2,
        cfg=_cfg(),
        _pool=_FakePool([("a",), ("b",), ("c",)]),
    )
    assert rows == ([("a",), ("b",)], True)
