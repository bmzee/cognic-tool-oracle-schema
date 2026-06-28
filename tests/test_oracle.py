import pytest

from cognic_tool_oracle_schema import oracle
from cognic_tool_oracle_schema.config import Config


def _cfg(**kw) -> Config:
    """Build a minimal, fully-populated ``Config``.

    Every field is populated with a sensible default; ``allowed_owners`` and
    ``max_rows`` (indeed any field) are overridable via ``**kw``.
    """
    defaults = {
        "oracle_dsn": "localhost:1521/XEPDB1",
        "oracle_user": "ro_user",
        "oracle_password": "pw",
        "allowed_owners": frozenset(),
        "max_rows": 200,
        "pool_max": 4,
        "auth_mode": "dev_insecure",
        "oauth_issuer": None,
        "oauth_jwks_uri": None,
        "oauth_audience": None,
        "required_scopes": frozenset({"oracle_schema.read"}),
    }
    defaults.update(kw)
    return Config(**defaults)


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
        "select 1 from dual", {}, limit=2, _pool=_FakePool([("a",), ("b",), ("c",)])
    )
    assert rows == ([("a",), ("b",)], True)
