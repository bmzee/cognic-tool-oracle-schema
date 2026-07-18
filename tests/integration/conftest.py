"""Fixtures + env gate for the live Oracle XE integration tests.

These run only when ``COGNIC_RUN_ORACLE_INTEGRATION=1`` AND a live, seeded Oracle
XE is reachable. Bring the DB up + seed it with::

    docker compose -f docker-compose.oracle.yml up -d

(the compose mounts ``tests/fixtures/seed_schema.sql`` into gvenzl's
``/container-entrypoint-initdb.d`` so the demo schema is created at first boot).

The env gate is the ONLY thing that skips. Once opted in, an unreachable or
unseeded DB FAILS LOUD — ``init_pool`` / the first ``acquire`` / a tool call
raises; the suite never silently skips on a connection error.

The ``oracle_pool`` fixture runs the SAME pool open/close body the FastMCP
server lifespan runs (``oracle.init_pool(cfg)`` then ``await oracle.close_pool()``
at teardown).
"""

import os
import pathlib
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from cognic_tool_oracle_schema import oracle
from cognic_tool_oracle_schema.config import Config

_RUN_INTEGRATION = os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION") == "1"
_INTEGRATION_DIR = pathlib.Path(__file__).parent


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Gate the whole integration package on ``COGNIC_RUN_ORACLE_INTEGRATION``.

    When not opted in, every test collected under ``tests/integration/`` is
    skipped — so the package is collected (visible) but skipped, with no errors
    and no live-DB requirement. Scoped to this directory (``item.path`` under
    ``tests/integration/``) so the unit suite is untouched even though
    ``pytest_collection_modifyitems`` receives the whole session's items.
    Belt-and-suspenders alongside each module's ``pytestmark`` skip.
    """
    if _RUN_INTEGRATION:
        return
    skip = pytest.mark.skip(
        reason="integration: set COGNIC_RUN_ORACLE_INTEGRATION=1 with a live Oracle XE",
    )
    for item in items:
        if _INTEGRATION_DIR in item.path.parents:
            item.add_marker(skip)


@pytest.fixture
def cfg(tmp_path: pathlib.Path) -> Config:
    """A Config wired to the integration Oracle from the integration env.

    Built directly (not via ``Config.from_env``) so the only env the integration
    run requires is the Oracle connection (DSN / USER / PASSWORD_FILE): the OAuth
    fields are irrelevant to the pool and the tools. Mirrors the unit suite's
    ``_cfg`` helper shape. Defaults match docker-compose.oracle.yml so the
    provided compose works out of the box.
    """
    owners_raw = os.environ.get("COGNIC_ORACLE_ALLOWED_OWNERS", "")
    configured_password_file = os.environ.get("COGNIC_ORACLE_PASSWORD_FILE")
    if configured_password_file is None:
        password_file = tmp_path / "oracle-password"
        password_file.write_text("cognic_dev_only", encoding="utf-8")
        configured_password_file = str(password_file)
    return Config(
        oracle_dsn=os.environ.get("COGNIC_ORACLE_DSN", "localhost:1521/XEPDB1"),
        oracle_user=os.environ.get("COGNIC_ORACLE_USER", "cognic"),
        oracle_password_file=configured_password_file,
        allowed_owners=frozenset(
            owner.strip().upper() for owner in owners_raw.split(",") if owner.strip()
        ),
        max_rows=int(os.environ.get("COGNIC_ORACLE_MAX_ROWS", "200")),
        pool_max=int(os.environ.get("COGNIC_ORACLE_POOL_MAX", "4")),
        auth_mode="dev_insecure",
        oauth_issuer=None,
        oauth_jwks_uri=None,
        oauth_audience=None,
        required_scopes=frozenset({"oracle_schema.read"}),
    )


@pytest.fixture
def app_owner() -> str:
    """The seeded schema owner (the gvenzl APP_USER), upper-cased as Oracle stores it."""
    return os.environ.get("COGNIC_ORACLE_USER", "cognic").strip().upper()


@pytest_asyncio.fixture
async def oracle_pool(cfg: Config) -> AsyncIterator[None]:
    """Open the real async Oracle pool for the test; close it at teardown.

    This is the SAME body the server lifespan runs. Opted-in-but-unreachable
    fails loud here (``init_pool`` / the first ``acquire`` raises) — never a
    silent skip.
    """
    oracle.init_pool(cfg)
    try:
        yield
    finally:
        await oracle.close_pool()
