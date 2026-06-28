from __future__ import annotations

import oracledb

from .config import Config

_pool: "oracledb.AsyncConnectionPool | None" = None


class OwnerNotAllowed(ValueError):
    """Owner not in COGNIC_ORACLE_ALLOWED_OWNERS (operator-visible product boundary)."""


def init_pool(cfg: Config) -> None:
    global _pool
    _pool = oracledb.create_pool_async(
        user=cfg.oracle_user,
        password=cfg.oracle_password,
        dsn=cfg.oracle_dsn,
        min=1,
        max=cfg.pool_max,
        increment=1,
    )


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def guard_owner(owner: str, cfg: Config) -> str:
    """Upper-case + (when an allow-list is configured) refuse owners not in it.

    Empty allow-list = trust the DB grant. The DB read-only grant is the hard
    boundary; this is the operator-visible product boundary.
    """
    norm = owner.strip().upper()
    if cfg.allowed_owners and norm not in cfg.allowed_owners:
        raise OwnerNotAllowed(f"owner {norm!r} not in COGNIC_ORACLE_ALLOWED_OWNERS")
    return norm


async def fetch(sql: str, binds: dict, *, limit: int, _pool=None) -> tuple[list[tuple], bool]:
    """Run a bounded read-only SELECT.

    Fetches limit+1 rows from the cursor to detect truncation; returns
    (rows[:limit], truncated).
    """
    pool = _pool if _pool is not None else _require_pool()
    async with pool.acquire() as conn:
        with conn.cursor() as cur:
            await cur.execute(sql, binds)
            fetched = await cur.fetchmany(limit + 1)
    return fetched[:limit], len(fetched) > limit


def _require_pool():
    if _pool is None:
        raise RuntimeError("oracle pool not initialised; call init_pool(cfg) at startup")
    return _pool
