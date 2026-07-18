from __future__ import annotations

import oracledb

from .config import Config
from .credential import read_credential

_pool: "oracledb.AsyncConnectionPool | None" = None


class OwnerNotAllowed(ValueError):
    """Owner not in COGNIC_ORACLE_ALLOWED_OWNERS (operator-visible product boundary)."""


def init_pool(cfg: Config) -> None:
    global _pool
    credential = read_credential(cfg.oracle_password_file)
    _pool = oracledb.create_pool_async(
        user=cfg.oracle_user,
        password=credential.password,
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


def _is_auth_error(exc: BaseException) -> bool:
    args = getattr(exc, "args", ())
    err = args[0] if args else None
    return getattr(err, "full_code", "") == "ORA-01017"


async def _fetch_once(pool, sql: str, binds: dict, *, limit: int) -> tuple[list[tuple], bool]:
    async with pool.acquire() as conn:
        with conn.cursor() as cur:
            await cur.execute(sql, binds)
            fetched = await cur.fetchmany(limit + 1)
    return fetched[:limit], len(fetched) > limit


async def fetch(
    sql: str,
    binds: dict,
    *,
    limit: int,
    cfg: Config,
    _pool=None,
) -> tuple[list[tuple], bool]:
    """Run a bounded read-only SELECT.

    Fetches limit+1 rows from the cursor to detect truncation; returns
    (rows[:limit], truncated).
    """
    pool = _pool if _pool is not None else _require_pool()
    try:
        return await _fetch_once(pool, sql, binds, limit=limit)
    except Exception as exc:
        if not _is_auth_error(exc):
            raise
    await close_pool()
    init_pool(cfg)
    return await _fetch_once(_require_pool(), sql, binds, limit=limit)


def _require_pool():
    if _pool is None:
        raise RuntimeError("oracle pool not initialised; call init_pool(cfg) at startup")
    return _pool
