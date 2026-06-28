"""The six read-only Oracle schema-metadata tools.

Safety boundary (verbatim from the design source of truth, #108): *"This is a
schema-metadata tool, not a database query tool. It never executes
user-supplied SQL, never queries application tables, never returns application
rows, and never performs DML/DDL."*

Every query below is a fixed string with bind variables (``:owner``, ``:tname``,
``:pat`` and generated ``:owner_N`` allow-list binds). Tool arguments are passed
as bind VALUES — never string-concatenated into the SQL text. Owner arguments
route through :func:`cognic_tool_oracle_schema.oracle.guard_owner` so an owner
outside ``COGNIC_ORACLE_ALLOWED_OWNERS`` is refused; ``list_schemas`` and the
ownerless ``find_columns`` path still constrain results to the configured
allow-list via generated ``:owner_N`` binds. Result bounding is enforced by
``oracle.fetch(...).fetchmany(limit + 1)``, not a fragile row-limit clause.
"""

from __future__ import annotations

from .config import Config
from .oracle import fetch, guard_owner

_LIST_SCHEMAS = "SELECT DISTINCT owner FROM all_tables WHERE {owner_filter} ORDER BY owner"
_LIST_TABLES = (
    "SELECT t.table_name, c.comments FROM all_tables t "
    "LEFT JOIN all_tab_comments c ON c.owner = t.owner AND c.table_name = t.table_name "
    "WHERE t.owner = :owner ORDER BY t.table_name"
)
_DESCRIBE_TABLE = (
    "SELECT col.column_name, col.data_type, col.nullable, col.data_default, cc.comments "
    "FROM all_tab_columns col "
    "LEFT JOIN all_col_comments cc ON cc.owner = col.owner "
    "AND cc.table_name = col.table_name AND cc.column_name = col.column_name "
    "WHERE col.owner = :owner AND col.table_name = :tname "
    "ORDER BY col.column_id"
)
_FIND_COLUMNS = (
    "SELECT owner, table_name, column_name, data_type FROM all_tab_columns "
    "WHERE column_name LIKE :pat AND {owner_filter} "
    "ORDER BY owner, table_name, column_name"
)
_LIST_RELATIONSHIPS = (
    "SELECT c.constraint_name, c.owner AS child_owner, c.table_name AS child_table, "
    "cc.column_name AS child_column, rc.owner AS parent_owner, rc.table_name AS parent_table, "
    "rcc.column_name AS parent_column "
    "FROM all_constraints c "
    "JOIN all_cons_columns cc ON cc.owner = c.owner AND cc.constraint_name = c.constraint_name "
    "JOIN all_constraints rc ON rc.owner = c.r_owner AND rc.constraint_name = c.r_constraint_name "
    "JOIN all_cons_columns rcc ON rcc.owner = rc.owner AND rcc.constraint_name = rc.constraint_name "
    "AND rcc.position = cc.position "
    "WHERE c.constraint_type = 'R' AND c.owner = :owner {table_filter} "
    "ORDER BY c.constraint_name, cc.position"
)
_GET_CONSTRAINTS = (
    "SELECT c.constraint_name, c.constraint_type, cc.column_name, c.search_condition, "
    "c.r_owner, c.r_constraint_name "
    "FROM all_constraints c "
    "LEFT JOIN all_cons_columns cc ON cc.owner = c.owner AND cc.constraint_name = c.constraint_name "
    "WHERE c.owner = :owner AND c.table_name = :tname "
    "ORDER BY c.constraint_name, cc.position"
)


def _owner_predicate(column: str, cfg: Config, *, owner: str | None = None) -> tuple[str, dict[str, str]]:
    """Build an owner predicate using bind variables only (never user values).

    - ``owner`` given → ``"<column> = :owner"`` with the guarded value.
    - ``owner`` omitted + no allow-list → ``"1 = 1"`` (trust the DB grant).
    - ``owner`` omitted + allow-list set → ``"<column> IN (:owner_0, …)"`` with
      generated binds carrying the (sorted) configured owners.
    """
    if owner is not None:
        return f"{column} = :owner", {"owner": guard_owner(owner, cfg)}
    if not cfg.allowed_owners:
        return "1 = 1", {}
    binds = {f"owner_{i}": value for i, value in enumerate(sorted(cfg.allowed_owners))}
    placeholders = ", ".join(f":{key}" for key in binds)
    return f"{column} IN ({placeholders})", binds


async def list_schemas(*, cfg: Config) -> dict:
    """List distinct schema owners (constrained to the allow-list when set)."""
    pred, binds = _owner_predicate("owner", cfg)
    sql = _LIST_SCHEMAS.format(owner_filter=pred)
    rows, truncated = await fetch(sql, binds, limit=cfg.max_rows)
    return {"items": [{"owner": r[0]} for r in rows], "truncated": truncated}


async def list_tables(*, cfg: Config, owner: str) -> dict:
    """List tables (with comments) for one owner."""
    rows, truncated = await fetch(
        _LIST_TABLES,
        {"owner": guard_owner(owner, cfg)},
        limit=cfg.max_rows,
    )
    items = [{"table_name": r[0], "comments": r[1]} for r in rows]
    return {"items": items, "truncated": truncated}


async def describe_table(*, cfg: Config, owner: str, table: str) -> dict:
    """Describe one table's columns (type / nullability / default / comment)."""
    rows, truncated = await fetch(
        _DESCRIBE_TABLE,
        {"owner": guard_owner(owner, cfg), "tname": table.strip().upper()},
        limit=cfg.max_rows,
    )
    columns = [
        {
            "column_name": r[0],
            "data_type": r[1],
            "nullable": r[2] == "Y",
            "data_default": (r[3].strip() if r[3] else None),
            "comments": r[4],
        }
        for r in rows
    ]
    return {"columns": columns, "truncated": truncated}


async def find_columns(*, cfg: Config, name_pattern: str, owner: str | None = None) -> dict:
    """Find columns by name LIKE pattern, optionally scoped to one owner."""
    pred, owner_binds = _owner_predicate("owner", cfg, owner=owner)
    sql = _FIND_COLUMNS.format(owner_filter=pred)
    binds = {"pat": name_pattern, **owner_binds}
    rows, truncated = await fetch(sql, binds, limit=cfg.max_rows)
    items = [
        {"owner": r[0], "table_name": r[1], "column_name": r[2], "data_type": r[3]}
        for r in rows
    ]
    return {"items": items, "truncated": truncated}


async def list_relationships(*, cfg: Config, owner: str, table: str | None = None) -> dict:
    """List foreign-key relationships for one owner (optionally one table)."""
    binds: dict[str, str] = {"owner": guard_owner(owner, cfg)}
    table_filter = ""
    if table is not None:
        table_filter = "AND c.table_name = :tname"
        binds["tname"] = table.strip().upper()
    sql = _LIST_RELATIONSHIPS.format(table_filter=table_filter)
    rows, truncated = await fetch(sql, binds, limit=cfg.max_rows)
    items = [
        {
            "constraint_name": r[0],
            "child_owner": r[1],
            "child_table": r[2],
            "child_column": r[3],
            "parent_owner": r[4],
            "parent_table": r[5],
            "parent_column": r[6],
        }
        for r in rows
    ]
    return {"items": items, "truncated": truncated}


async def get_constraints(*, cfg: Config, owner: str, table: str) -> dict:
    """List all constraints (PK / UK / CK / FK) for one table."""
    rows, truncated = await fetch(
        _GET_CONSTRAINTS,
        {"owner": guard_owner(owner, cfg), "tname": table.strip().upper()},
        limit=cfg.max_rows,
    )
    items = [
        {
            "constraint_name": r[0],
            "constraint_type": r[1],
            "column_name": r[2],
            "search_condition": r[3],
            "r_owner": r[4],
            "r_constraint_name": r[5],
        }
        for r in rows
    ]
    return {"items": items, "truncated": truncated}
