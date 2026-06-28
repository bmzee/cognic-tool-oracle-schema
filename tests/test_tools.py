"""Unit tests for the six read-only Oracle schema-metadata tools.

Fake-cursor / no-DB: every test monkeypatches ``tools.fetch`` with an async
recorder that captures the ``(sql, binds, limit)`` it was called with and
returns a caller-supplied ``(rows, truncated)``. The real ``guard_owner`` /
``_owner_predicate`` run, so the allow-list boundary is exercised for real.

Covers the plan's five per-tool requirements:
(a) each tool's SQL references the correct ``all_*`` view(s);
(b) user args arrive as bind VALUES (in the binds dict), never concatenated
    into the SQL text;
(c) owner args route through ``guard_owner`` → ``OwnerNotAllowed`` outside a
    configured allow-list;
(d) ``list_schemas`` + ownerless ``find_columns`` still constrain to the
    configured allow-list via generated ``:owner_N`` binds (or ``1 = 1`` when
    no allow-list);
(e) ``truncated`` is passed through from ``fetch`` and ``limit`` is
    ``cfg.max_rows``.
"""

import pytest

from cognic_tool_oracle_schema import oracle, tools
from cognic_tool_oracle_schema.config import Config


def _cfg(
    *,
    oracle_dsn: str = "localhost:1521/XEPDB1",
    oracle_user: str = "ro_user",
    oracle_password: str = "pw",
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
        oracle_password=oracle_password,
        allowed_owners=allowed_owners,
        max_rows=max_rows,
        pool_max=pool_max,
        auth_mode=auth_mode,
        oauth_issuer=oauth_issuer,
        oauth_jwks_uri=oauth_jwks_uri,
        oauth_audience=oauth_audience,
        required_scopes=required_scopes,
    )


class _FetchRecorder:
    """Async stand-in for ``tools.fetch``.

    Records every ``(sql, binds, limit)`` call and returns a caller-supplied
    ``(rows, truncated)`` tuple — the same shape the real ``oracle.fetch``
    yields.
    """

    def __init__(self, rows=(), truncated=False):
        self.rows = list(rows)
        self.truncated = truncated
        self.calls = []

    async def __call__(self, sql, binds, *, limit):
        self.calls.append((sql, binds, limit))
        return self.rows, self.truncated

    @property
    def sql(self):
        return self.calls[-1][0]

    @property
    def binds(self):
        return self.calls[-1][1]

    @property
    def limit(self):
        return self.calls[-1][2]


def _install_fetch(monkeypatch, rows=(), truncated=False) -> _FetchRecorder:
    recorder = _FetchRecorder(rows=rows, truncated=truncated)
    monkeypatch.setattr(tools, "fetch", recorder)
    return recorder


# --------------------------------------------------------------------------- #
# list_schemas
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_list_schemas_no_allowlist_uses_all_tables_and_1_eq_1(monkeypatch):
    rec = _install_fetch(monkeypatch, rows=[("HR",), ("SALES",)], truncated=False)
    out = await tools.list_schemas(cfg=_cfg(allowed_owners=frozenset()))
    assert "all_tables" in rec.sql  # (a) correct view
    assert "1 = 1" in rec.sql  # (d) no allow-list → unconstrained predicate
    assert rec.binds == {}
    assert out == {"items": [{"owner": "HR"}, {"owner": "SALES"}], "truncated": False}


@pytest.mark.asyncio
async def test_list_schemas_constrains_to_allowlist_via_generated_binds(monkeypatch):
    rec = _install_fetch(monkeypatch, rows=[("HR",)], truncated=False)
    out = await tools.list_schemas(cfg=_cfg(allowed_owners=frozenset({"HR", "SALES"})))
    # (d) allow-list surfaces as generated :owner_N binds (sorted)
    assert rec.binds == {"owner_0": "HR", "owner_1": "SALES"}
    assert "owner IN (:owner_0, :owner_1)" in rec.sql
    # (b) values never concatenated into the SQL text
    assert "HR" not in rec.sql
    assert "SALES" not in rec.sql
    assert out["items"] == [{"owner": "HR"}]


# --------------------------------------------------------------------------- #
# list_tables
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_list_tables_binds_owner_value_and_maps_items(monkeypatch):
    rec = _install_fetch(monkeypatch, rows=[("EMP", "employees"), ("DEPT", None)], truncated=False)
    out = await tools.list_tables(cfg=_cfg(allowed_owners=frozenset({"HR"})), owner="hr")
    assert "all_tables" in rec.sql  # (a)
    assert "all_tab_comments" in rec.sql  # (a)
    assert rec.binds == {"owner": "HR"}  # (b) value bound, upper-cased by guard_owner
    assert ":owner" in rec.sql  # (b) placeholder present
    assert "HR" not in rec.sql  # (b) value not concatenated
    assert out == {
        "items": [
            {"table_name": "EMP", "comments": "employees"},
            {"table_name": "DEPT", "comments": None},
        ],
        "truncated": False,
    }


@pytest.mark.asyncio
async def test_list_tables_refuses_owner_outside_allowlist(monkeypatch):
    rec = _install_fetch(monkeypatch)
    with pytest.raises(oracle.OwnerNotAllowed):  # (c)
        await tools.list_tables(cfg=_cfg(allowed_owners=frozenset({"HR"})), owner="SECRET")
    assert rec.calls == []  # guard fires before any fetch


# --------------------------------------------------------------------------- #
# describe_table
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_describe_table_binds_owner_table_and_maps_columns(monkeypatch):
    rows = [
        ("ID", "NUMBER", "N", None, "pk"),
        ("NAME", "VARCHAR2", "Y", "'x' ", "the name"),
    ]
    rec = _install_fetch(monkeypatch, rows=rows, truncated=False)
    out = await tools.describe_table(
        cfg=_cfg(allowed_owners=frozenset({"HR"})), owner="hr", table=" emp "
    )
    assert "all_tab_columns" in rec.sql  # (a)
    assert "all_col_comments" in rec.sql  # (a)
    assert rec.binds == {"owner": "HR", "tname": "EMP"}  # (b) both stripped + upper
    assert ":owner" in rec.sql
    assert ":tname" in rec.sql
    assert "EMP" not in rec.sql  # (b) value not concatenated
    assert out == {
        "columns": [
            {
                "column_name": "ID",
                "data_type": "NUMBER",
                "nullable": False,
                "data_default": None,
                "comments": "pk",
            },
            {
                "column_name": "NAME",
                "data_type": "VARCHAR2",
                "nullable": True,
                "data_default": "'x'",  # trailing whitespace stripped
                "comments": "the name",
            },
        ],
        "truncated": False,
    }


@pytest.mark.asyncio
async def test_describe_table_refuses_owner_outside_allowlist(monkeypatch):
    rec = _install_fetch(monkeypatch)
    with pytest.raises(oracle.OwnerNotAllowed):  # (c)
        await tools.describe_table(
            cfg=_cfg(allowed_owners=frozenset({"HR"})), owner="SECRET", table="EMP"
        )
    assert rec.calls == []


# --------------------------------------------------------------------------- #
# find_columns
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_find_columns_with_owner_binds_owner_and_pattern(monkeypatch):
    rows = [("HR", "EMP", "EMP_ID", "NUMBER")]
    rec = _install_fetch(monkeypatch, rows=rows, truncated=True)
    out = await tools.find_columns(
        cfg=_cfg(allowed_owners=frozenset({"HR"})), name_pattern="%ID%", owner="hr"
    )
    assert "all_tab_columns" in rec.sql  # (a)
    assert rec.binds == {"pat": "%ID%", "owner": "HR"}  # (b)
    assert ":pat" in rec.sql
    assert "owner = :owner" in rec.sql
    assert "%ID%" not in rec.sql  # (b) pattern not concatenated
    assert out == {
        "items": [
            {
                "owner": "HR",
                "table_name": "EMP",
                "column_name": "EMP_ID",
                "data_type": "NUMBER",
            }
        ],
        "truncated": True,  # (e) honoured
    }


@pytest.mark.asyncio
async def test_find_columns_owner_outside_allowlist_refuses(monkeypatch):
    rec = _install_fetch(monkeypatch)
    with pytest.raises(oracle.OwnerNotAllowed):  # (c)
        await tools.find_columns(
            cfg=_cfg(allowed_owners=frozenset({"HR"})), name_pattern="%X%", owner="SECRET"
        )
    assert rec.calls == []


@pytest.mark.asyncio
async def test_find_columns_ownerless_constrains_to_allowlist_binds(monkeypatch):
    rec = _install_fetch(monkeypatch, rows=[], truncated=False)
    # (d) owner=None + allow-list → generated :owner_N binds + IN predicate
    await tools.find_columns(
        cfg=_cfg(allowed_owners=frozenset({"HR", "SALES"})), name_pattern="%X%"
    )
    assert rec.binds == {"pat": "%X%", "owner_0": "HR", "owner_1": "SALES"}
    assert "owner IN (:owner_0, :owner_1)" in rec.sql
    assert "HR" not in rec.sql
    assert "SALES" not in rec.sql


@pytest.mark.asyncio
async def test_find_columns_ownerless_no_allowlist_emits_1_eq_1(monkeypatch):
    rec = _install_fetch(monkeypatch, rows=[], truncated=False)
    # (d) owner=None + no allow-list → 1 = 1, pattern still bound
    await tools.find_columns(cfg=_cfg(allowed_owners=frozenset()), name_pattern="%X%")
    assert rec.binds == {"pat": "%X%"}
    assert "1 = 1" in rec.sql


# --------------------------------------------------------------------------- #
# list_relationships
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_list_relationships_without_table_omits_table_filter(monkeypatch):
    rows = [("FK1", "HR", "EMP", "DEPT_ID", "HR", "DEPT", "ID")]
    rec = _install_fetch(monkeypatch, rows=rows, truncated=False)
    out = await tools.list_relationships(cfg=_cfg(allowed_owners=frozenset({"HR"})), owner="hr")
    assert "all_constraints" in rec.sql  # (a)
    assert "all_cons_columns" in rec.sql  # (a)
    assert rec.binds == {"owner": "HR"}  # (b) only owner bound
    assert ":tname" not in rec.sql  # no table filter when table omitted
    assert out == {
        "items": [
            {
                "constraint_name": "FK1",
                "child_owner": "HR",
                "child_table": "EMP",
                "child_column": "DEPT_ID",
                "parent_owner": "HR",
                "parent_table": "DEPT",
                "parent_column": "ID",
            }
        ],
        "truncated": False,
    }


@pytest.mark.asyncio
async def test_list_relationships_with_table_adds_table_filter_bind(monkeypatch):
    rec = _install_fetch(monkeypatch, rows=[], truncated=False)
    await tools.list_relationships(
        cfg=_cfg(allowed_owners=frozenset({"HR"})), owner="hr", table=" emp "
    )
    assert "AND c.table_name = :tname" in rec.sql  # table filter wired
    assert rec.binds == {"owner": "HR", "tname": "EMP"}  # (b) table stripped + upper
    assert "EMP" not in rec.sql  # (b) value not concatenated


@pytest.mark.asyncio
async def test_list_relationships_refuses_owner_outside_allowlist(monkeypatch):
    rec = _install_fetch(monkeypatch)
    with pytest.raises(oracle.OwnerNotAllowed):  # (c)
        await tools.list_relationships(cfg=_cfg(allowed_owners=frozenset({"HR"})), owner="SECRET")
    assert rec.calls == []


# --------------------------------------------------------------------------- #
# get_constraints
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_get_constraints_binds_owner_table_and_maps_items(monkeypatch):
    rows = [
        ("PK_EMP", "P", "ID", None, None, None),
        ("FK_EMP_DEPT", "R", "DEPT_ID", None, "HR", "PK_DEPT"),
    ]
    rec = _install_fetch(monkeypatch, rows=rows, truncated=False)
    out = await tools.get_constraints(
        cfg=_cfg(allowed_owners=frozenset({"HR"})), owner="hr", table=" emp "
    )
    assert "all_constraints" in rec.sql  # (a)
    assert "all_cons_columns" in rec.sql  # (a)
    assert rec.binds == {"owner": "HR", "tname": "EMP"}  # (b)
    assert out == {
        "items": [
            {
                "constraint_name": "PK_EMP",
                "constraint_type": "P",
                "column_name": "ID",
                "search_condition": None,
                "r_owner": None,
                "r_constraint_name": None,
            },
            {
                "constraint_name": "FK_EMP_DEPT",
                "constraint_type": "R",
                "column_name": "DEPT_ID",
                "search_condition": None,
                "r_owner": "HR",
                "r_constraint_name": "PK_DEPT",
            },
        ],
        "truncated": False,
    }


@pytest.mark.asyncio
async def test_get_constraints_refuses_owner_outside_allowlist(monkeypatch):
    rec = _install_fetch(monkeypatch)
    with pytest.raises(oracle.OwnerNotAllowed):  # (c)
        await tools.get_constraints(
            cfg=_cfg(allowed_owners=frozenset({"HR"})), owner="SECRET", table="EMP"
        )
    assert rec.calls == []


# --------------------------------------------------------------------------- #
# truncation + limit threading (cross-tool)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_truncated_passed_through_and_limit_is_max_rows(monkeypatch):
    rec = _install_fetch(monkeypatch, rows=[("HR",)], truncated=True)
    out = await tools.list_schemas(cfg=_cfg(allowed_owners=frozenset(), max_rows=37))
    assert out["truncated"] is True  # (e) passthrough
    assert rec.limit == 37  # (e) limit == cfg.max_rows
