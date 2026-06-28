"""Env-gated integration tests against a live, seeded Oracle XE.

Skipped unless ``COGNIC_RUN_ORACLE_INTEGRATION=1`` (the ONLY skip condition).
Bring the DB up + seed it via docker-compose.oracle.yml; the ``cfg`` /
``oracle_pool`` / ``app_owner`` fixtures live in this package's conftest.

Each test drives one of the six tools against the schema seeded by
``tests/fixtures/seed_schema.sql`` (``COGNIC.DEPARTMENTS`` / ``COGNIC.EMPLOYEES``),
connecting AS the seed owner so the ALL_* views surface its own objects. The
tools enumerate via ``cfg.max_rows`` (default 200), so the tiny seed never
truncates — every test asserts ``truncated is False``.

Fail-loud: when opted in but the DB is missing/unseeded, the tool calls raise
(they do not skip) — only the env gate skips.
"""

import os

import pytest

from cognic_tool_oracle_schema import tools

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION") != "1",
        reason="integration: set COGNIC_RUN_ORACLE_INTEGRATION=1 with a live Oracle XE",
    ),
    pytest.mark.oracle,
]

# Seeded objects (see tests/fixtures/seed_schema.sql). Oracle stores unquoted
# identifiers upper-cased, which is how they surface in the ALL_* views.
_DEPARTMENTS = "DEPARTMENTS"
_EMPLOYEES = "EMPLOYEES"


async def test_list_schemas_includes_app_owner(cfg, oracle_pool, app_owner):
    out = await tools.list_schemas(cfg=cfg)
    owners = {row["owner"] for row in out["items"]}
    assert app_owner in owners
    assert out["truncated"] is False


async def test_list_tables_returns_seeded_tables(cfg, oracle_pool, app_owner):
    out = await tools.list_tables(cfg=cfg, owner=app_owner)
    names = {row["table_name"] for row in out["items"]}
    assert {_DEPARTMENTS, _EMPLOYEES} <= names
    assert out["truncated"] is False


async def test_describe_table_returns_seeded_columns(cfg, oracle_pool, app_owner):
    out = await tools.describe_table(cfg=cfg, owner=app_owner, table=_EMPLOYEES)
    cols = {col["column_name"]: col for col in out["columns"]}
    assert {
        "EMPLOYEE_ID",
        "FULL_NAME",
        "EMAIL",
        "SALARY",
        "HIRED_ON",
        "CREATED_AT",
        "DEPARTMENT_ID",
    } <= set(cols)
    # varied column types map straight from ALL_TAB_COLUMNS.DATA_TYPE
    assert cols["EMPLOYEE_ID"]["data_type"] == "NUMBER"
    assert cols["FULL_NAME"]["data_type"] == "VARCHAR2"
    assert cols["HIRED_ON"]["data_type"] == "DATE"
    assert cols["CREATED_AT"]["data_type"].startswith("TIMESTAMP")
    # nullability is mapped Y/N -> bool
    assert cols["EMPLOYEE_ID"]["nullable"] is False
    assert cols["SALARY"]["nullable"] is True
    # the seeded column comment is surfaced verbatim
    assert cols["FULL_NAME"]["comments"] == "Employee full display name."
    assert out["truncated"] is False


async def test_find_columns_finds_seeded_column(cfg, oracle_pool, app_owner):
    out = await tools.find_columns(cfg=cfg, name_pattern="%EMAIL%", owner=app_owner)
    hits = {(row["table_name"], row["column_name"]) for row in out["items"]}
    assert (_EMPLOYEES, "EMAIL") in hits
    assert out["truncated"] is False


async def test_list_relationships_returns_fk_edge(cfg, oracle_pool, app_owner):
    out = await tools.list_relationships(cfg=cfg, owner=app_owner, table=_EMPLOYEES)
    edges = {
        (row["child_table"], row["child_column"], row["parent_table"], row["parent_column"])
        for row in out["items"]
    }
    assert (_EMPLOYEES, "DEPARTMENT_ID", _DEPARTMENTS, "DEPARTMENT_ID") in edges
    assert out["truncated"] is False


async def test_get_constraints_returns_pk_uk_ck_fk(cfg, oracle_pool, app_owner):
    out = await tools.get_constraints(cfg=cfg, owner=app_owner, table=_EMPLOYEES)
    types = {row["constraint_type"] for row in out["items"]}
    # P=primary key, U=unique, C=check (incl. the explicit ck_employees_salary),
    # R=referential (the FK to DEPARTMENTS).
    assert {"P", "U", "C", "R"} <= types
    assert out["truncated"] is False
