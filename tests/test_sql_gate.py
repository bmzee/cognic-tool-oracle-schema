"""Unit tests for the run_readonly_query SQL gate (arms 4-6, pure functions).

The Oracle-dialect parse suite per the M8 B1 contract: schema-qualified refs,
quoted identifiers, CTE/subquery/join extraction, hint comments, ``FOR
UPDATE`` refused, DML/DDL/PL-SQL/``WITH FUNCTION``/multi-statement refused,
malformed refused; the object allow-set walk; the FETCH FIRST row-bound wrap
(AST-applied, never string concat).
"""

from __future__ import annotations

import pytest
from sqlglot import exp

from cognic_tool_oracle_schema.readonly_query import (
    _analyze,
    _apply_row_bound,
    _out_of_scope_objects,
    _referenced_objects,
)


def _select_of(sql: str) -> exp.Select:
    reason, _message, stmt = _analyze(sql)
    assert reason is None, f"expected clean parse, got {reason}"
    assert stmt is not None
    return stmt


# --- arm 4: parse + SELECT-only ------------------------------------------------


class TestParseGate:
    def test_plain_select_passes(self) -> None:
        reason, message, stmt = _analyze(
            "SELECT c.name FROM retail_analytics.v_customer_deposits c"
        )
        assert reason is None and message is None
        assert isinstance(stmt, exp.Select)

    def test_hint_comment_passes(self) -> None:
        reason, _m, _s = _analyze("SELECT /*+ FULL(c) */ name FROM v_customers c")
        assert reason is None

    def test_cte_select_passes(self) -> None:
        reason, _m, _s = _analyze(
            "WITH top_c AS (SELECT cust_id FROM retail_analytics.v_customer_deposits) "
            "SELECT * FROM top_c"
        )
        assert reason is None

    def test_malformed_sql_refuses_parse_failed(self) -> None:
        reason, message, stmt = _analyze("SELEKT foo FRUM bar")
        assert reason == "sql_parse_failed"
        assert stmt is None
        assert message is not None

    def test_empty_sql_refuses_parse_failed(self) -> None:
        reason, _m, _s = _analyze("")
        assert reason == "sql_parse_failed"

    def test_comment_only_refuses_parse_failed(self) -> None:
        reason, _m, _s = _analyze("-- nothing here")
        assert reason == "sql_parse_failed"

    @pytest.mark.parametrize(
        ("sql", "case"),
        [
            ("INSERT INTO t (a) VALUES (1)", "insert"),
            ("UPDATE t SET a = 1", "update"),
            ("DELETE FROM t", "delete"),
            (
                "MERGE INTO t USING s ON (t.id = s.id) WHEN MATCHED THEN UPDATE SET t.a = s.a",
                "merge",
            ),
            ("CREATE TABLE t (a NUMBER)", "create"),
            ("DROP TABLE t", "drop"),
            ("ALTER TABLE t ADD (c NUMBER)", "alter"),
            ("TRUNCATE TABLE t", "truncate"),
            ("GRANT SELECT ON t TO u", "grant"),
            ("COMMIT", "commit"),
            ("ROLLBACK", "rollback"),
            ("CALL my_proc(1)", "call-proc-command-fallback"),
            ("EXPLAIN PLAN FOR SELECT 1 FROM dual", "explain-command-fallback"),
            ("ALTER SESSION SET CURRENT_SCHEMA = other", "alter-session-command-fallback"),
            ("SELECT 1 FROM dual; SELECT 2 FROM dual", "multi-statement"),
            ("SELECT a FROM t1 UNION SELECT a FROM t2", "top-level-set-operation"),
            ("SELECT name FROM v_customers FOR UPDATE", "for-update"),
            (
                "SELECT name FROM v_customers WHERE id = 1 FOR UPDATE OF name NOWAIT",
                "for-update-of",
            ),
            ("SELECT a INTO v_a FROM t", "plsql-select-into"),
        ],
    )
    def test_non_plain_select_refuses_not_select_only(self, sql: str, case: str) -> None:
        reason, message, stmt = _analyze(sql)
        assert reason == "sql_not_select_only", case
        assert stmt is None
        assert message is not None

    @pytest.mark.parametrize(
        "sql",
        [
            # Oracle 12c WITH FUNCTION / WITH PROCEDURE (PL/SQL in the WITH
            # clause) — classified via the tokenizer since sqlglot 30.12.0
            # raises ParseError on the construct.
            "WITH FUNCTION f(x NUMBER) RETURN NUMBER IS BEGIN RETURN x + 1; END; SELECT f(1) FROM dual",
            "with /* c */ function g RETURN NUMBER IS BEGIN RETURN 1; END; SELECT 1 FROM dual",
            # PL/SQL blocks
            "BEGIN DBMS_OUTPUT.PUT_LINE('hi'); END;",
            "DECLARE x NUMBER; BEGIN NULL; END;",
            "-- lead comment\nBEGIN NULL; END;",
        ],
    )
    def test_plsql_and_with_function_refuse_not_select_only(self, sql: str) -> None:
        reason, _m, _s = _analyze(sql)
        assert reason == "sql_not_select_only"

    def test_trailing_semicolon_single_statement_passes(self) -> None:
        reason, _m, _s = _analyze("SELECT 1 FROM dual;")
        assert reason is None

    def test_nested_set_operation_in_subquery_passes(self) -> None:
        # The STATEMENT is a plain SELECT; a set operation inside a derived
        # table is still read-only query semantics (tables still extracted).
        reason, _m, stmt = _analyze("SELECT * FROM (SELECT a FROM t1 UNION SELECT a FROM t2) x")
        assert reason is None
        assert stmt is not None
        assert _referenced_objects(stmt) == frozenset({"T1", "T2"})


# --- arm 5: object extraction + allow-set ---------------------------------------


class TestObjectExtraction:
    def test_schema_qualified_upper_normalized(self) -> None:
        stmt = _select_of("SELECT c.name FROM retail_analytics.v_customer_deposits c")
        assert _referenced_objects(stmt) == frozenset({"RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS"})

    def test_quoted_identifiers_normalize_case_insensitively(self) -> None:
        stmt = _select_of('SELECT * FROM "Retail_Analytics"."V_Customer_Deposits"')
        assert _referenced_objects(stmt) == frozenset({"RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS"})

    def test_join_and_subquery_tables_extracted(self) -> None:
        stmt = _select_of(
            "SELECT * FROM v_orders o "
            "JOIN (SELECT id FROM secret_tbl) s ON s.id = o.id "
            "LEFT JOIN fin.v_balances b ON b.id = o.id"
        )
        assert _referenced_objects(stmt) == frozenset({"V_ORDERS", "SECRET_TBL", "FIN.V_BALANCES"})

    def test_cte_alias_is_not_a_table(self) -> None:
        stmt = _select_of(
            "WITH top_c AS (SELECT cust_id FROM retail_analytics.v_customer_deposits) "
            "SELECT * FROM top_c"
        )
        # top_c is a CTE alias, NOT a database object.
        assert _referenced_objects(stmt) == frozenset({"RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS"})

    def test_cte_alias_shadowing_a_real_name_is_skipped_unqualified_only(self) -> None:
        stmt = _select_of("WITH v_customers AS (SELECT 1 id FROM dual) SELECT * FROM v_customers")
        # the unqualified reference resolves to the CTE (SQL scoping); DUAL is
        # in the always-allowed set but IS extracted.
        assert _referenced_objects(stmt) == frozenset({"DUAL"})

    def test_dblink_reference_is_extracted_verbatim(self) -> None:
        stmt = _select_of("SELECT * FROM remote_tbl@somelink")
        # extracted with the @dblink suffix — can never match a governed
        # object name, so the allow-set refuses it downstream.
        assert _referenced_objects(stmt) == frozenset({"REMOTE_TBL@SOMELINK"})


class TestAllowSet:
    def test_in_scope_passes(self) -> None:
        out = _out_of_scope_objects(
            frozenset({"RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS"}),
            ("RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS",),
        )
        assert out == ()

    def test_allow_set_membership_is_case_insensitive(self) -> None:
        out = _out_of_scope_objects(
            frozenset({"RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS"}),
            ("retail_analytics.v_customer_deposits",),
        )
        assert out == ()

    def test_out_of_scope_reported_sorted(self) -> None:
        out = _out_of_scope_objects(
            frozenset({"ZZZ_TBL", "AAA_TBL", "RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS"}),
            ("RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS",),
        )
        assert out == ("AAA_TBL", "ZZZ_TBL")

    def test_dual_always_allowed(self) -> None:
        # SYS.DUAL is the engine's one-row dummy table (no governed data);
        # Oracle expression idioms (SELECT SYSDATE FROM dual) stay usable.
        assert _out_of_scope_objects(frozenset({"DUAL"}), ()) == ()
        assert _out_of_scope_objects(frozenset({"SYS.DUAL"}), ()) == ()

    def test_unqualified_reference_does_not_match_qualified_grant(self) -> None:
        # Exact (case-insensitive) membership — an unqualified SQL reference
        # does NOT satisfy a schema-qualified allow-set entry (fail-closed:
        # the resolved object depends on the session schema).
        out = _out_of_scope_objects(
            frozenset({"V_CUSTOMER_DEPOSITS"}),
            ("RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS",),
        )
        assert out == ("V_CUSTOMER_DEPOSITS",)


# --- arm 6: row-bound wrap -------------------------------------------------------


class TestRowBound:
    def test_default_none_wraps_100(self) -> None:
        stmt = _select_of("SELECT name FROM v_customers ORDER BY name")
        bounded_sql, effective = _apply_row_bound(stmt, None)
        assert effective == 100
        assert "FETCH FIRST 100 ROWS ONLY" in bounded_sql

    def test_explicit_max_rows_used(self) -> None:
        stmt = _select_of("SELECT name FROM v_customers")
        bounded_sql, effective = _apply_row_bound(stmt, 7)
        assert effective == 7
        assert "FETCH FIRST 7 ROWS ONLY" in bounded_sql

    def test_500_ceiling_clamps(self) -> None:
        stmt = _select_of("SELECT name FROM v_customers")
        bounded_sql, effective = _apply_row_bound(stmt, 90_000)
        assert effective == 500
        assert "FETCH FIRST 500 ROWS ONLY" in bounded_sql

    def test_zero_falls_back_to_default_and_negative_clamps_to_one(self) -> None:
        stmt = _select_of("SELECT name FROM v_customers")
        _sql0, effective0 = _apply_row_bound(stmt, 0)
        assert effective0 == 100
        stmt2 = _select_of("SELECT name FROM v_customers")
        _sqln, effectiven = _apply_row_bound(stmt2, -5)
        assert effectiven == 1

    def test_wrap_is_ast_applied_limit_node(self) -> None:
        # AST-asserted: the emitted SQL re-parses with a well-formed FETCH
        # node carrying our literal bound (proves an AST wrap, not string
        # concatenation that could produce unparseable SQL).
        stmt = _select_of("SELECT name FROM v_customers")
        bounded_sql, _effective = _apply_row_bound(stmt, 10)
        reparsed = _select_of(bounded_sql)
        fetch = reparsed.args.get("limit")
        assert isinstance(fetch, exp.Fetch)
        assert fetch.args["count"].name == "10"

    def test_existing_smaller_fetch_first_is_kept(self) -> None:
        # The wrap only ever CAPS — it never raises an author-written bound.
        stmt = _select_of("SELECT name FROM v_customers FETCH FIRST 5 ROWS ONLY")
        bounded_sql, effective = _apply_row_bound(stmt, None)
        assert effective == 5
        assert "FETCH FIRST 5 ROWS ONLY" in bounded_sql

    def test_existing_larger_fetch_first_is_capped(self) -> None:
        stmt = _select_of("SELECT name FROM v_customers FETCH FIRST 9999 ROWS ONLY")
        bounded_sql, effective = _apply_row_bound(stmt, None)
        assert effective == 100
        assert "FETCH FIRST 100 ROWS ONLY" in bounded_sql
        assert "9999" not in bounded_sql

    def test_cte_query_wrap_applies_at_outer_select(self) -> None:
        stmt = _select_of("WITH t AS (SELECT 1 x FROM dual) SELECT x FROM t")
        bounded_sql, effective = _apply_row_bound(stmt, 50)
        assert effective == 50
        assert bounded_sql.endswith("FETCH FIRST 50 ROWS ONLY")
