"""run_readonly_query — the governed SQL leg of the M8 agent loop (ADR-027).

Seven fail-closed arms, each surfacing a closed-enum ``reason`` in the result
envelope. Arms 1-6 are PURE pre-checks — no database connection is attempted
until every one has passed:

  1. **verify_query_context** — the kernel-stamped RS256 token must verify
     against the public keys named by ``COGNIC_QUERY_CONTEXT_PUBLIC_KEYS``
     (comma-separated PEM file paths — the two-key rotation window). Absent /
     empty / invalid / expired / wrong-audience token, AND an unset / empty /
     unreadable key set, → ``query_context_missing_or_invalid`` (the
     agent-path-only guarantee: NO token, NO query).
  2. **jti replay cache** — an in-process TTL'd seen-set sized by the token
     TTL (evicted on read). SINGLE-PROCESS scope, honestly: replicas each
     keep their own set (a replayed token could pass once per replica within
     the short TTL); Wave-2 is a shared Redis set. → ``query_context_replayed``.
  3. **args_sha256 recompute** — over the RECEIVED args MINUS the token key
     (``{scope_id, sql}`` + ``max_rows`` ONLY when the wire carried it; the
     kernel digests the LLM-authored args PRE-stamp, ``dispatch.py:324``).
     → ``query_context_args_mismatch``.
  4. **sqlglot parse** (``sqlglot==30.12.0``, pure-Python, Oracle dialect) —
     unparseable → ``sql_parse_failed``; anything not one plain SELECT
     statement (DML, DDL, PL/SQL, ``WITH FUNCTION``, multi-statement,
     ``SELECT ... FOR UPDATE``, ``SELECT ... INTO``, top-level set
     operations) → ``sql_not_select_only``.
  5. **object allow-set** — every referenced table (``exp.Table`` walk incl.
     CTEs/subqueries/joins; schema-qualified, case-insensitively normalized;
     CTE aliases are NOT tables; ``DUAL`` always allowed) must be ⊆ the
     TOKEN's ``objects`` → ``agent_sql_object_out_of_scope`` (the
     kernel-mirrored reason name, byte-exact per
     ``core/agent/_types.py:33``).
  6. **row bound + timeout** — ``FETCH FIRST min(max_rows or 100, 500) ROWS
     ONLY`` applied on the AST (never string concat; an author-written
     smaller bound is kept — the wrap only ever CAPS) + a per-call statement
     timeout (``COGNIC_ORACLE_QUERY_TIMEOUT_S``, default 30s).
  7. **Oracle proxy authentication + identity stamp** — a DEDICATED connection as
     ``user="APP_USER[<proxy_db_identity from the token>]"``: the session
     RUNS AS that DB identity, whose grants (governed views only) are the
     engine backstop. Before user SQL, ``DBMS_SESSION.SET_IDENTIFIER`` stamps
     the 64-hex SHA-256 reference of the verified issuer-qualified human
     subject. The signed query context retains the full subject; audit readers
     correlate by recomputation. Deliberately NOT the shared metadata pool —
     proxy identity must never bleed across pooled sessions. Stamp failure →
     ``query_identity_stamp_failed``; any other DB-side failure →
     ``query_execution_failed`` (exception CLASS name at most, never text).

Result envelope: ``{"ok": True, "rows", "row_count", "truncated",
"credential_rotation_ref"}`` on
success; ``{"ok": False, "reason", "message"}`` on refusal — messages are
user-graceful, never stack traces.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import pathlib
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any, Final, Literal

import oracledb
import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

from .config import Config
from .credential import read_credential
from .oracle import _is_auth_error
from .query_context import (
    QueryContextRefusal,
    canonical_bytes,
    verify_query_context,
)

logger = logging.getLogger(__name__)

#: Closed-enum envelope refusal vocabulary (wire-public: the agent LLM sees
#: these through the kernel dispatcher's tool-result feedback).
RefusalReason = Literal[
    "query_context_missing_or_invalid",
    "query_context_replayed",
    "query_context_args_mismatch",
    "sql_parse_failed",
    "sql_not_select_only",
    "agent_sql_object_out_of_scope",
    "query_identity_stamp_failed",
    "query_execution_failed",
]

#: The pinned audience this tool accepts — the FULL ``server_id/tool_name``
#: granted ref. The kernel dispatcher stamps ``aud=resolved.ref`` (the A10
#: chokepoint, ``core/agent/dispatch.py:481``), where ``server_id`` is the
#: registry distribution name == this pack's ``pack_id`` (the Sprint-13.8
#: join-key invariant) and ``tool_name`` is this tool's MCP name.
_EXPECTED_AUD: Final[str] = "cognic-tool-oracle-schema/run_readonly_query"

#: Env contract (call-time reads — a server running only the metadata tools
#: must not fail at startup over query-context deployment config).
_PUBLIC_KEYS_ENV: Final[str] = "COGNIC_QUERY_CONTEXT_PUBLIC_KEYS"
_TIMEOUT_ENV: Final[str] = "COGNIC_ORACLE_QUERY_TIMEOUT_S"
_DEFAULT_TIMEOUT_S: Final[float] = 30.0

_MAX_ROWS_DEFAULT: Final[int] = 100
_MAX_ROWS_CEILING: Final[int] = 500

#: SYS.DUAL is the engine's one-row dummy table (no governed data); Oracle
#: expression idioms (``SELECT SYSDATE FROM dual``) stay usable without every
#: scope having to enumerate it.
_ALWAYS_ALLOWED_OBJECTS: Final[frozenset[str]] = frozenset({"DUAL", "SYS.DUAL"})

#: Oracle identifier shape for the proxy DB identity (defense-in-depth: the
#: claim is kernel-signed, but it lands inside the connect user string, so an
#: out-of-shape value refuses before any connection is attempted).
_PROXY_IDENTITY_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z][A-Za-z0-9_$#]{0,127}")

#: Statement node types that must never appear ANYWHERE in an admitted query
#: (defense-in-depth below the top-level plain-SELECT gate).
_DENIED_NODE_TYPES: Final[tuple[type[exp.Expression], ...]] = (
    exp.Command,
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.Grant,
    exp.TruncateTable,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
)


class ReplayCache:
    """In-process jti seen-set, TTL'd by each token's own ``exp``.

    Entries are evicted on read once ``now >= exp`` — after that instant the
    verifier's expiry arm refuses the token anyway, so the cache only ever
    needs to remember jtis inside the token TTL window. SINGLE-PROCESS scope
    (documented honestly in the module docstring; Wave-2: Redis).
    """

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    def check_and_insert(self, jti: str, *, exp: int, now: int) -> bool:
        """True = first sighting (recorded); False = replay."""
        expired = [key for key, key_exp in self._seen.items() if now >= key_exp]
        for key in expired:
            del self._seen[key]
        if jti in self._seen:
            return False
        self._seen[jti] = exp
        return True


#: The module-level cache the production path uses (tests inject their own).
_replay_cache = ReplayCache()


def _refusal(reason: RefusalReason, message: str) -> dict[str, Any]:
    return {"ok": False, "reason": reason, "message": message}


# --- arm 1 helpers ---------------------------------------------------------------


def _load_public_keys() -> list[bytes] | None:
    """Read the verifier public-key set from the env (call-time, fail-closed).

    ``None`` = unset env / no usable paths / any unreadable or empty file —
    the caller refuses ``query_context_missing_or_invalid``.
    """
    raw = os.environ.get(_PUBLIC_KEYS_ENV, "")
    paths = [p.strip() for p in raw.split(",") if p.strip()]
    if not paths:
        return None
    keys: list[bytes] = []
    for path in paths:
        try:
            pem = pathlib.Path(path).read_bytes()
        except OSError:
            logger.warning("readonly_query.public_key_unreadable", extra={"key_path": path})
            return None
        if not pem.strip():
            logger.warning("readonly_query.public_key_empty", extra={"key_path": path})
            return None
        keys.append(pem)
    return keys


# --- arm 3 helper ----------------------------------------------------------------


def _recompute_args_sha256(scope_id: str, sql: str, max_rows: int | None) -> str:
    """The tool-side digest recompute over the RECEIVED args MINUS the token
    key. ``max_rows`` enters the basis ONLY when the wire carried it —
    mirroring the kernel digest over the LLM-authored args PRE-stamp
    (``dispatch.py:324``; the token key is never in any digest basis)."""
    basis: dict[str, Any] = {"scope_id": scope_id, "sql": sql}
    if max_rows is not None:
        basis["max_rows"] = max_rows
    return hashlib.sha256(canonical_bytes(basis)).hexdigest()


# --- arm 4: parse + plain-SELECT gate ----------------------------------------------


def _classify_parse_failure(sql: str) -> tuple[RefusalReason, str]:
    """Classify an unparseable statement via the tokenizer: PL/SQL entry
    keywords (BEGIN / DECLARE) and Oracle 12c ``WITH FUNCTION`` /
    ``WITH PROCEDURE`` are *not-SELECT* refusals per the B1 contract even
    though sqlglot 30.12.0 raises ParseError on them."""
    try:
        tokens = sqlglot.tokenize(sql, read="oracle")
    except Exception:
        return "sql_parse_failed", "the SQL statement could not be parsed"
    if not tokens:
        return "sql_parse_failed", "no SQL statement was provided"
    first = tokens[0]
    if first.text.upper() in {"BEGIN", "DECLARE"}:
        return "sql_not_select_only", "PL/SQL blocks are not allowed; submit a single SELECT"
    if (
        first.text.upper() == "WITH"
        and len(tokens) > 1
        and tokens[1].text.upper()
        in {
            "FUNCTION",
            "PROCEDURE",
        }
    ):
        return (
            "sql_not_select_only",
            "WITH FUNCTION / WITH PROCEDURE is not allowed; submit a single SELECT",
        )
    return "sql_parse_failed", "the SQL statement could not be parsed"


def _analyze(sql: str) -> tuple[RefusalReason | None, str | None, exp.Select | None]:
    """Arm 4: parse under the Oracle dialect and admit exactly one plain
    SELECT statement. Returns ``(None, None, stmt)`` on success or
    ``(reason, message, None)`` on refusal.
    """
    try:
        statements = sqlglot.parse(sql, read="oracle")
    except ParseError:
        reason, message = _classify_parse_failure(sql)
        return reason, message, None
    except Exception:  # tokenizer edge cases — fail-closed, never a crash
        return "sql_parse_failed", "the SQL statement could not be parsed", None

    parsed = [s for s in statements if s is not None]
    if not parsed:
        return "sql_parse_failed", "no SQL statement was provided", None
    if len(parsed) > 1:
        return (
            "sql_not_select_only",
            "multi-statement SQL is not allowed; submit a single SELECT",
            None,
        )

    stmt = parsed[0]
    if not isinstance(stmt, exp.Select):
        return (
            "sql_not_select_only",
            f"only a single plain SELECT statement is allowed (got {type(stmt).__name__})",
            None,
        )
    if stmt.args.get("locks"):
        return (
            "sql_not_select_only",
            "SELECT ... FOR UPDATE is not allowed (read-only queries only)",
            None,
        )
    if stmt.args.get("into"):
        return (
            "sql_not_select_only",
            "SELECT ... INTO is not allowed (read-only queries only)",
            None,
        )
    for node in stmt.walk():
        if isinstance(node, _DENIED_NODE_TYPES):
            return (
                "sql_not_select_only",
                f"only read-only SELECT syntax is allowed (found {type(node).__name__})",
                None,
            )
    return None, None, stmt


# --- arm 5: object extraction + allow-set --------------------------------------------


def _referenced_objects(stmt: exp.Select) -> frozenset[str]:
    """Every database object the statement references, upper-normalized to
    its dotted form (``SCHEMA.NAME`` when qualified). CTE aliases are name
    bindings, not objects — an UNQUALIFIED table reference matching a CTE
    alias is skipped (SQL scoping: the CTE shadows the name); a
    schema-qualified reference is always a real object."""
    cte_aliases = {cte.alias_or_name.upper() for cte in stmt.find_all(exp.CTE) if cte.alias_or_name}
    refs: set[str] = set()
    for table in stmt.find_all(exp.Table):
        name = table.name
        if not name:
            continue
        parts = [p for p in (table.catalog, table.db) if p]
        if parts:
            refs.add(".".join([*parts, name]).upper())
        elif name.upper() not in cte_aliases:
            refs.add(name.upper())
    return frozenset(refs)


def _out_of_scope_objects(
    referenced: frozenset[str], allowed_objects: tuple[str, ...]
) -> tuple[str, ...]:
    """Arm 5 — THE object allow-set gate: every referenced object must be in
    the TOKEN's ``objects`` set (case-insensitive exact membership; ``DUAL``
    always allowed). Returns the sorted out-of-scope names (empty = pass)."""
    allowed = {o.upper() for o in allowed_objects} | _ALWAYS_ALLOWED_OBJECTS
    return tuple(sorted(ref for ref in referenced if ref not in allowed))


# --- arm 6: row bound + timeout ---------------------------------------------------


def _author_row_bound(stmt: exp.Select) -> int | None:
    """The statement's own literal row bound, when one is present.

    Oracle ``FETCH FIRST n ROWS ...`` parses as :class:`exp.Fetch` in
    ``args["limit"]`` (a ``LIMIT n`` clause would parse as :class:`exp.Limit`)
    — both are read. ``None`` for absent, non-literal (bind / expression), or
    PERCENT bounds (a percentage is not a row count; ours replaces it,
    fail-closed).
    """
    existing = stmt.args.get("limit")
    if isinstance(existing, exp.Fetch):
        options = existing.args.get("limit_options")
        if options is not None and options.args.get("percent"):
            return None
        count = existing.args.get("count")
        if isinstance(count, exp.Literal) and count.is_int:
            return int(count.name)
        return None
    if isinstance(existing, exp.Limit):
        count = existing.expression
        if isinstance(count, exp.Literal) and count.is_int:
            return int(count.name)
    return None


def _apply_row_bound(stmt: exp.Select, max_rows: int | None) -> tuple[str, int]:
    """Apply ``FETCH FIRST <effective> ROWS ONLY`` on the AST (never string
    concat) and return ``(bounded_sql, effective)``.

    ``effective = max(1, min(max_rows or 100, 500))`` — the B1 formula with a
    floor of 1 so a pathological negative can never reach the SQL text. An
    author-written smaller literal bound is KEPT (the wrap only ever caps —
    it never raises the author's own limit); a non-literal or PERCENT bound
    is replaced by ours, fail-closed.
    """
    effective = max(1, min(max_rows or _MAX_ROWS_DEFAULT, _MAX_ROWS_CEILING))
    author_bound = _author_row_bound(stmt)
    if author_bound is not None:
        effective = min(effective, author_bound)
    bounded = stmt.limit(effective)
    return bounded.sql(dialect="oracle"), effective


def _query_timeout_s() -> float:
    raw = os.environ.get(_TIMEOUT_ENV, "")
    if not raw.strip():
        return _DEFAULT_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        logger.warning("readonly_query.timeout_env_invalid", extra={"raw": raw})
        return _DEFAULT_TIMEOUT_S
    return value if value > 0 else _DEFAULT_TIMEOUT_S


# --- arm 7: proxy-authenticated execution --------------------------------------------


def _json_safe(value: Any) -> Any:
    """Project one result cell to a JSON-clean value (deterministic; the
    envelope rides FastMCP structuredContent)."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        # BINARY_FLOAT/DOUBLE columns can carry NaN/Inf — not JSON-encodable.
        return value if math.isfinite(value) else str(value)
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):  # datetime.date / datetime.datetime
        return isoformat()
    return str(value)  # Decimal and any driver-specific type — verbatim text


async def _default_connect(**kwargs: Any) -> Any:
    return await oracledb.connect_async(**kwargs)


async def _execute(
    *,
    cfg: Config,
    proxy_db_identity: str,
    verified_subject: str,
    bounded_sql: str,
    effective: int,
    timeout_s: float,
    connect: Callable[..., Awaitable[Any]],
) -> dict[str, Any]:
    """The Oracle leg: a DEDICATED proxy-authenticated connection — the
    session runs AS ``proxy_db_identity``; its grants are the engine backstop.
    A uniform 64-hex SHA-256 reference of the verified human subject is stamped
    before user SQL. Never the shared metadata pool (identity must not bleed
    across pooled sessions)."""
    subject_reference = hashlib.sha256(verified_subject.encode("utf-8")).hexdigest()

    credential = read_credential(cfg.oracle_password_file)
    try:
        conn = await connect(
            user=f"{cfg.oracle_user}[{proxy_db_identity}]",
            password=credential.password,
            dsn=cfg.oracle_dsn,
        )
    except Exception as exc:
        if not _is_auth_error(exc):
            raise
        credential = read_credential(cfg.oracle_password_file)
        conn = await connect(
            user=f"{cfg.oracle_user}[{proxy_db_identity}]",
            password=credential.password,
            dsn=cfg.oracle_dsn,
        )
    try:
        conn.call_timeout = int(timeout_s * 1000)
        with conn.cursor() as cur:
            try:
                await cur.callproc("dbms_session.set_identifier", [subject_reference])
            except Exception as exc:
                logger.warning(
                    "readonly_query.identity_stamp_failed",
                    extra={"exception_class": type(exc).__name__},
                )
                return _refusal(
                    "query_identity_stamp_failed",
                    "the database session could not be stamped with the verified "
                    "subject; refusing before user SQL",
                )
            await cur.execute(bounded_sql)
            columns = [d[0] for d in cur.description] if cur.description else []
            fetched = await cur.fetchall()
    finally:
        await conn.close()
    rows = [{column: _json_safe(value) for column, value in zip(columns, row)} for row in fetched]
    return {
        "ok": True,
        "rows": rows,
        "row_count": len(rows),
        # the bound is enforced IN the SQL, so a full page means the result
        # MAY have been cut (it can also be an exact fit — documented).
        "truncated": len(rows) >= effective,
        "credential_rotation_ref": credential.rotation_ref,
    }


# --- the orchestrator ---------------------------------------------------------------


async def run(
    *,
    cfg: Config,
    scope_id: str,
    sql: str,
    max_rows: int | None,
    token: str,
    _now: Callable[[], int] | None = None,
    _connect: Callable[..., Awaitable[Any]] | None = None,
    _replay: ReplayCache | None = None,
) -> dict[str, Any]:
    """Run the seven-arm pipeline (see the module docstring — order IS the
    contract). The underscore seams are test injection points, mirroring
    ``oracle.fetch(..., _pool=None)``."""
    now_fn = _now if _now is not None else (lambda: int(time.time()))
    connect = _connect if _connect is not None else _default_connect
    replay = _replay if _replay is not None else _replay_cache

    # --- Arm 1: verify the kernel-signed query context.
    keys = _load_public_keys()
    if keys is None:
        return _refusal(
            "query_context_missing_or_invalid",
            "query-context verification keys are not configured on this server "
            f"({_PUBLIC_KEYS_ENV}); governed queries cannot run",
        )
    if not token:
        return _refusal(
            "query_context_missing_or_invalid",
            "a kernel-signed query-context token is required "
            "(this tool only runs on the governed agent dispatch path)",
        )
    now = now_fn()
    try:
        claims = verify_query_context(
            token=token, public_keys_pem=keys, expected_aud=_EXPECTED_AUD, now=now
        )
    except QueryContextRefusal as refusal:
        # Operator-axis diagnostic keeps the precise internal reason; the
        # envelope collapses all four to the single closed-enum value.
        logger.info(
            "readonly_query.query_context_refused",
            extra={"internal_reason": refusal.reason},
        )
        return _refusal(
            "query_context_missing_or_invalid",
            "the query-context token did not verify "
            "(missing, invalid, expired, or for another audience)",
        )

    # --- Arm 2: jti replay (verified tokens only — an expired token never
    # enters the cache; the expiry arm already refused it).
    if not replay.check_and_insert(claims.jti, exp=claims.exp, now=now):
        return _refusal(
            "query_context_replayed",
            "this query-context token was already used (replay refused)",
        )

    # --- Arm 3: args digest recompute (received args MINUS the token key).
    if _recompute_args_sha256(scope_id, sql, max_rows) != claims.args_sha256:
        return _refusal(
            "query_context_args_mismatch",
            "the call arguments do not match the arguments this query context was minted for",
        )

    # --- Arm 4: parse + plain-SELECT gate.
    reason, message, stmt = _analyze(sql)
    if reason is not None:
        return _refusal(reason, message or "the SQL statement was refused")

    assert stmt is not None  # _analyze contract: reason None => stmt present

    # --- Arm 5: object allow-set (the token's objects ARE the authority).
    out_of_scope = _out_of_scope_objects(_referenced_objects(stmt), claims.objects)
    if out_of_scope:
        return _refusal(
            "agent_sql_object_out_of_scope",
            "the query references objects outside the entitled data scope: "
            + ", ".join(out_of_scope),
        )

    # --- Arm 6: row bound + statement timeout.
    bounded_sql, effective = _apply_row_bound(stmt, max_rows)
    timeout_s = _query_timeout_s()

    # --- Arm 7: Oracle proxy authentication.
    if not _PROXY_IDENTITY_RE.fullmatch(claims.proxy_db_identity):
        return _refusal(
            "query_execution_failed",
            "the token's proxy database identity is not a valid Oracle identifier",
        )
    try:
        return await _execute(
            cfg=cfg,
            proxy_db_identity=claims.proxy_db_identity,
            verified_subject=claims.sub,
            bounded_sql=bounded_sql,
            effective=effective,
            timeout_s=timeout_s,
            connect=connect,
        )
    except Exception as exc:
        # Value-free operator diagnostic: the credential and driver text never
        # enter logs. The envelope likewise carries the class name at most.
        logger.warning(
            "readonly_query.execution_failed",
            extra={"exception_class": type(exc).__name__},
        )
        return _refusal(
            "query_execution_failed",
            f"query execution failed ({type(exc).__name__})",
        )
