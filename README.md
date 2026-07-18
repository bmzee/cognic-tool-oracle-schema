# cognic-tool-oracle-schema

A **FastMCP** (Streamable-HTTP) MCP-server tool pack for **Cognic AgentOS** that
exposes **six read-only Oracle schema-metadata tools** over the Oracle
data-dictionary (`ALL_*`) views, plus (v0.3.0, M8 / ADR-027) **one governed
read-only query tool** for the AgentOS agent loop:

| Tool | Inputs | Returns (per item) |
|---|---|---|
| `list_schemas` | — | `owner` (schemas with visible tables; allow-list filtered) |
| `list_tables` | `owner` | `table_name`, `comments` |
| `describe_table` | `owner`, `table` | `column_name`, `data_type`, `nullable`, `data_default`, `comments` |
| `find_columns` | `name_pattern`, `owner?` | `owner`, `table_name`, `column_name`, `data_type` |
| `list_relationships` | `owner`, `table?` | FK edge: `constraint_name`, child `(owner, table, column)`, parent `(owner, table, column)` |
| `get_constraints` | `owner`, `table` | `constraint_name`, `constraint_type` (P/U/C/R), `column_name`, details |
| `run_readonly_query` | `scope_id`, `sql`, `max_rows?`, `_cognic_query_context` (kernel-stamped) | `{ok, rows, row_count, truncated}` or `{ok: false, reason, message}` |

The six metadata tools return a bounded envelope — `{ "items" | "columns": [...], "truncated": bool }`.

The pack has **no kernel runtime dependency**: the AgentOS authoring/governance
CLI (`agentos validate` / `sign` / `verify`) is an author/CI-time `dev` extra
only. The server runs behind a real OAuth-PRM bearer with a JWT/JWKS verifier.

## Safety boundary

> **The six metadata tools: this is a schema-metadata tool, not a database query tool. It never executes user-supplied SQL, never queries application tables, never returns application rows, and never performs DML/DDL.**

Mechanism: every metadata query is a hand-written string with **bind variables**;
tool arguments bind as *values* (`WHERE owner = :owner`, `LIKE :pat`), never
concatenated into SQL text.

v0.3.0 adds ONE deliberate, governed exception — `run_readonly_query` — which
executes agent-authored `SELECT` statements **only** under a kernel-signed
query-context token; see the section below. The six metadata tools are
unchanged.

## `run_readonly_query` — the governed SQL leg (v0.3.0, M8 / ADR-027)

The Cognic AgentOS kernel's agent dispatcher stamps every `run_readonly_query`
call with a short-TTL RS256-signed **query-context token** (the
`_cognic_query_context` argument — kernel-stamped, never LLM-authored) binding
the call to the asking user's resolved data scope. The tool enforces seven
fail-closed arms, each with a closed-enum `reason` in the result envelope;
**arms 1-6 are pure pre-checks — no database connection until all pass**:

1. **Token verification** (`query_context_missing_or_invalid`) — the token
   must verify against `COGNIC_QUERY_CONTEXT_PUBLIC_KEYS` (comma-separated
   PEM paths — list `[new, old]` during a rotation), be unexpired
   (`now >= exp` refuses), and carry the pinned audience
   `cognic-tool-oracle-schema/run_readonly_query` (the full
   `server_id/tool_name` ref the kernel stamps). Unset / unreadable / empty
   key config also refuses at call time — **no token, no query** (the
   agent-path-only guarantee). Bare-bearer calls outside the agent loop are
   refused here.
2. **Replay** (`query_context_replayed`) — each token's `jti` is single-use.
   The seen-set is **in-process** and TTL'd by the token's own expiry
   (honest scope note: replicas each keep their own set, so a replay could
   pass once per replica within the short TTL; a shared Redis set is the
   Wave-2 hardening).
3. **Argument binding** (`query_context_args_mismatch`) — the token's
   `args_sha256` is recomputed over the RECEIVED `{scope_id, sql}` (+
   `max_rows` only when the wire carried it), so a captured token cannot be
   re-targeted at different SQL.
4. **SELECT-only parse** (`sql_parse_failed` / `sql_not_select_only`) —
   `sqlglot` (Oracle dialect, pure Python) admits exactly ONE plain `SELECT`:
   DML, DDL, PL/SQL, `WITH FUNCTION`, multi-statement, `SELECT ... FOR
   UPDATE`, `SELECT ... INTO`, and top-level set operations all refuse.
5. **Scope object allow-set** (`agent_sql_object_out_of_scope`) — every
   referenced table (including inside CTEs / subqueries / joins;
   schema-qualified, case-insensitively normalized; CTE aliases are not
   tables) must be in the TOKEN's `objects` set. Matching is exact
   (case-insensitive) on the dotted name, so scopes should list objects as
   the SQL will reference them (e.g. `COGNIC.V_EMPLOYEE_DIRECTORY`). `DUAL`
   is always allowed (the engine's one-row dummy table — no governed data).
6. **Row bound + timeout** — `FETCH FIRST min(max_rows or 100, 500) ROWS
   ONLY` applied on the AST (an author-written smaller bound is kept; the
   wrap only ever caps) + a per-call statement timeout
   (`COGNIC_ORACLE_QUERY_TIMEOUT_S`, default 30 s).
7. **Oracle proxy authentication** (`query_execution_failed` on any DB
   failure — exception class name at most, never DB text) — a dedicated
   connection as `COGNIC_ORACLE_USER[<proxy_db_identity from the token>]`:
   the session **runs as** the token's DB identity, whose grants (governed
   views only) are the engine backstop. Never the shared metadata pool.

For DB-native attribution, Oracle audit carries a uniform 64-hex subject
reference: `CLIENT_IDENTIFIER = SHA-256(<issuer-qualified subject UTF-8 bytes>)`.
The kernel's signed query context and evidence chain retain the full subject;
operators correlate the database row to that identity by recomputing the
reference. The subject is an identifier rather than a secret, and the mapping
remains kernel-held rather than being delegated to the pack or database.

**DB setup for proxy authentication** (per proxy identity):

```sql
CREATE USER an_amir IDENTIFIED BY "...";        -- or IDENTIFIED EXTERNALLY
GRANT CREATE SESSION TO an_amir;
ALTER USER an_amir GRANT CONNECT THROUGH app_user;  -- app_user = COGNIC_ORACLE_USER
GRANT SELECT ON retail_analytics.v_customer_deposits TO an_amir;  -- governed views ONLY
```

The integration seed (`tests/fixtures/seed_schema.sql`) creates a working
example: `AGENT_RO` proxying through `cognic` with `SELECT` on
`COGNIC.V_EMPLOYEE_DIRECTORY` only. (gvenzl applies seeds on the FIRST boot of
a fresh volume — re-create the volume with `docker compose -f
docker-compose.oracle.yml down -v` if it predates v0.3.0.)

## Operator notes

- **The Oracle DSN is deployment config, not a manifest egress entry.** The
  connection is TCP 1521 from the pack's own deployment; the manifest
  `egress_allow_list` governs *sandboxed-tool* HTTP egress via the AgentOS proxy,
  and an external MCP server is not AgentOS-sandboxed.
- **Metadata only** — the tools return schema structure (names / types /
  constraints), never row data, never arbitrary SQL, and the pack persists
  nothing.
- **Read-only DB account is the hard boundary.** The connecting Oracle user should
  have read-only access (no DML/DDL); even a hypothetical bug cannot write or read
  application rows. The pack cannot self-enforce this — it is an operator precondition.
- **Schema visibility follows the `ALL_*` views.** The tools read `ALL_TABLES` /
  `ALL_TAB_COLUMNS` / `ALL_CONSTRAINTS`, which surface only objects the connecting
  user owns or has been granted access to:
  - For **self-owned** schema metadata, connecting as that schema owner is enough
    (no extra grant).
  - For **cross-schema** metadata, grant the connecting user `SELECT` on the target
    objects, or use an explicitly approved catalog / dictionary role or policy that
    expands `ALL_*` visibility. Do **not** assume `SELECT_CATALOG_ROLE` alone is the
    universal answer — it opens the `DBA_*` views, which these tools do not query.
- **`COGNIC_ORACLE_ALLOWED_OWNERS` is an application-side narrowing layer only.** It
  further restricts which owners the tools return; DB grants remain the hard floor.
  When table/column *names* are themselves sensitive, use both — the DB grant is the
  backend boundary, the allow-list narrows it further.

## Environment variables

All configuration is environment-driven and fail-closed at startup
(`Config.from_env`). Oracle connection / auth config is parsed in `config.py`;
the HTTP bind + URLs in `server.py`.

| Variable | Default | Meaning |
|---|---|---|
| `COGNIC_ORACLE_DSN` | *(required)* | Oracle DSN, e.g. `localhost:1521/XEPDB1`. Deployment config — **not** manifest egress. |
| `COGNIC_ORACLE_USER` | *(required)* | Read-only Oracle account; `ALL_*` visibility follows owned + granted objects (see operator notes). |
| `COGNIC_ORACLE_PASSWORD_FILE` | *(required)* | Path to the operator-injected password file. The file is read freshly for governed queries; `COGNIC_ORACLE_PASSWORD` is refused in v0.5.0. |
| `COGNIC_ORACLE_ALLOWED_OWNERS` | *(unset = trust the DB grant)* | Comma-separated schema-owner allow-list; upper-cased. When set, every tool additionally refuses owners not in it. |
| `COGNIC_ORACLE_MAX_ROWS` | `200` | Per-tool output cap; clamped to `[1, 1000]` (hard max `1000`). Sets `truncated` at the boundary. |
| `COGNIC_ORACLE_POOL_MAX` | `4` | Max connections in the async pool. |
| `COGNIC_AUTH_MODE` | `jwt` | `jwt` (real JWKS verifier) or `dev_insecure` (dev-only accept-and-bind verifier; permitted only when `COGNIC_ENV=dev`, else fail-closed at startup). |
| `COGNIC_ENV` | *(unset)* | Must equal `dev` to permit `COGNIC_AUTH_MODE=dev_insecure`. |
| `COGNIC_OAUTH_ISSUER` | *(unset)* | Expected token issuer. **Required** in `jwt` mode. |
| `COGNIC_OAUTH_JWKS_URI` | *(unset)* | Authorization-server JWKS URI for signature verification. **Required** in `jwt` mode. |
| `COGNIC_OAUTH_AUDIENCE` | *(unset)* | Expected audience / resource (this server's resource URL). **Required** in `jwt` mode. |
| `COGNIC_REQUIRED_SCOPES` | `oracle_schema.read` | Comma-separated required scopes; must be non-empty. |
| `COGNIC_MCP_HOST` | `127.0.0.1` | Streamable-HTTP bind host. |
| `COGNIC_MCP_PORT` | `8765` | Streamable-HTTP bind port. |
| `COGNIC_MCP_SERVER_URL` | `http://127.0.0.1:8765/mcp` | Public resource-server URL (audience/resource); deploy-overridden to the ClusterIP. |
| `COGNIC_MCP_AS_ISSUER` | `http://127.0.0.1:9000` | Authorization-server issuer URL passed to `build_server(as_issuer=…)`. |
| `COGNIC_QUERY_CONTEXT_PUBLIC_KEYS` | *(unset)* | v0.3.0: comma-separated PEM file paths — the kernel query-context verification key set (list `[new, old]` during rotation). Read at **call time**; unset / unreadable / empty refuses every `run_readonly_query` call (`query_context_missing_or_invalid`) while the six metadata tools keep working. |
| `COGNIC_ORACLE_QUERY_TIMEOUT_S` | `30` | v0.3.0: per-call statement timeout (seconds) for `run_readonly_query` (`oracledb` `call_timeout`). |

## Running locally (dev)

The `DevTokenVerifier` is **dev-only**: it accepts any non-empty bearer and is
reachable only when you opt in explicitly (`COGNIC_AUTH_MODE=dev_insecure`
**and** `COGNIC_ENV=dev`). The default `jwt` mode fails closed unless the OAuth
env above is set.

```sh
COGNIC_AUTH_MODE=dev_insecure COGNIC_ENV=dev \
  COGNIC_ORACLE_DSN=localhost:1521/XEPDB1 \
  COGNIC_ORACLE_USER=cognic \
  COGNIC_ORACLE_PASSWORD_FILE=/path/to/oracle-password \
  python -m cognic_tool_oracle_schema.server
```

**Production requires `COGNIC_AUTH_MODE=jwt`** with `COGNIC_OAUTH_ISSUER` /
`COGNIC_OAUTH_JWKS_URI` / `COGNIC_OAUTH_AUDIENCE` set — the real JWT/JWKS
verifier (issuer / signature / expiry / audience / required scope).

## Testing

**Unit suite** (no DB — fake-cursor):

```sh
uv lock --check
uv sync --frozen --extra dev
uv run pytest tests/ -q
```

**Integration suite** (env-gated; live, seeded Oracle XE via `docker compose`):

```sh
docker compose -f docker-compose.oracle.yml up -d   # first boot ~3-5 min
COGNIC_RUN_ORACLE_INTEGRATION=1 \
  COGNIC_ORACLE_DSN=localhost:1521/XEPDB1 \
  COGNIC_ORACLE_USER=cognic \
  COGNIC_ORACLE_PASSWORD_FILE=/path/to/oracle-password \
  pytest tests/integration -m oracle -q
docker compose -f docker-compose.oracle.yml down -v
```

The `COGNIC_RUN_ORACLE_INTEGRATION=1` gate is the *only* skip condition: once
opted in, an unreachable / unseeded DB **fails loud** rather than skipping.

## Authoring / validation

The `dev` extra carries the AgentOS authoring CLI, full-SHA-pinned to the
ADR-016 hardened signer used by the sibling approval-probe pack:

```sh
uv lock --check
uv sync --frozen --extra dev
uv run agentos validate .     # build-time manifest-shape check
```

`uv.lock` is committed supply-chain evidence, not local cache. It is the
single resolved dependency inventory consumed by `agentos sign`; CI and
`release.sh` both check it before a frozen sync so a release cannot silently
resolve a different dependency set from the reviewed tree.

`agentos validate` checks the manifest against the build-time trust gate, which
includes that each declared `[supply_chain].attestation_paths` file exists — so
it **fails standalone until those are present**. The real bundle (cosign
signature + CycloneDX SBOM) is produced by `agentos sign --bundle .` at
**release** (Task 9); to run the shape check before then, seed throwaway
placeholders first — exactly what the CI `authoring-validate` lane does on the
runner (it never commits them):

```sh
mkdir -p attestations
printf 'placeholder\n' > attestations/cosign.sig
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}\n' > attestations/sbom.cdx.json
uv run agentos validate .     # now PASS (manifest-shape only)
```

The real bundle (`agentos sign --bundle .`, which shells out to cosign / syft /
grype / pip-licenses), offline verification against `cosign.pub`, GitHub release
upload, and `ORACLE_*_SHA256` digest print are wrapped by **`release.sh`**.
The dispatch-only `sign-and-publish` workflow is the protected remote entry:
its first job validates the requested version and absence of a prior tag/release,
then the `release` environment holds execution for maintainer approval. Only
that protected job can read `COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD`; it
installs checksum-pinned signing tools, proves the private key derives the
committed `cosign.pub`, and invokes `release.sh` with the exact workflow SHA
as the release target. The same script remains usable locally with
`COGNIC_SIGNING_KEY_PATH` and `COSIGN_PASSWORD`; secret values are never
echoed.

## Provenance

The governed-query wire contract was authored against **cognic-agentos
`6c4d944`** (M8; v0.1.0/v0.2.0 evidence anchored `v0.0.2`). Release authoring
now uses the full-SHA ADR-016 hardened signer at
`756b9abd02c59e8f1e0164bec975da0de166e70d`; these are distinct provenance
claims. The resolved kernel commits plus live integration and sign/verify
proofs are recorded in
[`docs/VALIDATION-RESULTS.md`](docs/VALIDATION-RESULTS.md).
