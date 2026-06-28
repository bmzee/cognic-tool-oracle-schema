# cognic-tool-oracle-schema

A **FastMCP** (Streamable-HTTP) MCP-server tool pack for **Cognic AgentOS** that
exposes **six read-only Oracle schema-metadata tools** over the Oracle
data-dictionary (`ALL_*`) views:

| Tool | Inputs | Returns (per item) |
|---|---|---|
| `list_schemas` | — | `owner` (schemas with visible tables; allow-list filtered) |
| `list_tables` | `owner` | `table_name`, `comments` |
| `describe_table` | `owner`, `table` | `column_name`, `data_type`, `nullable`, `data_default`, `comments` |
| `find_columns` | `name_pattern`, `owner?` | `owner`, `table_name`, `column_name`, `data_type` |
| `list_relationships` | `owner`, `table?` | FK edge: `constraint_name`, child `(owner, table, column)`, parent `(owner, table, column)` |
| `get_constraints` | `owner`, `table` | `constraint_name`, `constraint_type` (P/U/C/R), `column_name`, details |

Every tool returns a bounded envelope — `{ "items" | "columns": [...], "truncated": bool }`.

The pack has **no kernel runtime dependency**: the AgentOS authoring/governance
CLI (`agentos validate` / `sign` / `verify`) is an author/CI-time `dev` extra
only. The server runs behind a real OAuth-PRM bearer with a JWT/JWKS verifier.

## Safety boundary

> **This is a schema-metadata tool, not a database query tool. It never executes user-supplied SQL, never queries application tables, never returns application rows, and never performs DML/DDL.**

Mechanism: every query is a hand-written string with **bind variables**; tool
arguments bind as *values* (`WHERE owner = :owner`, `LIKE :pat`), never
concatenated into SQL text. There is no passthrough/query tool.

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
| `COGNIC_ORACLE_PASSWORD` | *(required)* | Password for that account. |
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

## Running locally (dev)

The `DevTokenVerifier` is **dev-only**: it accepts any non-empty bearer and is
reachable only when you opt in explicitly (`COGNIC_AUTH_MODE=dev_insecure`
**and** `COGNIC_ENV=dev`). The default `jwt` mode fails closed unless the OAuth
env above is set.

```sh
COGNIC_AUTH_MODE=dev_insecure COGNIC_ENV=dev \
  COGNIC_ORACLE_DSN=localhost:1521/XEPDB1 \
  COGNIC_ORACLE_USER=cognic \
  COGNIC_ORACLE_PASSWORD=cognic_dev_only \
  python -m cognic_tool_oracle_schema.server
```

**Production requires `COGNIC_AUTH_MODE=jwt`** with `COGNIC_OAUTH_ISSUER` /
`COGNIC_OAUTH_JWKS_URI` / `COGNIC_OAUTH_AUDIENCE` set — the real JWT/JWKS
verifier (issuer / signature / expiry / audience / required scope).

## Testing

**Unit suite** (no DB — fake-cursor):

```sh
uv pip install -e '.[dev]'
pytest tests/ -q
```

**Integration suite** (env-gated; live, seeded Oracle XE via `docker compose`):

```sh
docker compose -f docker-compose.oracle.yml up -d   # first boot ~3-5 min
COGNIC_RUN_ORACLE_INTEGRATION=1 \
  COGNIC_ORACLE_DSN=localhost:1521/XEPDB1 \
  COGNIC_ORACLE_USER=cognic \
  COGNIC_ORACLE_PASSWORD=cognic_dev_only \
  pytest tests/integration -m oracle -q
docker compose -f docker-compose.oracle.yml down -v
```

The `COGNIC_RUN_ORACLE_INTEGRATION=1` gate is the *only* skip condition: once
opted in, an unreachable / unseeded DB **fails loud** rather than skipping.

## Authoring / validation

The `dev` extra carries the AgentOS authoring CLI (git-pinned to `@v0.0.2`):

```sh
uv pip install -e '.[dev]'
agentos validate .            # build-time manifest-shape check
```

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
agentos validate .            # now PASS (manifest-shape only)
```

`agentos sign --bundle .` + `agentos verify .` run at **release** (they shell
out to cosign / syft / grype / pip-licenses) and are wired into
`.github/workflows/sign-and-publish.yml`. The PR-side `ci.yml` runs lint + type
+ unit, `agentos validate`, and the env-gated Oracle lane.

## Provenance

Generated from the AgentOS authoring path and authored against
**cognic-agentos `v0.0.2`**. The resolved kernel commit SHA plus the live
integration and `sign` / `verify` proofs are recorded in
[`docs/VALIDATION-RESULTS.md`](docs/VALIDATION-RESULTS.md).
