# Validation results — cognic-tool-oracle-schema

Source-of-truth provenance + proof record for this pack. The README links here.

## Provenance

Authored against **cognic-agentos `v0.0.2`** = commit
`1baed465069d7c8344e04983c529bf2fa1988a82` (short `1baed46`), resolved with:

```sh
git -C <cognic-agentos> rev-list -n1 v0.0.2
# → 1baed465069d7c8344e04983c529bf2fa1988a82
```

The tag is recorded for readability; the full SHA is the integrity anchor. The
kernel pin lives in `[project.optional-dependencies] dev` of `pyproject.toml`:
`cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2` — an
author/CI-time dependency only (the pack has no kernel runtime dependency).

## Live integration proof — 2026-06-28

The six tools were exercised against a **real** Oracle, not a fake cursor.

- **Substrate:** `gvenzl/oracle-xe:21-slim` (`XEPDB1`), brought up via
  `docker compose -f docker-compose.oracle.yml up -d --wait`, seeded at first
  boot from `tests/fixtures/seed_schema.sql`.
- **Command:** env-gated
  `COGNIC_RUN_ORACLE_INTEGRATION=1 COGNIC_ORACLE_DSN=localhost:1521/XEPDB1
  COGNIC_ORACLE_USER=cognic COGNIC_ORACLE_PASSWORD=cognic_dev_only
  pytest tests/integration -m oracle -q`.
- **Result:** **6 / 6 passed (~7.8 s)** against the live database — one test per
  tool (`list_schemas`, `list_tables`, `describe_table`, `find_columns`,
  `list_relationships`, `get_constraints`).
- **Seed pattern validated:** the seed runs admin-side
  (`ALTER SESSION SET CONTAINER` + fully-qualified `cognic.*` object DDL); the
  tools then connect **as** the seed owner so the `ALL_*` data-dictionary views
  surface the account's own objects (self-owned visibility).
- **Teardown confirmed:** `docker compose -f docker-compose.oracle.yml down -v`
  removed the container and its volume cleanly.

This is the local live-integration bar. The deployed acceptance bar (Proof-2 /
M3-E2c — install the released signed pack into a deployed AgentOS, reach
`discovery_status = auth_ready`, and `call_tool(describe_table)` over the
override-pinned ClusterIP) is a separate follow-on; the M3 milestone checkbox
flips only when that runs green.

## `sign` / `verify` proof

> **To be filled at release (Task 9).**

`agentos sign --bundle .` (cosign sign-blob + syft SBOM + grype vuln scan +
pip-licenses audit + SLSA / in-toto templates → 7-attestation bundle under
`attestations/`) followed by `agentos verify .` (offline trust gate, 11 steps
incl. the isolated load-probe) must **both** pass on the operator host before
the signed release is tagged. Record here at release time:

- `agentos sign --bundle .` output + the produced `attestations/` file set
- `agentos verify .` → green
- the released pack tag (e.g. `v0.1.0`) and the kernel SHA re-confirmation

If a required supply-chain binary is absent, record `BLOCKED tooling_absent:<bin>`,
install/provide it, and rerun — M3-E2b is not complete until `sign` + `verify`
both pass.
