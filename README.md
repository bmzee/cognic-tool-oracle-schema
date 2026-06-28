# cognic-tool-oracle_schema

AUTHOR-FILL: short description of what this tool pack does.

This is a **FastMCP MCP-server** tool pack: it runs the tool behind a real
Streamable-HTTP MCP server (`server.py`) and ships an inert `SERVER_DESCRIPTOR`
entry point that AgentOS discovery resolves the distribution from. The pack has
**no kernel runtime dependency** — the AgentOS authoring/governance CLI
(`validate` / `sign` / `verify`) is an author/CI-time `dev` extra only.

## Quick start

Install the pack plus the authoring CLI (the `dev` extra carries the kernel):

```sh
uv pip install -e '.[dev]'
```

Edit `cognic-pack-manifest.toml` to replace every `AUTHOR-FILL:` placeholder,
then surface any remaining gaps:

```sh
agentos validate .
```

Iterate until exit 0.

## Layout

```
cognic-tool-oracle_schema/
├── pyproject.toml
├── cognic-pack-manifest.toml
├── README.md
├── src/cognic_tool_oracle_schema/
│   ├── __init__.py            # inert SERVER_DESCRIPTOR (discovery + load-probe)
│   └── server.py              # FastMCP Streamable-HTTP app
├── tests/
│   ├── conftest.py
│   └── test_tool.py
├── attestations/              # Populated by `agentos sign --bundle .`
└── .github/workflows/sign-and-publish.yml
```

## Implementing the tool

Add your tool(s) to `build_server()` in `src/cognic_tool_oracle_schema/server.py` via the
`@mcp.tool(...)` decorator. The shipped `ping` tool is a placeholder — replace
it with your real tool body.

## Running locally

The shipped `DevTokenVerifier` is **dev-only**: it accepts any non-empty bearer
token and is reachable ONLY when you opt in explicitly. The default
`COGNIC_AUTH_MODE=jwt` path fails closed because the scaffold ships no real
verifier.

```sh
COGNIC_AUTH_MODE=dev_insecure COGNIC_ENV=dev python -m cognic_tool_oracle_schema.server
```

**Production requires a real JWT/JWKS `TokenVerifier`** (validating issuer /
signature / expiry / audience / scope) run with `COGNIC_AUTH_MODE=jwt`. Replace
`_select_token_verifier()` accordingly before deploying.

## Testing locally

```sh
uv pip install -e '.[dev]'
pytest tests/
```

## Publishing

```sh
agentos sign --bundle .
agentos verify .
```

The reference workflow at `.github/workflows/sign-and-publish.yml` wires this
into CI on every push to main. AUTHOR-FILL: review + customize the workflow's
publish step for your registry.
