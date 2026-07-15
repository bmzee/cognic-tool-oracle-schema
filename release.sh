#!/usr/bin/env bash
# release.sh — the maintainer's guarded release path for
# cognic-tool-oracle-schema. Mirrors sign-and-publish.yml's frozen
# build → sign → verify spine, then publishes the GitHub release and prints
# the digest pins consumed by AgentOS proof runners.
#
# REMOTE-AFFECTING: `gh release create` publishes to GitHub. Run only as the
# maintainer, deliberately, from a clean published tree.

set -euo pipefail
cd "$(dirname "$0")"

VERSION="0.3.0"
TAG="v${VERSION}"
WHEEL="dist/cognic_tool_oracle_schema-${VERSION}-py3-none-any.whl"

ATTESTATIONS=(
  attestations/cosign.sig
  attestations/sbom.cdx.json
  attestations/slsa-provenance.intoto.json
  attestations/intoto-layout.json
  attestations/vuln-scan.json
  attestations/license-audit.json
  attestations/bundle.sigstore
)

_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

for tool in uv cosign syft grype pip-licenses gh; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "FATAL: required tool not on PATH: $tool" >&2
    exit 1
  }
done
[ -n "${COGNIC_SIGNING_KEY_PATH:-}" ] || {
  echo "FATAL: COGNIC_SIGNING_KEY_PATH is unset" >&2
  exit 1
}
[ -f "${COGNIC_SIGNING_KEY_PATH}" ] || {
  echo "FATAL: COGNIC_SIGNING_KEY_PATH does not point at a file" >&2
  exit 1
}
[ -n "${COSIGN_PASSWORD:-}" ] || {
  echo "FATAL: COSIGN_PASSWORD is unset" >&2
  exit 1
}
[ -f cosign.pub ] || {
  echo "FATAL: committed cosign.pub trust root is missing" >&2
  exit 1
}
[ -f uv.lock ] || {
  echo "FATAL: committed uv.lock dependency inventory is missing" >&2
  exit 1
}

rm -rf dist
uv lock --check
uv sync --frozen --extra dev
uv build --wheel
[ -f "$WHEEL" ] || {
  echo "FATAL: expected wheel not produced: $WHEEL" >&2
  exit 1
}

uv run agentos sign --bundle .
uv run agentos verify --trust-root cosign.pub .

for artefact in "${ATTESTATIONS[@]}"; do
  [ -s "$artefact" ] || {
    echo "FATAL: expected attestation missing or empty: $artefact" >&2
    exit 1
  }
done

gh release create "$TAG" \
  "$WHEEL" \
  "${ATTESTATIONS[@]}" \
  cosign.pub \
  --title "cognic-tool-oracle-schema ${TAG}" \
  --notes "Read-only Oracle schema metadata and governed run_readonly_query MCP tool pack. Signed bundle: cosign + SBOM + SLSA + in-toto + vulnerability + license evidence; verify with \`agentos verify --trust-root cosign.pub .\`."

echo
echo "# ---- locked digest pins — paste into the AgentOS proof stage-packs.sh ----"
printf 'ORACLE_WHEEL_SHA256="%s"\n' "$(_sha256 "$WHEEL")"
printf 'ORACLE_PUB_SHA256="%s"\n' "$(_sha256 cosign.pub)"
