"""Pins the reproducible dependency inventory and guarded release path."""

from __future__ import annotations

import pathlib
import re
import stat
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "sign-and-publish.yml"
HARDENED_AGENTOS_SHA = "756b9abd02c59e8f1e0164bec975da0de166e70d"
RUNTIME_DIRECT_DEPENDENCIES = {
    "cryptography",
    "joserfc",
    "mcp",
    "oracledb",
    "pyjwt",
    "sqlglot",
    "uvicorn",
}
RELEASE_PATH_SYNC_COUNTS = {
    ROOT / "release.sh": 1,
    ROOT / ".github" / "workflows" / "ci.yml": 3,
    ROOT / ".github" / "workflows" / "sign-and-publish.yml": 1,
}


def _normalized_requirement_name(requirement: str) -> str:
    match = re.match(r"[A-Za-z0-9._-]+", requirement)
    assert match is not None
    return match.group(0).lower().replace("_", "-")


def _pyproject() -> dict[str, object]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _root_lock_package() -> dict[str, object]:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    packages = lock["package"]
    assert isinstance(packages, list)
    roots = [
        package
        for package in packages
        if isinstance(package, dict)
        and package.get("name") == "cognic-tool-oracle-schema"
        and package.get("source") == {"editable": "."}
    ]
    assert len(roots) == 1
    return roots[0]


def test_authoring_cli_uses_the_hardened_full_sha() -> None:
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    optional = project["optional-dependencies"]
    assert isinstance(optional, dict)
    dev = optional["dev"]
    assert isinstance(dev, list)
    pins = [item for item in dev if isinstance(item, str) and item.startswith("cognic-agentos @")]
    assert pins == [
        f"cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@{HARDENED_AGENTOS_SHA}"
    ]


def test_committed_lock_is_present_and_not_ignored() -> None:
    assert (ROOT / "uv.lock").is_file()
    ignored = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert "uv.lock" not in ignored


def test_lock_runtime_roots_match_the_published_project_contract() -> None:
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    dependencies = project["dependencies"]
    assert isinstance(dependencies, list)
    declared = {
        _normalized_requirement_name(item) for item in dependencies if isinstance(item, str)
    }
    assert declared == RUNTIME_DIRECT_DEPENDENCIES

    root = _root_lock_package()
    locked_dependencies = root["dependencies"]
    assert isinstance(locked_dependencies, list)
    locked = {
        str(dependency["name"]).lower().replace("_", "-")
        for dependency in locked_dependencies
        if isinstance(dependency, dict)
    }
    assert locked == RUNTIME_DIRECT_DEPENDENCIES


def test_every_ci_and_release_sync_is_frozen_and_lock_checked() -> None:
    for path, expected_count in RELEASE_PATH_SYNC_COUNTS.items():
        commands = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
        assert commands.count("uv lock --check") == expected_count, path
        assert commands.count("uv sync --frozen --extra dev") == expected_count, path
        assert commands.count("uv sync --extra dev") == 0, path
        for index, command in enumerate(commands):
            if command == "uv sync --frozen --extra dev":
                assert commands[index - 1] == "uv lock --check", path


def test_release_script_is_executable_version_locked_and_fail_closed() -> None:
    script_path = ROOT / "release.sh"
    assert script_path.stat().st_mode & stat.S_IXUSR
    script = script_path.read_text(encoding="utf-8")
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    version = project["version"]
    assert isinstance(version, str)
    assert f'VERSION="{version}"' in script
    assert "set -euo pipefail" in script
    assert 'RELEASE_TARGET_SHA="${RELEASE_TARGET_SHA:-$(git rev-parse HEAD)}"' in script
    assert '[[ "$RELEASE_TARGET_SHA" =~ ^[0-9a-f]{40}$ ]]' in script
    assert "uv run agentos verify --trust-root cosign.pub ." in script
    assert 'gh release create "$TAG"' in script
    assert '--target "$RELEASE_TARGET_SHA"' in script
    assert "ORACLE_WHEEL_SHA256" in script
    assert "ORACLE_PUB_SHA256" in script


def test_release_workflow_is_dispatch_only_protected_and_exact_sha_targeted() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    trigger_block = workflow.split("\non:\n", maxsplit=1)[1].split("\npermissions:\n", maxsplit=1)[
        0
    ]

    assert re.search(r"(?m)^  workflow_dispatch:$", trigger_block)
    assert not re.search(r"(?m)^  (?:push|pull_request|release|schedule):", trigger_block)
    assert re.search(r"(?m)^    environment: release$", workflow)
    assert re.search(r"(?m)^      contents: write$", workflow)
    assert "RELEASE_TARGET_SHA: ${{ github.sha }}" in workflow
    assert "GH_TOKEN: ${{ github.token }}" in workflow
    assert "run: ./release.sh" in workflow
    assert "gh release create" not in workflow


def test_release_workflow_provisions_and_matches_the_environment_key() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}" in workflow
    assert "COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}" in workflow
    capture_at = workflow.index('_signing_key_material="$COSIGN_PRIVATE_KEY"')
    unset_at = workflow.index("unset COSIGN_PRIVATE_KEY", capture_at)
    write_at = workflow.index(
        'printf \'%s\' "$_signing_key_material" > "$COGNIC_SIGNING_KEY_PATH"',
        unset_at,
    )
    retire_at = workflow.index("unset _signing_key_material", write_at)
    chmod_at = workflow.index('chmod 0600 "$COGNIC_SIGNING_KEY_PATH"', retire_at)
    assert capture_at < unset_at < write_at < retire_at < chmod_at
    assert 'chmod 0600 "$COGNIC_SIGNING_KEY_PATH"' in workflow
    assert 'cosign public-key --key "$COGNIC_SIGNING_KEY_PATH"' in workflow
    assert 'cmp -s "$RUNNER_TEMP/derived-cosign.pub" cosign.pub' in workflow


def test_release_workflow_installs_the_reviewed_supply_chain_toolchain() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "COSIGN_VERSION=3.0.6" in workflow
    assert (
        "COSIGN_SHA256=c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74" in workflow
    )
    assert "SYFT_VERSION=1.45.1" in workflow
    assert (
        "SYFT_SHA256=20c84195e24927f50a3b2269946be51f4c4abc9d2f145fee7388b4199149f716" in workflow
    )
    assert "GRYPE_VERSION=0.114.0" in workflow
    assert (
        "GRYPE_SHA256=edda0968d8827daab01d32b3cd7de192ae0915005e7bbfcfef9e68e79bc43343" in workflow
    )
    assert workflow.count("sha256sum -c -") == 3
    assert 'echo "$GITHUB_WORKSPACE/.venv/bin" >> "$GITHUB_PATH"' in workflow


def test_release_script_scopes_password_and_github_token_to_their_consumers() -> None:
    script = (ROOT / "release.sh").read_text(encoding="utf-8")

    capture_password_at = script.index('_COSIGN_PASSWORD_LOCAL="${COSIGN_PASSWORD:-}"')
    capture_token_at = script.index('_GH_TOKEN_LOCAL="${GH_TOKEN:-}"')
    unset_exports_at = script.index("unset COSIGN_PASSWORD GH_TOKEN")
    first_external_at = script.index("git rev-parse HEAD")
    assert max(capture_password_at, capture_token_at) < unset_exports_at < first_external_at
    assert 'COSIGN_PASSWORD="$_COSIGN_PASSWORD_LOCAL" uv run agentos sign --bundle .' in script
    assert 'GH_TOKEN="$_GH_TOKEN_LOCAL" _publish_release' in script
