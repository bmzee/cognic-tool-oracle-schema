"""Pins the reproducible dependency inventory and guarded release path."""

from __future__ import annotations

import pathlib
import re
import stat
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
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
    assert "uv run agentos verify --trust-root cosign.pub ." in script
    assert 'gh release create "$TAG"' in script
    assert "ORACLE_WHEEL_SHA256" in script
    assert "ORACLE_PUB_SHA256" in script
