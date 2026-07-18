from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cognic_tool_oracle_schema.credential import CredentialFileError, read_credential


_FILE_CONTENT = "fixture-only-credential-value"
_MTIME = 1_767_225_600


def _write(path: Path, content: bytes = _FILE_CONTENT.encode()) -> Path:
    path.write_bytes(content)
    os.utime(path, (_MTIME, _MTIME))
    return path


def _assert_value_free_refusal(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    with pytest.raises(CredentialFileError) as caught:
        read_credential(str(path))
    decoded = content.decode("utf-8", errors="ignore")
    if decoded:
        assert decoded not in str(caught.value)


def test_reads_password_and_uses_file_mtime_as_rotation_reference(tmp_path: Path) -> None:
    path = _write(tmp_path / "password")

    result = read_credential(str(path))

    assert result.password == _FILE_CONTENT
    assert result.rotation_ref == datetime.fromtimestamp(_MTIME, tz=UTC).isoformat()


def test_accepts_kubernetes_data_symlink_indirection(tmp_path: Path) -> None:
    version_dir = tmp_path / "..2026_07_18_00_00_00"
    version_dir.mkdir()
    _write(version_dir / "password")
    (tmp_path / "..data").symlink_to(version_dir.name, target_is_directory=True)
    configured = tmp_path / "password"
    configured.symlink_to("..data/password")

    result = read_credential(str(configured))

    assert result.password == _FILE_CONTENT


def test_refuses_symlink_that_escapes_mount_directory(tmp_path: Path) -> None:
    mount_dir = tmp_path / "mount"
    mount_dir.mkdir()
    outside = _write(tmp_path / "outside")
    configured = mount_dir / "password"
    configured.symlink_to(outside)

    with pytest.raises(CredentialFileError, match="resolves outside its mount directory") as caught:
        read_credential(str(configured))

    assert _FILE_CONTENT not in str(caught.value)


@pytest.mark.parametrize(
    "content",
    [b"", b"   \t", b" leading", b"trailing ", b"fixture-only-credential-value\n\n"],
)
def test_refuses_empty_or_malformed_content_without_disclosing_it(
    tmp_path: Path, content: bytes
) -> None:
    _assert_value_free_refusal(tmp_path / "password", content)


def test_refuses_content_over_size_bound_without_disclosing_it(tmp_path: Path) -> None:
    _assert_value_free_refusal(tmp_path / "password", b"x" * 4097)


def test_refuses_non_utf8_content(tmp_path: Path) -> None:
    path = tmp_path / "password"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(CredentialFileError, match="is not UTF-8") as caught:
        read_credential(str(path))

    assert "\\xff" not in str(caught.value)


def test_strips_exactly_one_trailing_newline(tmp_path: Path) -> None:
    path = _write(tmp_path / "password", f"{_FILE_CONTENT}\n".encode())

    result = read_credential(str(path))

    assert result.password == _FILE_CONTENT


def test_refuses_missing_file_without_disclosing_a_value(tmp_path: Path) -> None:
    path = tmp_path / "password"

    with pytest.raises(CredentialFileError, match="credential file unreadable") as caught:
        read_credential(str(path))

    assert _FILE_CONTENT not in str(caught.value)
