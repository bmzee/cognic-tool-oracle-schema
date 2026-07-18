from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_MAX_CREDENTIAL_BYTES = 4096


class CredentialFileError(RuntimeError):
    """Raised when the injected credential file is unusable (fail-closed).

    Messages never include file content: only the path and structural reason.
    """


@dataclass(frozen=True)
class CredentialRead:
    password: str
    rotation_ref: str


def read_credential(path: str) -> CredentialRead:
    """Read an operator-injected credential file freshly on every call."""
    configured = Path(path)
    mount_dir = configured.parent.resolve(strict=False)
    try:
        resolved = configured.resolve(strict=True)
    except OSError as exc:
        raise CredentialFileError(f"credential file unreadable at {path}") from exc
    if not resolved.is_relative_to(mount_dir):
        raise CredentialFileError(f"credential file at {path} resolves outside its mount directory")

    try:
        stat = resolved.stat()
        if stat.st_size > _MAX_CREDENTIAL_BYTES:
            raise CredentialFileError(f"credential file at {path} exceeds size bound")
        raw = resolved.read_bytes()
    except OSError as exc:
        raise CredentialFileError(f"credential file unreadable at {path}") from exc

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CredentialFileError(f"credential file at {path} is not UTF-8") from exc
    if text.endswith("\n"):
        text = text[:-1]
    if not text or text.strip() != text or not text.strip("\r\n \t"):
        raise CredentialFileError(f"credential file at {path} is empty or malformed")

    rotation_ref = datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat()
    return CredentialRead(password=text, rotation_ref=rotation_ref)
