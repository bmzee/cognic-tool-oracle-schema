"""Shared query-context token helpers for the run_readonly_query test suites.

Hand-mints RS256 ATTACHED compact JWS tokens with joserfc over the pack's
``canonical_bytes`` mirror — the SAME wire form the kernel's
``mint_query_context`` emits (``header.payload.signature``; payload =
``canonical_bytes(<the 12-key claims dict>)`` with ``objects`` as a LIST).

The cross-repo wire pin — minting via the REAL kernel dev-dep — lives in
``tests/test_kernel_wire_pin.py``; everything else in the suite mints through
these helpers so the unit tests run without the M8 kernel installed.
"""

from __future__ import annotations

import hashlib
import pathlib
import secrets
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jws
from joserfc.jwk import RSAKey

from cognic_tool_oracle_schema.query_context import canonical_bytes

#: Fixed deterministic epoch base for iat/exp arithmetic (mirrors the kernel
#: A6 suite's fixed-now discipline — no wall-clock flake).
NOW = 1_770_000_000
TTL_S = 120
EXP = NOW + TTL_S

#: The pinned audience: the FULL ``server_id/tool_name`` granted ref the
#: kernel dispatcher stamps (``dispatch.py:481`` ``aud=resolved.ref``).
AUD = "cognic-tool-oracle-schema/run_readonly_query"


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an RSA-2048 keypair at test time → (private_pem, public_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def args_sha256_for(scope_id: str, sql: str, max_rows: int | None = None) -> str:
    """The kernel's args digest: sha256 over ``canonical_bytes`` of the
    LLM-AUTHORED args — ``max_rows`` enters the basis ONLY when present
    (``dispatch.py:324`` digests ``dict(call.arguments)`` PRE-stamp)."""
    basis: dict[str, Any] = {"scope_id": scope_id, "sql": sql}
    if max_rows is not None:
        basis["max_rows"] = max_rows
    return hashlib.sha256(canonical_bytes(basis)).hexdigest()


def claims_dict(**overrides: Any) -> dict[str, Any]:
    """The 12-key wire claims payload (``objects`` as a LIST — canonical form
    rejects tuples). Any key overridable."""
    base: dict[str, Any] = {
        "iss": "cognic-agentos",
        "aud": AUD,
        "sub": "analyst.amir",
        "act": "bank-analyst",
        "tenant_id": "tenant-a",
        "scope_id": "retail_analytics",
        "objects": ["RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS"],
        "proxy_db_identity": "AGENT_RO",
        "args_sha256": args_sha256_for("retail_analytics", "SELECT 1"),
        "jti": secrets.token_hex(16),
        "iat": NOW,
        "exp": EXP,
    }
    base.update(overrides)
    return base


def mint(payload: dict[str, Any], private_pem: bytes) -> str:
    """Mint the RS256 ATTACHED compact JWS over ``canonical_bytes(payload)``
    (the kernel ``mint_query_context`` wire form)."""
    return jws.serialize_compact(
        {"alg": "RS256"}, canonical_bytes(payload), RSAKey.import_key(private_pem)
    )


def write_keys_env(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    *public_pems: bytes,
) -> list[pathlib.Path]:
    """Write each public PEM to a file and point
    ``COGNIC_QUERY_CONTEXT_PUBLIC_KEYS`` at the comma-separated paths."""
    paths: list[pathlib.Path] = []
    for i, pem in enumerate(public_pems):
        p = tmp_path / f"query_context_pub_{i}.pem"
        p.write_bytes(pem)
        paths.append(p)
    monkeypatch.setenv("COGNIC_QUERY_CONTEXT_PUBLIC_KEYS", ",".join(str(p) for p in paths))
    return paths
