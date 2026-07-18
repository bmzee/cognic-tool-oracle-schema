"""Cross-repo wire pins: kernel mint ↔ pack verify (the M8 B1 contract).

Mints REAL tokens with the kernel dev-dep's ``mint_query_context`` (the A6
reference at ``cognic_agentos/core/agent/query_context.py``) and drives them
through the PACK's verifier + envelope — any wire drift between kernel mint
and pack verify trips here, in the pack's CI.

Skips (loudly) when the installed kernel dev-dep predates M8: the committed
dev pin is ``cognic-agentos @ ...@v0.0.2``, which has no
``core.agent.query_context`` module yet. Run locally against the M8 kernel
working tree with::

    uv run --with 'cognic-agentos @ file:///path/to/cognic-agentos' \
        python -m pytest tests/test_kernel_wire_pin.py -q

(``python -m pytest``, NOT the ``pytest`` console script — the venv script
resolves the venv's own kernel ahead of the ``--with`` overlay.) Once the
kernel M8 branch is pushed, re-point the dev pin at that SHA and this module
runs in CI unconditionally.
"""

from __future__ import annotations

import hashlib
import pathlib
from typing import Any

import pytest

kernel_qc = pytest.importorskip(
    "cognic_agentos.core.agent.query_context",
    reason=(
        "kernel dev-dep predates M8 (no cognic_agentos.core.agent.query_context); "
        "re-point the dev pin at the M8 kernel or run via "
        "uv run --with 'cognic-agentos @ file:///.../cognic-agentos'"
    ),
)
kernel_canonical = pytest.importorskip("cognic_agentos.core.canonical")

from cognic_tool_oracle_schema import readonly_query  # noqa: E402
from cognic_tool_oracle_schema.credential import CredentialRead  # noqa: E402
from cognic_tool_oracle_schema.query_context import (  # noqa: E402
    QueryContextRefusal,
    canonical_bytes,
    verify_query_context,
)
from cognic_tool_oracle_schema.readonly_query import ReplayCache  # noqa: E402
from tests._token_helpers import AUD, generate_keypair, write_keys_env  # noqa: E402
from tests.test_run_readonly_query import _ConnectRecorder, _cfg  # noqa: E402

_NOW = 1_770_000_000
_TTL_S = 120


def _kernel_claims(**overrides: Any) -> Any:
    """Build kernel QueryContextClaims exactly as the dispatcher stamps them
    (``dispatch.py:478-492``): aud = the FULL granted ref; args_sha256 over
    canonical_bytes of the LLM-authored args."""
    base: dict[str, Any] = {
        "iss": "cognic-agentos",
        "aud": AUD,
        "sub": "analyst.amir",
        "act": "bank-analyst",
        "tenant_id": "tenant-a",
        "scope_id": "retail_analytics",
        "objects": ("COGNIC.V_EMPLOYEE_DIRECTORY",),
        "proxy_db_identity": "AGENT_RO",
        "args_sha256": "0" * 64,
        "jti": "f" * 32,
        "iat": _NOW,
        "exp": _NOW + _TTL_S,
    }
    base.update(overrides)
    return kernel_qc.QueryContextClaims(**base)


def _kernel_args_sha256(arguments: dict[str, Any]) -> str:
    """EXACTLY the dispatcher's digest recipe (``dispatch.py:324``):
    sha256(kernel canonical_bytes(dict(call.arguments))) — PRE-stamp."""
    return hashlib.sha256(kernel_canonical.canonical_bytes(arguments)).hexdigest()


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


class TestCanonicalMirrorEquality:
    @pytest.mark.parametrize(
        "shape",
        [
            pytest.param({"scope_id": "retail_analytics", "sql": "SELECT 1"}, id="two-key"),
            pytest.param(
                {"scope_id": "retail_analytics", "sql": "SELECT 1", "max_rows": 50},
                id="with-max-rows",
            ),
            pytest.param({"scope_id": "s", "sql": "SELECT 'é' || chr(10) FROM dual"}, id="unicode"),
            pytest.param({"sql": "", "scope_id": ""}, id="empty-strings"),
            pytest.param({"scope_id": "s", "sql": "SELECT 1", "max_rows": 0}, id="zero-max-rows"),
            pytest.param(
                {"objects": ["A", "B"], "n": 3, "nested": {"k": [1, None, True]}},
                id="nested-primitives",
            ),
        ],
    )
    def test_pack_canonical_equals_kernel_canonical(self, shape: dict[str, Any]) -> None:
        assert canonical_bytes(shape) == kernel_canonical.canonical_bytes(shape)

    def test_max_rows_absent_digest_parity(self) -> None:
        # The kernel digests exactly the LLM-authored args: {scope_id, sql}
        # when max_rows was omitted. The pack recompute (max_rows=None) must
        # match that basis byte-for-byte.
        kernel_digest = _kernel_args_sha256({"scope_id": "retail_analytics", "sql": "SELECT 1"})
        pack_digest = readonly_query._recompute_args_sha256("retail_analytics", "SELECT 1", None)
        assert pack_digest == kernel_digest

    def test_max_rows_present_digest_parity(self) -> None:
        kernel_digest = _kernel_args_sha256(
            {"scope_id": "retail_analytics", "sql": "SELECT 1", "max_rows": 25}
        )
        pack_digest = readonly_query._recompute_args_sha256("retail_analytics", "SELECT 1", 25)
        assert pack_digest == kernel_digest


class TestKernelMintPackVerify:
    def test_kernel_minted_token_verifies_in_pack(self, keypair: tuple[bytes, bytes]) -> None:
        claims = _kernel_claims()
        token = kernel_qc.mint_query_context(claims=claims, signing_key_pem=keypair[0])
        verified = verify_query_context(
            token=token, public_keys_pem=[keypair[1]], expected_aud=AUD, now=_NOW
        )
        assert verified.aud == claims.aud
        assert verified.sub == claims.sub
        assert verified.act == claims.act
        assert verified.tenant_id == claims.tenant_id
        assert verified.scope_id == claims.scope_id
        assert verified.objects == claims.objects
        assert verified.proxy_db_identity == claims.proxy_db_identity
        assert verified.args_sha256 == claims.args_sha256
        assert verified.jti == claims.jti
        assert verified.iat == claims.iat and verified.exp == claims.exp

    def test_expired_kernel_token_refused(self, keypair: tuple[bytes, bytes]) -> None:
        token = kernel_qc.mint_query_context(claims=_kernel_claims(), signing_key_pem=keypair[0])
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=token,
                public_keys_pem=[keypair[1]],
                expected_aud=AUD,
                now=_NOW + _TTL_S,  # the boundary instant is dead (now >= exp)
            )
        assert exc.value.reason == "query_context_expired"

    def test_wrong_audience_kernel_token_refused(self, keypair: tuple[bytes, bytes]) -> None:
        token = kernel_qc.mint_query_context(
            claims=_kernel_claims(aud="cognic-tool-oracle-schema/describe_table"),
            signing_key_pem=keypair[0],
        )
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=token, public_keys_pem=[keypair[1]], expected_aud=AUD, now=_NOW
            )
        assert exc.value.reason == "query_context_audience_mismatch"

    def test_tampered_kernel_token_refused(self, keypair: tuple[bytes, bytes]) -> None:
        token = kernel_qc.mint_query_context(claims=_kernel_claims(), signing_key_pem=keypair[0])
        header, payload, sig = token.split(".")
        tampered_sig = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=".".join([header, payload, tampered_sig]),
                public_keys_pem=[keypair[1]],
                expected_aud=AUD,
                now=_NOW,
            )
        assert exc.value.reason == "query_context_signature_invalid"


class TestKernelTokenThroughEnvelope:
    async def test_kernel_minted_token_drives_full_pipeline_to_execution(
        self,
        tmp_path: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
        keypair: tuple[bytes, bytes],
    ) -> None:
        """The full-stack cross pin: the EXACT stamp the dispatcher makes
        (args digest over the LLM-authored args, aud = the granted ref) walks
        arms 1-6 of the pack tool and reaches the (fake) Oracle leg."""
        write_keys_env(tmp_path, monkeypatch, keypair[1])
        sql = "SELECT full_name FROM cognic.v_employee_directory"
        arguments = {"scope_id": "retail_analytics", "sql": sql}
        claims = _kernel_claims(args_sha256=_kernel_args_sha256(arguments))
        token = kernel_qc.mint_query_context(claims=claims, signing_key_pem=keypair[0])
        monkeypatch.setattr(
            readonly_query,
            "read_credential",
            lambda _path: CredentialRead(
                password="fixture-only-kernel-wire-value",
                rotation_ref="2026-07-18T00:00:00+00:00",
            ),
        )
        connect = _ConnectRecorder(rows=[("Ada",)], description=[("FULL_NAME",)])
        result = await readonly_query.run(
            cfg=_cfg(),
            scope_id="retail_analytics",
            sql=sql,
            max_rows=None,
            token=token,
            _now=lambda: _NOW,
            _connect=connect,
            _replay=ReplayCache(),
        )
        assert result == {
            "ok": True,
            "rows": [{"FULL_NAME": "Ada"}],
            "row_count": 1,
            "truncated": False,
            "credential_rotation_ref": "2026-07-18T00:00:00+00:00",
        }
        assert connect.calls[0]["user"] == "app_user[AGENT_RO]"
        assert connect.conns[0].cursor().operations[0] == (
            "callproc",
            "dbms_session.set_identifier",
            (hashlib.sha256(claims.sub.encode("utf-8")).hexdigest(),),
        )
