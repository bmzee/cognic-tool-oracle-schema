"""Unit tests for the pack-local query-context verifier mirror.

``query_context.py`` mirrors the kernel A6 reference
(``cognic_agentos/core/agent/query_context.py``): the same 12-claim shape, the
same DETERMINISTIC refusal precedence (signature → claims_malformed → expired →
audience_mismatch), the same ``algorithms=["RS256"]`` pin, the same
exactly-12-keys gate and bool-guarded ints. The byte-level cross-repo pin
against the REAL kernel mint lives in ``tests/test_kernel_wire_pin.py``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from joserfc import jws
from joserfc.jwk import RSAKey

from cognic_tool_oracle_schema.query_context import (
    QueryContextClaims,
    QueryContextRefusal,
    canonical_bytes,
    verify_query_context,
)
from tests._token_helpers import (
    AUD,
    EXP,
    NOW,
    claims_dict,
    generate_keypair,
    mint,
)


@pytest.fixture(scope="module")
def keypair_a() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture(scope="module")
def keypair_b() -> tuple[bytes, bytes]:
    return generate_keypair()


# --- canonical_bytes mirror (JSON-primitive shapes) ---------------------------


class TestCanonicalBytesMirror:
    def test_sorted_keys_compact_separators(self) -> None:
        assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_unicode_preserved_not_escaped(self) -> None:
        assert canonical_bytes({"sql": "SELECT 'é'"}) == '{"sql":"SELECT \'é\'"}'.encode()

    def test_nested_list_and_none_and_bool(self) -> None:
        assert canonical_bytes({"a": [1, None, True], "b": "x"}) == b'{"a":[1,null,true],"b":"x"}'

    def test_tuple_rejected(self) -> None:
        with pytest.raises(TypeError):
            canonical_bytes({"objects": ("A", "B")})

    def test_non_string_dict_key_rejected(self) -> None:
        with pytest.raises(ValueError):
            canonical_bytes({1: "x"})

    def test_non_finite_float_rejected(self) -> None:
        with pytest.raises(ValueError):
            canonical_bytes({"x": float("nan")})

    def test_unserializable_object_rejected(self) -> None:
        with pytest.raises(TypeError):
            canonical_bytes({"x": object()})


# --- verify: green path -------------------------------------------------------


class TestVerifyGreenPath:
    def test_valid_token_returns_claims(self, keypair_a: tuple[bytes, bytes]) -> None:
        payload = claims_dict()
        token = mint(payload, keypair_a[0])
        claims = verify_query_context(
            token=token, public_keys_pem=[keypair_a[1]], expected_aud=AUD, now=NOW
        )
        assert isinstance(claims, QueryContextClaims)
        assert claims.aud == AUD
        assert claims.objects == tuple(payload["objects"])
        assert claims.proxy_db_identity == "AGENT_RO"
        assert claims.args_sha256 == payload["args_sha256"]
        assert claims.jti == payload["jti"]

    def test_second_rotation_key_accepts(
        self, keypair_a: tuple[bytes, bytes], keypair_b: tuple[bytes, bytes]
    ) -> None:
        # Two-key rotation window: token signed with key B verifies when the
        # env lists [new(A), old(B)].
        token = mint(claims_dict(), keypair_b[0])
        claims = verify_query_context(
            token=token,
            public_keys_pem=[keypair_a[1], keypair_b[1]],
            expected_aud=AUD,
            now=NOW,
        )
        assert claims.aud == AUD


# --- verify: refusal arms + precedence -----------------------------------------


class TestVerifyRefusals:
    def test_wrong_key_refuses_signature_invalid(
        self, keypair_a: tuple[bytes, bytes], keypair_b: tuple[bytes, bytes]
    ) -> None:
        token = mint(claims_dict(), keypair_a[0])
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=token, public_keys_pem=[keypair_b[1]], expected_aud=AUD, now=NOW
            )
        assert exc.value.reason == "query_context_signature_invalid"

    def test_empty_key_list_refuses_signature_invalid(self, keypair_a: tuple[bytes, bytes]) -> None:
        token = mint(claims_dict(), keypair_a[0])
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(token=token, public_keys_pem=[], expected_aud=AUD, now=NOW)
        assert exc.value.reason == "query_context_signature_invalid"

    def test_tampered_payload_refuses_signature_invalid(
        self, keypair_a: tuple[bytes, bytes]
    ) -> None:
        token = mint(claims_dict(), keypair_a[0])
        header, payload, sig = token.split(".")
        tampered = ".".join([header, payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB"), sig])
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=tampered, public_keys_pem=[keypair_a[1]], expected_aud=AUD, now=NOW
            )
        assert exc.value.reason == "query_context_signature_invalid"

    def test_garbage_token_refuses_signature_invalid(self, keypair_a: tuple[bytes, bytes]) -> None:
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token="not-a-jws",
                public_keys_pem=[keypair_a[1]],
                expected_aud=AUD,
                now=NOW,
            )
        assert exc.value.reason == "query_context_signature_invalid"

    def test_rs512_token_refused_by_alg_pin(self, keypair_a: tuple[bytes, bytes]) -> None:
        # The accepted-alg set is pinned to exactly what the kernel emits.
        # (joserfc's default registry refuses MINTING RS512 too — the mint
        # side must opt in explicitly to forge the probe token.)
        token = jws.serialize_compact(
            {"alg": "RS512"},
            canonical_bytes(claims_dict()),
            RSAKey.import_key(keypair_a[0]),
            algorithms=["RS512"],
        )
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=token, public_keys_pem=[keypair_a[1]], expected_aud=AUD, now=NOW
            )
        assert exc.value.reason == "query_context_signature_invalid"

    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda d: d.pop("jti"), id="missing-key"),
            pytest.param(lambda d: d.update(extra="x"), id="extra-key"),
            pytest.param(lambda d: d.update(iat=True), id="bool-not-int"),
            pytest.param(lambda d: d.update(exp="soon"), id="str-not-int"),
            pytest.param(lambda d: d.update(objects="CUSTOMERS"), id="objects-not-list"),
            pytest.param(lambda d: d.update(objects=[1, 2]), id="objects-not-str-list"),
            pytest.param(lambda d: d.update(iss="someone-else"), id="issuer-not-kernel"),
            pytest.param(lambda d: d.update(tenant_id=7), id="str-field-not-str"),
        ],
    )
    def test_malformed_claims_refuse(self, keypair_a: tuple[bytes, bytes], mutate: Any) -> None:
        payload = claims_dict()
        mutate(payload)
        token = mint(payload, keypair_a[0])
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=token, public_keys_pem=[keypair_a[1]], expected_aud=AUD, now=NOW
            )
        assert exc.value.reason == "query_context_claims_malformed"

    def test_non_object_payload_refuses_malformed(self, keypair_a: tuple[bytes, bytes]) -> None:
        token = jws.serialize_compact(
            {"alg": "RS256"}, b'["not", "an", "object"]', RSAKey.import_key(keypair_a[0])
        )
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=token, public_keys_pem=[keypair_a[1]], expected_aud=AUD, now=NOW
            )
        assert exc.value.reason == "query_context_claims_malformed"

    def test_expired_refuses_and_boundary_instant_is_dead(
        self, keypair_a: tuple[bytes, bytes]
    ) -> None:
        token = mint(claims_dict(), keypair_a[0])
        # now == exp refuses (the kernel's ``now >= exp`` boundary rule).
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=token, public_keys_pem=[keypair_a[1]], expected_aud=AUD, now=EXP
            )
        assert exc.value.reason == "query_context_expired"
        # one second before exp still verifies
        claims = verify_query_context(
            token=token, public_keys_pem=[keypair_a[1]], expected_aud=AUD, now=EXP - 1
        )
        assert claims.exp == EXP

    def test_audience_mismatch_refuses(self, keypair_a: tuple[bytes, bytes]) -> None:
        token = mint(claims_dict(aud="cognic-tool-oracle-schema/list_tables"), keypair_a[0])
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=token, public_keys_pem=[keypair_a[1]], expected_aud=AUD, now=NOW
            )
        assert exc.value.reason == "query_context_audience_mismatch"

    def test_precedence_expired_and_wrong_audience_reports_expired(
        self, keypair_a: tuple[bytes, bytes]
    ) -> None:
        # Precedence is deterministic: expiry (step 3) is evaluated BEFORE
        # audience (step 4) — mirrors the kernel A6 ordering.
        token = mint(claims_dict(aud="other/tool"), keypair_a[0])
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=token, public_keys_pem=[keypair_a[1]], expected_aud=AUD, now=EXP + 5
            )
        assert exc.value.reason == "query_context_expired"

    def test_precedence_malformed_before_expired(self, keypair_a: tuple[bytes, bytes]) -> None:
        payload = claims_dict()
        payload.pop("scope_id")
        token = mint(payload, keypair_a[0])
        with pytest.raises(QueryContextRefusal) as exc:
            verify_query_context(
                token=token, public_keys_pem=[keypair_a[1]], expected_aud=AUD, now=EXP + 5
            )
        assert exc.value.reason == "query_context_claims_malformed"

    def test_wire_payload_is_canonical_bytes_of_claims(
        self, keypair_a: tuple[bytes, bytes]
    ) -> None:
        # The attached-JWS payload segment IS canonical_bytes of the 12-key
        # dict (objects as a list) — the wire form the kernel mints.
        payload = claims_dict()
        token = mint(payload, keypair_a[0])
        verified = jws.deserialize_compact(token, RSAKey.import_key(keypair_a[1]))
        assert verified.payload == canonical_bytes(payload)
        assert json.loads(verified.payload) == payload
