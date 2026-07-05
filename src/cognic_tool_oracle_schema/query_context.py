"""Pack-local mirror of the kernel's query-context verifier (M8, ADR-027 §c).

The Cognic AgentOS kernel mints a short-TTL RS256-signed query-context token
binding one agent dispatch to its resolved data scope (``tenant_id`` /
``scope_id`` / ``objects`` / ``proxy_db_identity``) and its exact arguments
(``args_sha256``). This module is the TOOL-SIDE verifier: a faithful mirror of
the kernel A6 reference implementation at
``cognic_agentos/core/agent/query_context.py`` — the pack has NO runtime
kernel dependency, so the wire contract is re-implemented here and pinned
against the real kernel mint by the cross-repo tests in
``tests/test_kernel_wire_pin.py`` (kernel dev-dep).

Wire form: the FULL 3-segment ATTACHED compact JWS
(``header.payload.signature``). The payload bytes are
``canonical_bytes(<the 12-key claims dict>)`` with ``objects`` as a LIST.

Verification precedence is DETERMINISTIC (mirrors the kernel):
**signature → claims_malformed → expired → audience_mismatch**. Nothing is
parsed off an unverified payload; ``now >= exp`` refuses (the boundary
instant itself is dead); the accepted algorithm is PINNED to ``RS256``.

``canonical_bytes`` below mirrors the kernel canonical form
(``cognic_agentos/core/canonical.py``) for JSON-primitive shapes — the only
shapes MCP tool arguments and query-context claims can carry. The kernel's
extra rules for datetime/UUID/bytes/Decimal/Enum are deliberately NOT
mirrored: those types cannot appear in JSON-decoded MCP arguments, and an
allow-list ``TypeError`` is the correct fail-closed behavior if one ever did.
"""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import RSAKey

#: The fixed kernel issuer claim — the only ``iss`` the verifier accepts.
_ISSUER: Final[str] = "cognic-agentos"

#: Closed-enum refusal vocabulary — mirrors the kernel A6 4-value Literal.
QueryContextRefusalReason = Literal[
    "query_context_signature_invalid",
    "query_context_expired",
    "query_context_audience_mismatch",
    "query_context_claims_malformed",
]


# --- canonical form mirror (JSON-primitive subset of core/canonical.py) --------


def _reject_unsafe_values(obj: Any) -> None:
    """Mirror the kernel pre-walk: reject tuples (silent list-collision),
    non-string dict keys (silent key coercion), and non-finite floats."""
    if isinstance(obj, tuple):
        raise TypeError(
            "tuple not allowed in canonical form (would silently serialize as "
            "a JSON array, colliding with list inputs); convert to list "
            f"explicitly at the call site: {obj!r}"
        )
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError(f"non-finite float not allowed in canonical form: {obj!r}")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(
                    f"non-string dict key not allowed in canonical form: {k!r} ({type(k).__name__})"
                )
            _reject_unsafe_values(v)
        return
    if isinstance(obj, list):
        for v in obj:
            _reject_unsafe_values(v)


def _json_default(o: Any) -> Any:
    """Allow-list by design: MCP arguments / claims are JSON primitives only."""
    raise TypeError(
        f"canonical_bytes cannot serialize {type(o).__name__}; the query-context "
        "canonical mirror accepts JSON-primitive shapes only"
    )


def canonical_bytes(obj: Any) -> bytes:
    """Serialize ``obj`` to canonical UTF-8 JSON bytes.

    Byte-identical to the kernel ``core/canonical.py`` output for
    JSON-primitive shapes (sorted keys, compact separators, preserved
    Unicode, ``allow_nan=False``) — pinned by
    ``tests/test_kernel_wire_pin.py::TestCanonicalMirrorEquality``.
    """
    _reject_unsafe_values(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")


# --- claims + refusal (mirror of the kernel A6 shapes) --------------------------


@dataclass(frozen=True, slots=True)
class QueryContextClaims:
    """The 12 query-context claims, in wire-documentation order.

    ``objects`` rides the wire as a JSON list and is reconstructed to a tuple
    here; ``iat``/``exp`` are integer epoch seconds (bool is NOT an int at
    the verify boundary).
    """

    iss: str
    aud: str
    sub: str
    act: str
    tenant_id: str
    scope_id: str
    objects: tuple[str, ...]
    proxy_db_identity: str
    args_sha256: str
    jti: str
    iat: int
    exp: int


class QueryContextRefusal(RuntimeError):
    """A query-context token failed verification (fail-closed).

    Carries the closed-enum ``reason``; the message is
    ``f"{reason}: {detail}"`` so log lines stay greppable by reason.
    """

    def __init__(self, *, reason: QueryContextRefusalReason, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason: QueryContextRefusalReason = reason


#: The 9 string-typed claim fields (``iss`` additionally carries the
#: ``== _ISSUER`` equality gate below).
_CLAIM_STR_FIELDS: Final[tuple[str, ...]] = (
    "iss",
    "aud",
    "sub",
    "act",
    "tenant_id",
    "scope_id",
    "proxy_db_identity",
    "args_sha256",
    "jti",
)

#: The 2 integer-typed claim fields (epoch seconds; bool refused).
_CLAIM_INT_FIELDS: Final[tuple[str, ...]] = ("iat", "exp")

#: The EXACT 12-key claims key set — missing OR extra keys are malformed.
_CLAIM_KEYS: Final[frozenset[str]] = frozenset((*_CLAIM_STR_FIELDS, "objects", *_CLAIM_INT_FIELDS))


def verify_query_context(
    *,
    token: str,
    public_keys_pem: Sequence[bytes],
    expected_aud: str,
    now: int,
) -> QueryContextClaims:
    """Verify a query-context token and reconstruct its claims.

    Deterministic refusal precedence (mirrors the kernel A6 reference):

      1. **signature** — the token must deserialize + verify under at least
         one key in ``public_keys_pem`` (tried in order — the two-key
         rotation window: operators list [new, old] during a rotation), with
         the accepted algorithm PINNED to ``RS256``. Every key failing OR an
         empty key list → ``query_context_signature_invalid``. Nothing is
         parsed off an unverified payload.
      2. **claims_malformed** — the payload must be a JSON object with
         EXACTLY the 12 documented keys, each type-correct (``objects`` a
         list of str; ``iat``/``exp`` ints with bool refused) and
         ``iss == "cognic-agentos"``.
      3. **expired** — ``now >= exp`` → ``query_context_expired`` (the
         boundary instant itself refuses).
      4. **audience_mismatch** — ``aud != expected_aud``.

    Raises:
        QueryContextRefusal: closed-enum ``reason`` per the precedence above.
    """
    # --- 1. Signature (first — nothing is parsed off an unverified payload).
    payload_bytes: bytes | None = None
    for pem in public_keys_pem:
        try:
            # algorithms pinned to exactly what the kernel mint emits —
            # version-drift armor mirroring the kernel verifier.
            verified = jws.deserialize_compact(token, RSAKey.import_key(pem), algorithms=["RS256"])
        except (JoseError, ValueError, TypeError):
            # Wrong key / non-RS256 alg / tampered token / malformed compact
            # shape / unimportable PEM — try the next rotation-window key.
            continue
        payload_bytes = verified.payload
        break
    if payload_bytes is None:
        raise QueryContextRefusal(
            reason="query_context_signature_invalid",
            detail=(
                f"token did not verify under any of the {len(public_keys_pem)} "
                "configured public key(s)"
            ),
        )

    # --- 2. Claims shape (exactly 12 keys, type-checked, pinned issuer).
    claims = _parse_claims(payload_bytes)

    # --- 3. Expiry (now >= exp refuses — the boundary instant is dead).
    if now >= claims.exp:
        raise QueryContextRefusal(
            reason="query_context_expired",
            detail=f"now={now} >= exp={claims.exp}",
        )

    # --- 4. Audience.
    if claims.aud != expected_aud:
        raise QueryContextRefusal(
            reason="query_context_audience_mismatch",
            detail=f"aud={claims.aud!r} != expected_aud={expected_aud!r}",
        )

    return claims


def _malformed(detail: str) -> QueryContextRefusal:
    return QueryContextRefusal(reason="query_context_claims_malformed", detail=detail)


def _parse_claims(payload_bytes: bytes) -> QueryContextClaims:
    """Parse + shape-gate the verified payload into QueryContextClaims.

    EXACTLY the 12 documented keys (missing OR extra → malformed); every
    field type-checked (bool is NOT an int for ``iat``/``exp``); ``iss`` must
    equal ``_ISSUER``. Every violation refuses
    ``query_context_claims_malformed`` — the closed-enum boundary never leaks
    a raw ``TypeError``/``KeyError`` to the tool caller.
    """
    try:
        parsed = json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _malformed(f"payload is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise _malformed(f"payload JSON root is not an object (got {type(parsed).__name__})")

    keys = set(parsed.keys())
    if keys != _CLAIM_KEYS:
        missing = sorted(_CLAIM_KEYS - keys)
        extra = sorted(keys - _CLAIM_KEYS)
        raise _malformed(f"claims key-set mismatch: missing={missing} extra={extra}")

    for field_name in _CLAIM_STR_FIELDS:
        if not isinstance(parsed[field_name], str):
            raise _malformed(
                f"claim {field_name!r} must be str (got {type(parsed[field_name]).__name__})"
            )
    for field_name in _CLAIM_INT_FIELDS:
        value = parsed[field_name]
        # bool is a subclass of int — guard it FIRST so a JSON true/false can
        # never ride through as an epoch timestamp.
        if isinstance(value, bool) or not isinstance(value, int):
            raise _malformed(f"claim {field_name!r} must be int (got {type(value).__name__})")

    objects_raw = parsed["objects"]
    if not isinstance(objects_raw, list) or not all(isinstance(o, str) for o in objects_raw):
        raise _malformed("claim 'objects' must be a list of str")

    if parsed["iss"] != _ISSUER:
        raise _malformed(f"claim 'iss' must equal {_ISSUER!r} (got {parsed['iss']!r})")

    return QueryContextClaims(
        iss=parsed["iss"],
        aud=parsed["aud"],
        sub=parsed["sub"],
        act=parsed["act"],
        tenant_id=parsed["tenant_id"],
        scope_id=parsed["scope_id"],
        objects=tuple(objects_raw),
        proxy_db_identity=parsed["proxy_db_identity"],
        args_sha256=parsed["args_sha256"],
        jti=parsed["jti"],
        iat=parsed["iat"],
        exp=parsed["exp"],
    )


__all__ = (
    "QueryContextClaims",
    "QueryContextRefusal",
    "QueryContextRefusalReason",
    "canonical_bytes",
    "verify_query_context",
)
