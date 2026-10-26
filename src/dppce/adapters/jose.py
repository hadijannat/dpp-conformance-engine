"""JOSE adapter: verify a JWS credential or token under a named profile (check ``integrity.jose``).

Signature validity, issuer trust, key validity, and credential validity are separate findings.
A signature that verifies shows that the holder of a key signed these bytes. It does not show
that the signed attributes are true. The report signing profile of ``integrity.jws`` is
unchanged; the profiles of this check are in ``dppce.evidence.jose_profiles``.
"""

from __future__ import annotations

import re
from typing import Final, Literal

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from pydantic import Field, ValidationError, field_validator, model_validator

from dppce.adapters.common import (
    blocked,
    completed,
    fetch_once,
    no_answer,
    no_reply,
    resource_url,
    unusable,
)
from dppce.adapters.did import DidDocument, did_web_url, resolve_did_web
from dppce.adapters.integrity import _certificates, _purpose, _status_gap, _TooLongError, trust_path
from dppce.evidence import x509path
from dppce.evidence.jose_profiles import (
    ALGORITHMS,
    ENGINE_LIMITS,
    MAX_SIGNATURES,
    Algorithm,
    JoseError,
    Profile,
    PublicKey,
    Signature,
    Token,
    check_header,
    credential_issuer,
    parse,
    public_key_from_jwk,
    verify,
)
from dppce.infrastructure.clock import parse_stamp
from dppce.infrastructure.interfaces import Record
from dppce.models import (
    CheckOutcome,
    ExecutionStatus,
    JsonValue,
    Model,
    Observation,
    TrustBundle,
    TrustedKey,
)
from dppce.testdefs.registry import CheckContext, register

# A closed set. "did": a key of a resolved DID document that a pinned key of the DID matches.
KeySource = Literal["x5c", "trust_kid", "did"]
_ACCEPT: Final = re.compile(r"[\x20-\x7e]{1,256}")
# A DID URL of any method with a fragment (W3C DID Core 1.0). Only did:web is resolved.
_DID_URL: Final = re.compile(r"did:[a-z0-9]+:[^#\s]+#[^#\s]+")
# The public members of an EC, OKP, or RSA JWK (RFC 7518, RFC 8037). Other members do not name the key.
_PUBLIC_MEMBERS: Final = ("kty", "crv", "x", "y", "n", "e")
_LIMIT: Final = "A valid signature does not prove that the signed attributes are true."
# The resolved DID documents of one check, by DID: each DID is resolved once.
Dids = dict[str, DidDocument | CheckOutcome]


class JoseParams(Model):
    profile: Profile = Field(
        default="vc-jose",
        description=(
            "vc-jose: a W3C VC-JOSE-COSE credential. A present typ must be vc+jwt, and the issuer, iss, "
            "validFrom, validUntil, nbf, and exp are judged. jws: any JWS. No typ and no claim is read."
        ),
    )
    key_source: KeySource = Field(
        default="trust_kid",
        description=(
            "trust_kid: the kid names a key of the trust bundle with the purpose passport. "
            "x5c: the certificate chain in x5c reaches a passport anchor of the trust bundle. "
            "x5c needs the profile jws: no rule binds a credential issuer to a certificate. "
            "did: the kid is a did:web DID URL. The key of the DID document must equal a passport key "
            "of the trust bundle whose issuer is the DID. Resolution is not trust."
        ),
    )
    did_sample: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description=(
            "Name of the IXIT sample that holds an offline copy of the DID document, for the key "
            "source did. Without it, the DID document is fetched through the transport policy."
        ),
    )
    source: Literal["signed", "sample"] = Field(
        default="signed",
        description="signed: fetch the resource 'signed'. sample: read the IXIT sample that 'sample' names.",
    )
    sample: str = Field(
        default="credential",
        min_length=1,
        max_length=64,
        description="Name of the IXIT sample that holds an offline credential file, for the source 'sample'.",
    )
    accept: str | None = Field(
        default=None,
        description="Accept request header for the source 'signed'. Printable ASCII, 1 to 256 characters.",
    )
    algorithms: tuple[Algorithm, ...] | None = Field(
        default=None,
        min_length=1,
        description="Allowlist that narrows the profile, from ES256, ES384, and EdDSA. Default: all three.",
    )

    @field_validator("accept")
    @classmethod
    def _accept(cls, value: str | None) -> str | None:
        if value is not None and not _ACCEPT.fullmatch(value):
            raise ValueError("must be printable ASCII of 1 to 256 characters")
        return value

    @field_validator("algorithms")
    @classmethod
    def _distinct(cls, value: tuple[Algorithm, ...] | None) -> tuple[Algorithm, ...] | None:
        if value is not None and len(set(value)) != len(value):
            raise ValueError("each algorithm may appear once")
        return value

    @model_validator(mode="after")
    def _issuer_binding(self) -> JoseParams:
        # Under vc-jose with x5c, any certificate under an anchor could sign for any issuer.
        if self.profile == "vc-jose" and self.key_source == "x5c":
            raise ValueError("the profile vc-jose needs the key source trust_kid or did")
        if self.did_sample is not None and self.key_source != "did":
            raise ValueError("did_sample needs the key source did")
        return self


class _Finding(Exception):  # noqa: N818 - a finding, not an error of the engine
    """A finding that ends the check: a fail (``passed`` False) or an engine limit (None).

    ``no_answer`` marks a host that gave no answer: a fail that is not a defect, like a limit.
    """

    def __init__(
        self,
        passed: bool | None,
        code: str,
        message: str,
        finding: tuple[str, str] | None = None,
        *,
        no_answer: bool = False,
    ):
        super().__init__(message)
        self.passed, self.code, self.message, self.finding = passed, code, message, finding
        self.no_answer = no_answer


def _acquire(ctx: CheckContext, params: JoseParams) -> Record | CheckOutcome:
    if params.source == "sample":
        record = ctx.acquirer.artifact(params.sample)
        if record.error == "body_too_large":
            return blocked("INTEGRITY.JOSE.TOO_LARGE", "The credential sample is larger than the limit.")
        if record.error is not None:
            return blocked("INTEGRITY.JOSE.SAMPLE_MISSING", f"The sample '{params.sample}' is not available.")
        return record
    url = resource_url(ctx, "signed", "INTEGRITY")
    if isinstance(url, CheckOutcome):
        return url
    record = fetch_once(ctx, url, accept=params.accept)
    # Only a missing answer comes before the status rule: a body coding or a cut body must not
    # turn a status fail into blocked. jose_check applies the body rules after the status rule.
    if no_reply(record):
        return no_answer(ctx, record)
    return record


def _pinned_key(ctx: CheckContext, trust: TrustBundle, signature: Signature) -> tuple[PublicKey, TrustedKey]:
    kid = signature.header.get("kid")
    key = next((k for k in trust.keys if k.kid == kid and "passport" in k.purposes), None)
    if key is None:
        message = "The kid names no passport key of the trust bundle."
        raise _Finding(False, "INTEGRITY.JOSE.ISSUER_UNTRUSTED", message, ("issuer_trust", "no trusted key"))
    return _valid(ctx, trust, key)


def _valid(ctx: CheckContext, trust: TrustBundle, key: TrustedKey) -> tuple[PublicKey, TrustedKey]:
    now = ctx.evaluation_time
    if trust.key_revoked(key.kid, now) or not parse_stamp(key.not_before) <= now <= parse_stamp(
        key.not_after
    ):
        message = "The trusted key is revoked or outside its validity at the evaluation time."
        raise _Finding(False, "INTEGRITY.JOSE.KEY_NOT_VALID", message, ("issuer_trust", "key not valid"))
    return public_key_from_jwk(key.public_jwk), key


def _untrusted(message: str, finding: str) -> _Finding:
    return _Finding(False, "INTEGRITY.JOSE.ISSUER_UNTRUSTED", message, ("issuer_trust", finding))


def _did_key(
    ctx: CheckContext, trust: TrustBundle, params: JoseParams, signature: Signature, dids: Dids
) -> tuple[PublicKey, TrustedKey]:
    """The key of a DID document that a pinned key of the DID matches. Resolution is not trust."""
    kid = signature.header.get("kid")
    if not isinstance(kid, str) or not _DID_URL.fullmatch(kid):
        raise _untrusted("The kid is not a DID URL with a fragment.", "no DID URL")
    did = kid.partition("#")[0]
    # The pin comes before the DID method, so an untrusted signer cannot pick a kid that gives a
    # limit of the engine in place of this fail. Nothing pins the DID, so its host is not contacted.
    pinned = [k for k in trust.keys if k.issuer == did and "passport" in k.purposes]
    if not pinned:
        raise _untrusted(
            "No passport key of the trust bundle has the DID of the kid as its issuer.", "no pin"
        )
    if did_web_url(did) is None:
        if not did.startswith("did:web:"):
            message = "The kid is a DID URL of a DID method that this engine does not resolve."
            raise _Finding(None, "INTEGRITY.JOSE.UNSUPPORTED", message)
        raise _untrusted("The kid is not a did:web DID URL with a fragment.", "no DID URL")
    if did not in dids:
        dids[did] = resolve_did_web(ctx, did, params.did_sample)
    resolved = dids[did]
    if isinstance(resolved, CheckOutcome):
        if resolved.unreachable:
            raise _Finding(False, resolved.reason_code, resolved.message, no_answer=True)
        if resolved.passed is False:
            message = f"The DID document of the kid breaks the rule {resolved.reason_code}."
            raise _untrusted(message, "the DID document breaks a rule")
        raise _Finding(None, resolved.reason_code, resolved.message)
    if kid not in resolved.assertion_methods:
        raise _untrusted("The kid is not an assertion method of the DID document.", "not an assertion method")
    public = resolved.keys.get(kid)
    if public is None:
        message = "The assertion method of the kid has no publicKeyJwk. This engine reads JWK keys only."
        raise _Finding(None, "INTEGRITY.JOSE.UNSUPPORTED", message)
    match = next(
        (k for k in pinned if all(k.public_jwk.get(m) == public.get(m) for m in _PUBLIC_MEMBERS)), None
    )
    if match is None:
        raise _untrusted(
            "The key of the DID document is not a pinned key of the DID.", "no pinned key matches"
        )
    return _valid(ctx, trust, match)


def _chain_key(trust: TrustBundle, signature: Signature) -> tuple[PublicKey, list[x509.Certificate]]:
    try:
        certificates = _certificates(signature.header)
    except _TooLongError:
        # The limit applies to a chain of certificates only. The body limit bounds this decoding.
        chain = signature.header["x5c"]
        assert isinstance(chain, list)  # noqa: S101 - _certificates raises for a long list only
        if all(_certificates({"x5c": [item]}) for item in chain):
            raise _Finding(
                None, "INTEGRITY.JOSE.TOO_LARGE", f"The x5c chain is longer than {x509path.MAX_CHAIN}."
            ) from None
        raise _Finding(
            False, "INTEGRITY.JOSE.MALFORMED", "The x5c header does not hold certificates."
        ) from None
    if certificates is None:
        if "x5c" in signature.header:
            raise _Finding(False, "INTEGRITY.JOSE.MALFORMED", "The x5c header does not hold certificates.")
        message = "The token has no x5c chain to a trust anchor."
        raise _Finding(False, "INTEGRITY.JOSE.ISSUER_UNTRUSTED", message, ("issuer_trust", "no x5c chain"))
    path = trust_path(certificates[0], certificates[1:], trust)
    if path is None:
        message = "The certificate of the token does not chain to an anchor of the trust bundle."
        finding = ("issuer_trust", "no path to a trust anchor")
        raise _Finding(False, "INTEGRITY.JOSE.ISSUER_UNTRUSTED", message, finding)
    if (gap := x509path.path_gap(path)) is not None:
        raise _Finding(None, "INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT", gap)
    try:
        key = certificates[0].public_key()
    except (UnsupportedAlgorithm, ValueError):
        key = None
    if not isinstance(key, PublicKey):
        raise _Finding(None, "INTEGRITY.JOSE.UNSUPPORTED", "The certificate key is of an unsupported type.")
    return key, path


def _chain_findings(ctx: CheckContext, trust: TrustBundle, path: list[x509.Certificate]) -> None:
    """The certificate findings in the order of integrity.jws: purpose to revocation."""
    now = ctx.evaluation_time
    may_sign, message = _purpose(path[0])
    if may_sign is None:
        raise _Finding(None, "INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT", message)
    if not may_sign:
        raise _Finding(False, "INTEGRITY.CERT.KEY_USAGE", message, ("key_usage", "does not permit signing"))
    anchor, below = path[-1], path[:-1]
    revocations = trust.revoked_certificates
    if not anchor.not_valid_before_utc <= now <= anchor.not_valid_after_utc or x509path.revoked(
        [anchor], revocations, now
    ):
        message = "The trust anchor of this chain is expired or revoked in the operator's trust bundle."
        raise _Finding(None, "INTEGRITY.TRUST.ANCHOR_INVALID", message)
    if not all(c.not_valid_before_utc <= now <= c.not_valid_after_utc for c in below):
        message = "A certificate of the chain is outside its validity period at the evaluation time."
        raise _Finding(False, "INTEGRITY.CERT.EXPIRED", message, ("certificate_validity", "outside"))
    if (gap := _status_gap(trust, now)) is not None:
        raise _Finding(None, "INTEGRITY.STATUS.MISSING", gap)
    if x509path.revoked(below, revocations, now):
        message = "A certificate of the chain is in the revocation snapshot."
        raise _Finding(False, "INTEGRITY.CERT.REVOKED", message, ("revocation", "revoked"))


def _defer(exc: JoseError | _Finding, deferred: list[Exception]) -> None:
    """Keep an engine limit for the end of the check. Raise any other finding at once."""
    if (isinstance(exc, JoseError) and exc.code in ENGINE_LIMITS) or (
        isinstance(exc, _Finding) and (exc.passed is None or exc.no_answer)
    ):
        deferred.append(exc)
        return
    raise exc


def _signature(
    ctx: CheckContext,
    trust: TrustBundle,
    params: JoseParams,
    signature: Signature,
    *,
    found: tuple[list[TrustedKey], list[list[x509.Certificate]]],
    findings: dict[str, JsonValue],
    dids: Dids,
) -> None:
    """The header, key, and signature rules of one signature."""
    check_header(signature, params.profile)
    if params.key_source == "trust_kid":
        key, entry = _pinned_key(ctx, trust, signature)
        found[0].append(entry)
    elif params.key_source == "did":
        key, entry = _did_key(ctx, trust, params, signature, dids)
        found[0].append(entry)
    else:
        key, path = _chain_key(trust, signature)
        found[1].append(path)
    try:
        verify(signature, key, params.algorithms or ALGORITHMS)
    except JoseError as exc:
        if exc.code == "INTEGRITY.JOSE.SIGNATURE":
            findings["signature"] = "invalid"
        raise


def _judge(
    ctx: CheckContext,
    trust: TrustBundle,
    params: JoseParams,
    body: bytes,
    *,
    findings: dict[str, JsonValue],
    dids: Dids,
) -> Token:
    """Every finding in the order of the contract. Returns the token only if it passes.

    An engine limit of one signature is kept, and the other signatures and the claims are judged.
    So a fail anywhere comes before any limit, in every order of the signatures.
    """
    token = parse(body)
    findings |= {"serialization": token.serialization, "signatures": len(token.signatures)}
    deferred: list[Exception] = []
    if token.truncated:
        message = f"The token has more than {MAX_SIGNATURES} signatures."
        deferred.append(JoseError("INTEGRITY.JOSE.TOO_LARGE", message))
    pinned: list[TrustedKey] = []
    paths: list[list[x509.Certificate]] = []
    for signature in token.signatures:
        try:
            _signature(ctx, trust, params, signature, found=(pinned, paths), findings=findings, dids=dids)
        except (JoseError, _Finding) as exc:
            _defer(exc, deferred)
    if not deferred:
        findings |= {"signature": "valid", "issuer_trust": "a trusted key"}
    for path in paths:
        try:
            _chain_findings(ctx, trust, path)
        except _Finding as exc:
            _defer(exc, deferred)
    if params.profile == "vc-jose":
        issuer = credential_issuer(token.payload, ctx.evaluation_time)
        findings["validity"] = "valid at the evaluation time"
        if any(entry.issuer != issuer for entry in pinned):
            message = "The trust bundle binds the key to an issuer other than the credential issuer."
            finding = ("issuer_trust", "the key belongs to a different issuer")
            raise _Finding(False, "INTEGRITY.JOSE.ISSUER_UNTRUSTED", message, finding)
    if deferred:
        raise deferred[0]
    return token


def did_observations(ctx: CheckContext, dids: Dids, start: int) -> list[Observation]:
    """The observations of the resolved DID documents, numbered from ``start`` so each id is unique."""
    found = [
        o
        for v in dids.values()
        for o in (v.observations if isinstance(v, CheckOutcome) else (v.observation,))
    ]
    return [o.model_copy(update={"id": f"{ctx.purpose.id}#{start + n}"}) for n, o in enumerate(found)]


def judged(
    passed: bool | None,
    code: str,
    message: str,
    observations: list[Observation],
    *,
    no_answer: bool = False,
    limit: ExecutionStatus = ExecutionStatus.BLOCKED,
) -> CheckOutcome:
    """The outcome of a finding: a limit is ``limit``, a host without an answer is no answer."""
    if passed is None:
        return CheckOutcome(status=limit, reason_code=code, message=message, observations=tuple(observations))
    if no_answer:
        return completed(False, code, message, observations, no_answer=True)
    return completed(passed, code, f"{message} {_LIMIT}", observations)


@register("integrity.jose", capability="integrity.jose", params=JoseParams)
def jose_check(ctx: CheckContext) -> CheckOutcome:
    try:
        params = JoseParams.model_validate(ctx.params)
    except ValidationError:
        return blocked("INTEGRITY.JOSE.PARAMS", "The parameters are not valid. Nothing is read.")
    if ctx.trust is None:
        return blocked(
            "INTEGRITY.TRUST.MISSING", "No trust bundle is configured. Nothing is trusted by default."
        )
    acquired = _acquire(ctx, params)
    if isinstance(acquired, CheckOutcome):
        return acquired
    record = acquired
    findings: dict[str, JsonValue] = {"source": params.source}
    dids: Dids = {}

    def outcome(passed: bool | None, code: str, message: str, *, no_answer: bool = False) -> CheckOutcome:
        kind: Literal["artifact", "exchange"] = "artifact" if record.kind == "artifact" else "exchange"
        observation = ctx.observation(0, kind=kind, records=[record], summary={"findings": findings})
        return judged(
            passed, code, message, [observation, *did_observations(ctx, dids, 1)], no_answer=no_answer
        )

    if (gate := credential_gate(ctx, record, findings)) is not None:
        return gate if isinstance(gate, CheckOutcome) else outcome(*gate)
    try:
        _judge(ctx, ctx.trust, params, record.body, findings=findings, dids=dids)
    except (JoseError, _Finding) as exc:
        return outcome(*finding_of(exc, findings), no_answer=isinstance(exc, _Finding) and exc.no_answer)
    signer = {
        "trust_kid": "a pinned key of the trust bundle",
        "did": "a key of the DID document that a pinned key of the DID matches",
        "x5c": "the key of a certificate that chains to a passport anchor",
    }[params.key_source]
    if params.profile == "jws":
        message = (
            f"The signature verifies with {signer} under the profile jws. "
            "No claim, no validity, and no issuer binding was judged."
        )
    elif params.key_source == "did":
        message = f"The signature verifies with {signer}. The issuer key and the validity are in order."
    else:
        message = "The signature, the issuer key, and the validity are in order under the profile."
    return outcome(True, "INTEGRITY.JOSE.OK", message)


def credential_gate(
    ctx: CheckContext, record: Record, findings: dict[str, JsonValue]
) -> CheckOutcome | tuple[bool, str, str] | None:
    """The status rule and the body rules of a fetched credential, before its body is judged."""
    if record.kind == "http" and record.status != 200:
        findings["status"] = record.status
        message = f"The system declares a signed resource, and its endpoint answers {record.status}."
        return False, "INTEGRITY.JOSE.NOT_AVAILABLE", message
    if record.kind == "http":
        return unusable(ctx, record)
    return None


def finding_of(exc: JoseError | _Finding, findings: dict[str, JsonValue]) -> tuple[bool | None, str, str]:
    """(passed, code, message) of a refused token. An engine limit has ``passed`` None."""
    if isinstance(exc, JoseError):
        return (None if exc.code in ENGINE_LIMITS else False), exc.code, exc.message
    if exc.finding is not None:
        findings[exc.finding[0]] = exc.finding[1]
    return exc.passed, exc.code, exc.message
