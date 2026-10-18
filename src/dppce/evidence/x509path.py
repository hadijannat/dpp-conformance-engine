"""X.509 certificate paths and issuer-scoped revocation by snapshot.

The passport check (``integrity.jws``) and the timestamp verifier share this code. It does no
network I/O: no CRL, no OCSP, and no certificate URL is fetched.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

from dppce.models import RevokedCertificate, TrustAnchor

MAX_CHAIN: Final = 5

# Extensions that this engine evaluates. Any other extension marked critical is a constraint
# that a conforming validator must understand (RFC 5280, section 4.2), so the path is not passed.
_EVALUATED: Final = frozenset(
    {
        x509.BasicConstraints.oid, x509.KeyUsage.oid, x509.ExtendedKeyUsage.oid,
        x509.SubjectKeyIdentifier.oid, x509.AuthorityKeyIdentifier.oid,
    }
)  # fmt: skip
_NOT_EVALUATED: Final = (x509.NameConstraints, x509.PolicyConstraints, x509.InhibitAnyPolicy)


def extensions(certificate: x509.Certificate) -> x509.Extensions | None:
    """The extensions, or None if they cannot be parsed (malformed or repeated)."""
    try:
        return certificate.extensions
    except ValueError:
        return None


def extension_value[E: x509.ExtensionType](certificate: x509.Certificate, kind: type[E]) -> E | None:
    found = extensions(certificate)
    if found is None:
        return None
    try:
        return found.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return None


def _may_issue(issuer: x509.Certificate, authorities_below: int) -> bool:
    """True if ``issuer`` is a certificate authority that may sign the next certificate of the path.

    A signature and a matching name are not enough. Without this test, the holder of any end
    certificate from a trusted root could sign certificates of its own.
    """
    constraints = extension_value(issuer, x509.BasicConstraints)
    if constraints is None or not constraints.ca:
        # No basic constraints, or extensions that cannot be read: not a certificate authority.
        return False
    if constraints.path_length is not None and authorities_below > constraints.path_length:
        return False
    usage = extension_value(issuer, x509.KeyUsage)
    return usage is None or bool(usage.key_cert_sign)


def trust_path(
    leaf: x509.Certificate, intermediates: list[x509.Certificate], anchors: Sequence[TrustAnchor]
) -> list[x509.Certificate] | None:
    """Return the path from the leaf to one of ``anchors``, or None if there is none.

    Each issuer must have signed the certificate below it, must be a certificate authority,
    must permit signing certificates, and must respect its path length constraint.
    """
    loaded = [x509.load_pem_x509_certificate(a.certificate_pem.encode("ascii")) for a in anchors]
    candidates = [*((a, True) for a in loaded), *((i, False) for i in intermediates)]

    def extend(path: list[x509.Certificate]) -> list[x509.Certificate] | None:
        # Depth first, with backtracking: a cross-signed authority can appear twice in ``x5c``,
        # once under an anchor and once under a root that the bundle does not hold.
        depth = len(path) - 1  # the number of certificate authorities already below the next issuer
        if depth >= MAX_CHAIN:
            return None
        for candidate, is_anchor in candidates:
            # An intermediate cannot appear twice. An anchor ends the path, so it can sign itself:
            # a passport signed with the key of a self-signed anchor has the path [anchor, anchor].
            if (not is_anchor and candidate in path) or not _may_issue(candidate, authorities_below=depth):
                continue
            try:
                path[-1].verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
                continue
            found = [*path, candidate] if is_anchor else extend([*path, candidate])
            if found is not None:
                return found
        return None

    return extend([leaf])


def _issuer_matches(entry: RevokedCertificate, certificate: x509.Certificate) -> bool:
    if entry.issuer_name is not None:
        # The model validated the name. The comparison is exact, without case folding.
        return x509.Name.from_rfc4514_string(entry.issuer_name) == certificate.issuer
    authority = extension_value(certificate, x509.AuthorityKeyIdentifier)
    # A certificate without the extension, or with unreadable extensions, never matches a key id.
    return (
        authority is not None
        and entry.issuer_key_id is not None
        and authority.key_identifier == bytes.fromhex(entry.issuer_key_id)
    )


def revoked(
    path: Sequence[x509.Certificate], revocations: Sequence[RevokedCertificate], at: datetime
) -> bool:
    """True if an entry revokes a certificate of the path at ``at``.

    An entry matches when the serial (compared as an integer) and the issuer both match. It
    applies from ``revoked_at``, or at every time if that is null. Instants compare exactly.
    """
    active = [
        r
        for r in revocations
        if r.revoked_at is None
        or datetime.strptime(r.revoked_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC) <= at
    ]
    return any(
        int(r.serial.replace(":", ""), 16) == certificate.serial_number and _issuer_matches(r, certificate)
        for certificate in path
        for r in active
    )


def path_gap(path: Sequence[x509.Certificate]) -> str | None:
    """Return a constraint of the path that this engine cannot evaluate, or None.

    The engine implements a subset of RFC 5280 path validation: signature, issuer name,
    certificate authority, path length, certificate signing usage, validity, and revocation by
    snapshot. It does not evaluate name constraints or policy constraints. A path that carries
    one is not passed: the result is inconclusive.
    """
    for certificate in path:
        found = extensions(certificate)
        if found is None:
            return "A certificate of the chain has extensions that this engine cannot read."
        for extension in found:
            if isinstance(extension.value, _NOT_EVALUATED):
                return (
                    f"A certificate of the chain has {type(extension.value).__name__}, "
                    "which this engine does not evaluate."
                )
            if extension.critical and extension.oid not in _EVALUATED:
                return (
                    "A certificate of the chain has a critical extension that this engine does not evaluate."
                )
    return None
