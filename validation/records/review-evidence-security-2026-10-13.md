# Security review of the evidence, verifier, transport, and adapter code

Audience: maintainers, operators, and the person who ratifies the ADRs.
Purpose: report what an independent agent review found in the security-relevant code, with
reproductions, so that each item can be fixed or accepted on record.
Prerequisites: read `docs/explanation/architecture.md` sections 9 to 12,
`docs/explanation/threat-model.md`, and ADRs 0005 to 0012.

## Status

| Field | Value |
| --- | --- |
| Reviewer | An AI model: Claude, model identifier `claude-fable-5-1` |
| Date | 2026-10-13 |
| Commit reviewed | `d53170c55eedbfce981ebd5071fab7352c7fd24f` |
| Nature of this record | An agent review. It is not a human approval. It is not an independent security audit. |

The reviewer did not write the code under review. The reviewer gains nothing if the code is
correct. Every reproduction in this record was run on loopback servers and temporary
directories only. No real system was contacted.

## Scope

Reviewed in full:

- `src/dppce/evidence/canonical.py`, `merkle.py`, `recording.py`, `jws.py`, `envelope.py`
- `src/dppce/verifier/verify.py`, `src/dppce/verifier/__main__.py`
- `src/dppce/infrastructure/authorization.py`, `transport.py`, `redaction.py`, `keys.py`, `replay.py`
- `src/dppce/cli.py` (ICS, IXIT, trust bundle, secrets, and paths)
- `src/dppce/adapters/integrity.py`, `src/dppce/adapters/access.py`
- `src/dppce/orchestrator/run.py`

Read for context only: `src/dppce/adapters/common.py`, `src/dppce/testdefs/registry.py`,
`src/dppce/infrastructure/interfaces.py`, the models, and the existing tests.

## Method

1. Read the contract and the threat model. Treated each claim as a hypothesis to test.
2. Read each file in scope in full. Listed every suspected defect.
3. For each suspect, wrote a short script and ran it with `uv run python - <<'EOF'`. Scripts
   used the existing test helpers (`tests/support.py`, `tests/test_adapters_security.py`), a
   loopback HTTP server, or a canned acquirer. No script contacted a host other than loopback.
4. Marked a finding "reproduced" only when a script ran and showed the behavior.
5. Ran the fast test suite once to record its state at the reviewed commit.

The reproduction scripts are not part of the repository. The report quotes the parts that
matter. Each quoted script can be run from the repository root.

## Findings

| Id | Severity | Component | Title | Reproduced |
| --- | --- | --- | --- | --- |
| F-01 | high | adapters/integrity.py | Engine limits on the passport token are reported as an invalid signature (fail) | yes |
| F-02 | high | adapters/integrity.py | The engine's JCS rule is applied to the third-party payload; a float or non-canonical bytes give fail | yes |
| F-03 | high | adapters/access.py, cli.py | A role probe without a credential is attributed to the role and can pass | yes |
| F-04 | medium | adapters/access.py | An encoded non-JSON body hides a canary and the channel passes | yes |
| F-05 | medium | infrastructure/transport.py | Total request time is not bounded; only each socket operation is | yes |
| F-06 | medium | infrastructure/transport.py | A redirect to a non-ASCII path raises out of `fetch` | yes |
| F-07 | low | adapters/integrity.py | A P-384 leaf certificate raises `OverflowError` (execution error, run aborted) | yes |
| F-08 | low | cli.py, transport.py | IXIT sample paths are confined at check time and read later | yes |
| F-09 | low | evidence/recording.py, cli.py | Purge deletes any directory with an expired clear-text index; retention comes from the IXIT | yes |
| F-10 | low | evidence/recording.py | A sealed file shorter than the nonce raises `ValueError`, not `RecordingError` | yes |
| F-11 | low | evidence/recording.py | The record identifier pattern uses `$` and admits a trailing newline | yes |
| F-12 | low | infrastructure/redaction.py | Response headers are default-allow; `Link` is recorded unredacted | yes |
| F-13 | info | evidence/jws.py | The verification JWK `kty` is not checked | yes |
| F-14 | low | cli.py | `--allow-remote-read` confirms every public host that the IXIT names at once | no |
| F-15 | low | cli.py | `report --trust` verifies at the current time when `--at` is absent | no |
| F-16 | low | adapters/integrity.py | Name constraints and extended key usage are not enforced on the path | no |
| F-17 | info | cli.py, transport.py | Credential origin strings are built two ways and can disagree | no |

### F-01. Engine limits on the passport token are reported as an invalid signature

Severity: high. Component: `src/dppce/adapters/integrity.py`, lines 129 to 147.

Description. `jws_check` maps every `SignatureError` except `TOO_LARGE` to
`completed(False, "INTEGRITY.SIGNATURE.INVALID", "The signature does not verify with the key of
its certificate.")`. That is a `fail` for the tested system. The codes `NOT_ALLOWED` and
`MALFORMED` are limits of this engine, not evidence about the system: an algorithm outside the
one-entry allowlist (ES384, RS256, EdDSA), a header parameter outside the four that the engine
knows (`x5t#S256`, `cty`, `crit`), or a leaf key that is not P-256. A non-200 status on
`/signed` (503, 404) and a non-JWS body take the same path, because `unusable()` checks the
transport error and the truncation flag but not the status. The threat model (row "A limit or a
defect of the engine reads as a failure of the tested system") claims this cannot happen.

Reproduction (canned acquirer, no network).

```python
# uv run python - <<'EOF'   (from the repository root)
import base64, json
from datetime import UTC, datetime
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from dppce.adapters.integrity import jws_check
from dppce.infrastructure.interfaces import Record, Request
from dppce.models import ICS, IXIT, Profile, TestPurpose
from dppce.testdefs.registry import CheckContext
from tests.support import make_record
from tests.test_adapters_security import bundle, issue

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def token(header, payload, key):
    si = f"{b64u(json.dumps(header, separators=(',', ':')).encode())}.{b64u(payload)}".encode()
    r, s = decode_dss_signature(key.sign(si, ec.ECDSA(hashes.SHA256())))
    return f"{si.decode()}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

class Canned:
    def __init__(self, signed, item, status=200): self.signed, self.item, self.status, self._r = signed, item, status, []
    def fetch(self, req: Request) -> Record:
        s = req.url.endswith("/signed"); base = make_record(len(self._r) + 1, self.signed if s else self.item, req.url)
        rec = Record(**{**base.__dict__, "status": self.status if s else 200}); self._r.append(rec); return rec
    def artifact(self, n): raise AssertionError
    def records(self): return tuple(self._r)

def ctx(acq, trust):
    purpose = TestPurpose.model_validate({"id": "TP-X", "title": "t", "requirements": ["R"], "profiles": ["*"],
        "applicability": {"const": "true"}, "stimulus": {"check": "integrity.jws"}, "permitted_modes": ["illustrative"]})
    profile = Profile.model_validate({"schema_version": "dppce.profile/1", "id": "p/x", "title": "t",
        "product_category": "x", "packs": [], "testpacks": []})
    ics = ICS.model_validate({"schema_version": "dppce.ics/1", "sut": {"name": "s", "identifier": "urn:x"}, "profile": "p/x"})
    ixit = IXIT.model_validate({"schema_version": "dppce.ixit/1", "endpoints": {"api": "http://sut.example"}, "samples": {"passport_id": "P1"}})
    return CheckContext(purpose=purpose, ics=ics, ixit=ixit, profile=profile, acquirer=acq,
                        evaluation_time=datetime(2026, 10, 13, tzinfo=UTC), data_root=Path("."), trust=trust)

root = issue("root", None, ca=True); leaf = issue("leaf", root, ca=False); trust = bundle(root[1])
x5c = [base64.b64encode(leaf[1].public_bytes(serialization.Encoding.DER)).decode()]
hdr = {"alg": "ES256", "typ": "dpp+jws", "x5c": x5c}; item = b'{"a":1}'
for label, signed, status in (
    ("baseline", token(hdr, item, leaf[0]), 200),
    ("alg ES384", token(hdr | {"alg": "ES384"}, item, leaf[0]), 200),
    ("header x5t#S256", token(hdr | {"x5t#S256": "abc"}, item, leaf[0]), 200),
    ("HTTP 503 on /signed", token(hdr, item, leaf[0]), 503),
    ("not a JWS", "<html>maintenance</html>", 200),
):
    out = jws_check(ctx(Canned(signed.encode(), item, status), trust))
    print(f"{label:22} status={out.status.value} passed={out.passed} code={out.reason_code}")
EOF
```

Observed output.

```text
baseline               status=completed passed=True code=INTEGRITY.OK
alg ES384              status=completed passed=False code=INTEGRITY.SIGNATURE.INVALID
header x5t#S256        status=completed passed=False code=INTEGRITY.SIGNATURE.INVALID
HTTP 503 on /signed    status=completed passed=False code=INTEGRITY.SIGNATURE.INVALID
not a JWS              status=completed passed=False code=INTEGRITY.SIGNATURE.INVALID
```

The full script also showed the same `fail` for an extra `cty` header, an RSA leaf under the
anchor with `RS256`, and a 404.

Recommendation. Map `NOT_ALLOWED` and `MALFORMED` to `blocked` with distinct codes, for example
`INTEGRITY.ALGORITHM.UNSUPPORTED` and `INTEGRITY.TOKEN.NOT_PROCESSABLE`. Reserve
`INTEGRITY.SIGNATURE.INVALID` for `BAD_SIGNATURE` only. Treat a non-200 status as
`unreachable` (5xx) or as a separate completed finding with its own code (4xx). State in the
capability manifest that only ES256 with an `x5c` P-256 leaf is supported.

### F-02. The engine's JCS rule is applied to the third-party payload

Severity: high. Component: `src/dppce/adapters/integrity.py`, lines 180 to 189.

Description. The payload comparison is `canonical_bytes(document) == payload`. `document` is
the published passport parsed from the item endpoint; `payload` is the raw signed bytes of the
third-party token. `canonical_bytes` enforces the engine's own rules from ADR 0006: RFC 8785
form and integers only. A passport whose JSON holds a float raises `CanonicalizationError`,
which is caught and becomes `same = False`. A signed payload that is not byte-for-byte RFC 8785
(key order, whitespace) also differs. Both give `completed(False, "INTEGRITY.PAYLOAD.MISMATCH")`,
a `fail`. ADR 0006 says JCS "does not replace the processing rules of any credential securing
specification". No DPP credential specification requires an RFC 8785 payload.

Reproduction. Same harness as F-01, with these cases.

```python
for label, raw in (("float 1.5", b'{"a":1.5}'), ("not JCS order", b'{"b":1,"a":2}'), ("whitespace", b'{"a": 1}')):
    out = jws_check(ctx(Canned(token(hdr, raw, leaf[0]).encode(), raw), trust))
    print(f"{label:14} passed={out.passed} code={out.reason_code}")
```

Observed output.

```text
float 1.5      passed=False code=INTEGRITY.PAYLOAD.MISMATCH
not JCS order  passed=False code=INTEGRITY.PAYLOAD.MISMATCH
whitespace     passed=False code=INTEGRITY.PAYLOAD.MISMATCH
```

In each case the signed payload and the published document were identical bytes.

Recommendation. Parse the signed payload with `parse_strict` and compare the two parsed JSON
values for equality. If a float is present, either compare parsed values with a documented
float rule or return `blocked` with a code such as `INTEGRITY.PAYLOAD.NOT_COMPARABLE`. Never
let the engine's integer-only rule produce a `fail` for an external document.

### F-03. A role probe without a credential is attributed to the role and can pass

Severity: high. Component: `src/dppce/adapters/access.py` lines 87 to 94 and 141 to 146;
`src/dppce/cli.py` lines 263 to 266; `src/dppce/infrastructure/transport.py` lines 221 to 223.

Description. The check fetches each channel with `Request(..., role=role)`. The transport adds
an `Authorization` header only if `credentials[role]` exists and its origin equals the target
origin. Otherwise the request goes out with no credential, but the record still says `role`.
The check does not verify that a credential was attached. It then reports
`ACCESS.POLICY.ENFORCED` for the role, when it observed the anonymous view. The credential is
absent whenever the IXIT names no `secret_ref` for the role, whenever `cmd_run` computes
`permitted` as false, or whenever the two origin strings disagree (see F-17). An authorization
that lists the role does not change this: `_target` checks the role name, not the credential.
The supplier controls the IXIT. Omitting one `secret_ref` turns a leaking role into a pass.

Reproduction (loopback server; the system leaks to any bearer token).

```python
# uv run python - <<'EOF'
import tempfile, yaml
from datetime import UTC, datetime
from pathlib import Path
from dppce.adapters.access import restricted_fields
from dppce.infrastructure.clock import FrozenClock
from dppce.infrastructure.transport import PolicyTransport, TransportConfig
from dppce.models import ICS, IXIT, Authorization, NetworkPolicy, Profile, TestPurpose
from dppce.testdefs.registry import CheckContext
from tests.support import LoopbackServer, reply
from tests.test_adapters_security import _POLICY

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC); tmp = Path(tempfile.mkdtemp())
def leaky(req):
    reply(req, body=b'{"id":"x","restricted":{"secret":"CANARY-test"}}' if req.headers.get("Authorization") else b'{"id":"x"}')
server = LoopbackServer(leaky)
policy = {"allowed_hosts": ("127.0.0.1",), "allow_private_hosts": ("127.0.0.1",)}
auth = Authorization.model_validate({"schema_version": "dppce.authorization/1", "authorization_id": "TEST-ONLY-a",
    "issuer": "urn:i", "subject": "urn:s", "sut_identifier": "urn:x", "endpoints": (server.origin,), "methods": ("GET",),
    "roles": ("anonymous", "legitimate_interest"), "scopes": ("read", "access_probe"),
    "not_before": "2026-10-01T00:00:00Z", "not_after": "2026-10-31T00:00:00Z", "max_requests": 50})
def ctx(acq, role):
    (tmp / "policy.yaml").write_text(yaml.safe_dump(_POLICY), encoding="utf-8")
    purpose = TestPurpose.model_validate({"id": "TP-X", "title": "t", "requirements": ["R"], "profiles": ["*"],
        "applicability": {"const": "true"}, "stimulus": {"check": "access.restricted_fields", "params": {"role": role}},
        "permitted_modes": ["illustrative"]})
    profile = Profile.model_validate({"schema_version": "dppce.profile/1", "id": "p/x", "title": "t", "product_category": "x",
        "access_policy": "policy.yaml", "packs": [], "testpacks": []})
    ics = ICS.model_validate({"schema_version": "dppce.ics/1", "sut": {"name": "s", "identifier": "urn:x"}, "profile": "p/x"})
    ixit = IXIT.model_validate({"schema_version": "dppce.ixit/1", "endpoints": {"api": server.origin}, "samples": {"passport_id": "0950-EV1"}})
    return CheckContext(purpose=purpose, ics=ics, ixit=ixit, profile=profile, acquirer=acq, evaluation_time=NOW, data_root=tmp, authorization=auth)
def transport(credentials):
    return PolicyTransport(TransportConfig(policy=NetworkPolicy(**policy), engine_version="t", credentials=credentials, authorization=auth), FrozenClock(NOW), sleep=lambda _: None)

t = transport({"legitimate_interest": (server.origin, "TEST-ONLY-token")})
out = restricted_fields(ctx(t, "legitimate_interest")); print("with credential   :", out.passed, out.reason_code, t.records()[0].request_headers)
t = transport({})   # the IXIT named no secret_ref for the role
out = restricted_fields(ctx(t, "legitimate_interest")); print("without credential:", out.passed, out.reason_code, t.records()[0].request_headers)
server.close()
EOF
```

Observed output.

```text
with credential   : False ACCESS.LEAK.FETCH (('Accept', '*/*'), ('Authorization', '<removed>'), ('User-Agent', 'dppce/t'))
without credential: True ACCESS.POLICY.ENFORCED (('Accept', '*/*'), ('User-Agent', 'dppce/t'))
```

Recommendation. In `restricted_fields`, for any role other than `anonymous`, require that every
record's `request_headers` names `Authorization` (the redacted entry proves it was sent). If
not, return `blocked("ACCESS.ROLE.NO_CREDENTIAL", ...)`. In `cmd_run`, refuse to start when a
test purpose needs a role for which no confirmed credential exists. Build the credential origin
with the same function as the transport (F-17).

### F-04. An encoded non-JSON body hides a canary and the channel passes

Severity: medium. Component: `src/dppce/adapters/access.py`, lines 104 to 116 and 132 to 146.

Description. On a channel whose body is not JSON, the only detector is
`c.value.encode("utf-8") in record.body`. The transport does not decompress and sends no
`Accept-Encoding`, but the tested system chooses its encoding. A gzip body, a UTF-16 body, or
an HTML entity in the canary (`CANARY&#45;test`) defeats the byte search. When every withheld
field has a canary, the check returns `ACCESS.POLICY.ENFORCED`. The threat model row "A tested
system hides a leak behind a wrong media type" says "a partial look never passes".

Reproduction. One sentence: with the `_Canned` acquirer from `tests/test_adapters_security.py`
and a policy whose only channel is `html`, bodies `gzip.compress(b"<p>CANARY-test</p>")`,
`"<p>CANARY-test</p>".encode("utf-16")`, and `b"<p>CANARY&#45;test</p>"` with
`Content-Type: text/html` each gave `passed=True code=ACCESS.POLICY.ENFORCED`.

Recommendation. Treat a `Content-Encoding` other than identity, a non-UTF-8 charset, and a
body that is not valid UTF-8 as not checkable: return `blocked("ACCESS.RESPONSE.NOT_CHECKABLE")`.
Document that a canary must be chosen so that common escapes cannot split it, or search for
canaries after HTML entity decoding on `text/html`.

### F-05. Total request time is not bounded

Severity: medium. Component: `src/dppce/infrastructure/transport.py`, lines 187 to 203.

Description. `timeout_ms` is applied as a socket timeout. It bounds each `recv`, not the
request. A system that sends one byte at a time inside the timeout keeps `getresponse()` and
`read()` alive as long as it likes. Section 9 lists "timeout" among the limits and the threat
model row "A large or endless response exhausts memory" says "time ... limited". Memory is
bounded; time is not. The open risk "A denial of service against the engine by a slow tested
system" says "Timeouts and budgets limit it", which is only true per operation.

Reproduction. One sentence: a loopback server that sent the body one byte every 80 ms, with
`timeout_ms=100` (the minimum), returned a complete record with `error=None` after 3.29 s; a
raw socket server that sent the status line one byte every 80 ms returned after 3.12 s.

Recommendation. Add a per-request deadline (for example `timeout_ms * 4`, or a separate
`deadline_ms`). Check it between header read and body chunks, read the body in chunks with
`response.read(n)` in a loop, and return a new error code `deadline` when it is exceeded.

### F-06. A redirect to a non-ASCII path raises out of `fetch`

Severity: medium. Component: `src/dppce/infrastructure/transport.py`, lines 193 to 213 and 288 to 291.

Description. `http.client` decodes a `Location` header as Latin-1 and encodes the request line
as ASCII. A `Location: /dpp/ü` from an allowed host passes `_target`, and
`connection.request()` then raises `UnicodeEncodeError`. The `except` clauses catch
`TimeoutError`, `ssl.SSLError`, `HTTPException`, and `OSError` only, so the exception leaves
`fetch`. The contract says a transport failure "is never raised". The orchestrator turns it into
`ENGINE.CHECK_EXCEPTION`, an `error`, not a `fail`, so the verdict stays honest, but the run
ends in an execution error that a tested system can trigger at will.

Reproduction. One sentence: a loopback server answering `302` with `Location: /dpp/ü`
made `PolicyTransport.fetch` raise `UnicodeEncodeError: 'ascii' codec can't encode character
'\xfc'`.

Recommendation. Percent-encode the path and query of each hop with `urllib.parse.quote(...,
safe=...)` before the request, and catch `ValueError` in `_send` as a `protocol` error.

### F-07. A P-384 leaf certificate raises `OverflowError`

Severity: low. Component: `src/dppce/adapters/integrity.py` line 135; `src/dppce/evidence/jws.py` lines 127 to 134.

Description. `public_jwk_of` calls `numbers.x.to_bytes(32, "big")`. For a P-384 or P-521 leaf
the coordinate does not fit and `OverflowError` is raised. The check does not catch it. The
orchestrator records an `error`. That is honest, but a common certificate type aborts the step
with an engine exception instead of a documented `blocked` outcome.

Reproduction. One sentence: an `ES384` token with a P-384 leaf in `x5c` made `jws_check` raise
`OverflowError: int too big to convert`.

Recommendation. In `jws_check`, check `isinstance(leaf_key.curve, ec.SECP256R1)` and return
`blocked("INTEGRITY.KEY.UNSUPPORTED", ...)` otherwise.

### F-08. IXIT sample paths are confined at check time and read later

Severity: low. Component: `src/dppce/cli.py` lines 189 to 204 and 267 to 271;
`src/dppce/infrastructure/transport.py` lines 297 to 310.

Description. `_confined` resolves the path and checks containment once, when the run starts.
`PolicyTransport.artifact` reads the resolved path later with `stat()` and `read_bytes()`,
which follow symbolic links again. If a path component is replaced by a symbolic link between
the two, the read leaves the IXIT directory. This needs write access to the IXIT directory on
the test host during the run. The threat model row "The supplier's IXIT names a local file to
read" claims a symbolic link that leaves the directory is refused.

Reproduction. One sentence: after `_confined` returned a path inside the IXIT directory, the
script replaced the `samples` directory with a symbolic link to a temporary directory holding a
link to an outside file, and `transport.artifact("qr_image").body` returned `b'OUTSIDE'`
(deterministic swap, not a timed race).

Recommendation. Pass the confinement root into `TransportConfig`. In `artifact()`, resolve the
path again, refuse it if it is no longer inside the root, open it with
`os.open(path, os.O_RDONLY | os.O_NOFOLLOW)`, and compare `os.fstat(fd)` with `path.stat()`
(same device and inode) before reading from the descriptor.

### F-09. Purge deletes any directory with an expired clear-text index; retention comes from the IXIT

Severity: low. Component: `src/dppce/evidence/recording.py` lines 186 to 202; `src/dppce/cli.py` lines 288 to 294 and 465 to 471.

Description. `purge_expired` removes with `shutil.rmtree` every child directory of a run that
holds a `recording.json` whose `delete_after` is past. The index is clear text and has no
authentication. Any directory that contains a planted index is removed with all its content.
In addition `delete_after` is `created + IXIT.observation.retention_days`, and `retention_days`
accepts `0`. The supplier of the IXIT therefore decides when the evidence behind a report
becomes eligible for deletion. The index is also read with `json.loads`, not `parse_strict`.

Reproduction. One sentence: a directory `runs/my-notes` holding `important.txt` and a planted
expired `recording.json` was removed by `purge_expired(runs, date(2026, 10, 14))`, and
`important.txt` was gone.

Recommendation. Require `records/` to exist and require the index to validate against the data
key id before deletion. Let the operator set a minimum retention on the command line that
overrides a smaller IXIT value. Read the index with `parse_strict`.

### F-10. A sealed file shorter than the nonce raises `ValueError`

Severity: low. Component: `src/dppce/evidence/recording.py`, lines 174 to 178.

Description. `AESGCM.decrypt` is called with `sealed[:12]`. A file shorter than 12 bytes gives
`ValueError: Nonce must be between 8 and 128 bytes`, which is not in the `except` tuple. The
CLI reports it as `execution error` with exit 3 instead of an input error with exit 2.

Reproduction. One sentence: writing five zero bytes to `records/r0001.enc` and calling
`read_recording` raised `ValueError` instead of `RecordingError`.

Recommendation. Check `len(sealed) > 12 + 16` before decrypting and add `ValueError` to the
`except` tuple.

### F-11. The record identifier pattern admits a trailing newline

Severity: low. Component: `src/dppce/evidence/recording.py`, line 35.

Description. `re.compile(r"^r\d{4,6}$")` with `match` accepts `"r0001\n"` because `$` matches
before a final newline. The engine never produces such an identifier, and `\d` and `\n` cannot
form a path traversal, but two identifiers that print the same can coexist and sort as distinct.

Reproduction. One sentence: `_RECORD_ID.match("r0001\n")` returned a match.

Recommendation. Use `re.fullmatch` or `\Z`.

### F-12. Response headers are default-allow; `Link` is recorded unredacted

Severity: low. Component: `src/dppce/infrastructure/redaction.py`, lines 58 to 68.

Description. Only four response header names are removed. `Location` and `Content-Location`
are redacted as URLs, `Link` is kept verbatim, and every other header is kept. ADR 0012 says
secrets are removed "with a default-deny rule for header values"; that is true for request
headers only. A `Link` header with a token in a URL reaches the retained record.

Reproduction. One sentence: `redact_response_headers((("Link", "<http://h/?access_token=S3CRET>; rel=next"),))`
returned the header unchanged.

Recommendation. Redact each URL inside `Link` with `redact_url`, and extend the removed set with
`Proxy-Authenticate`, `Authentication-Info`, and any name that matches the sensitive-parameter
pattern. State the actual rule in ADR 0012.

### F-13. The verification JWK `kty` is not checked

Severity: info. Component: `src/dppce/evidence/jws.py`, lines 108 to 111.

Description. The JWK check tests the field set and `crv`, not `kty`. `ECKey.import_key` in
joserfc accepts `kty` of `oct`, `RSA`, or `OKP` with EC coordinates. The key comes from the
operator's trust bundle, so no untrusted party controls it. No algorithm confusion follows,
because the allowlist is fixed. It is a missing sanity check only.

Reproduction. One sentence: `verify_compact` verified the same token with `kty` set to `EC`,
`oct`, `RSA`, and `OKP`.

Recommendation. Add `public_jwk.get("kty") == "EC"` to the check.

### F-14. `--allow-remote-read` confirms every public host that the IXIT names at once

Severity: low. Component: `src/dppce/cli.py`, lines 527 to 531; `src/dppce/infrastructure/transport.py`, line 152.

Description. With no authorization, one flag permits bounded `GET` and `HEAD` to every public
host in `IXIT.network.allowed_hosts`, a list the supplier writes. The non-public list needs one
confirmation per host; the public list needs none. The confirmation for a private host is also
per host, not per origin, so every port on a confirmed host is reachable. Section 9.1 states
this design. It is reported because the asset "Other systems" in the threat model expects that
the engine is not pointed at a system that nobody named.

Reproduction. Not reproduced; the behavior follows from `cmd_run` and `_target`.

Recommendation. Make `--allow-remote-read HOST` take a host, repeatable, and require each public
host to be named, as `--allow-private-host` does.

### F-15. `report --trust` verifies at the current time when `--at` is absent

Severity: low. Component: `src/dppce/cli.py`, lines 362 to 376.

Description. Section 11.4 says verification needs an explicit evaluation time. `cmd_verify`
requires `--at`; `cmd_report --trust` calls `verify_json` with `_time(args.at)`, which defaults
to now. The rendered HTML then carries a verification section whose time was not chosen.

Reproduction. Not reproduced; the behavior follows from `_time(None)`.

Recommendation. Require `--at` when `--trust` is given to `report`.

### F-16. Name constraints and extended key usage are not enforced on the path

Severity: low. Component: `src/dppce/adapters/integrity.py`, lines 42 to 89.

Description. `trust_path` checks the signature, the issuer name, `BasicConstraints.ca`, the
path length, and `KeyUsage.key_cert_sign`. It does not apply `NameConstraints` of an issuer,
does not check `ExtendedKeyUsage`, and does not check the leaf's `digital_signature` usage. An
anchor whose certificate has `ca=False` can never validate a leaf, which is fail-closed.

Reproduction. Not reproduced; the code has no reference to those extensions.

Recommendation. Document the subset of RFC 5280 path validation that is implemented, or build
the path with `cryptography.x509.verification` and a policy that fits passport signing.

### F-17. Credential origin strings are built two ways and can disagree

Severity: info. Component: `src/dppce/cli.py` lines 233 to 235; `src/dppce/infrastructure/transport.py` lines 154 to 155.

Description. `cli._origin` returns `scheme://netloc` verbatim: case kept, brackets kept for an
IPv6 literal, an explicit default port kept. `transport._target` builds
`scheme://host[:port]` with a lowercased host, no brackets, and no default port. For
`http://[::1]:8080` or `https://Example.com:443` the two differ, the credential is silently not
sent, and F-03 applies.

Reproduction. Not reproduced; the two functions are quoted above.

Recommendation. Export one `origin_of(url)` from the transport and use it in `cmd_run`.

## What holds up

These claims were tested and held. They are listed so that the assessment is not read as
"everything is broken".

- Verifier: shortening, reordering, a flipped verdict, a changed overall outcome, a changed
  manifest, a changed coverage ratio, a float where an integer is expected, a re-signature by an
  untrusted key, a key trusted for authorizations only, a revoked key, a missing required status
  snapshot, a missing required timestamp, and an authorization token placed among the
  signatures each gave `complete=false`. A report-supplied key is never consulted.
- Signatures: the allowlist is fixed in code and also passed to joserfc; `crit`, `jwk`, `jku`,
  and `x5u` are rejected as unknown; `typ` separates attestation, authorization, and passport
  tokens; `TOO_LARGE` is reported as a limit, not as an invalid signature.
- Merkle tree and commitments: leaf, node, and empty hashes are domain separated and the two
  trees use different labels; keys must be strictly ascending; a single leaf and an empty tree
  have distinct roots; the salt is 32 random bytes and never leaves the encrypted record.
- Recording: AES-256-GCM with the record identifier as associated data; a record swapped between
  slots fails to authenticate; a record whose content differs from its commitment is refused.
- Authorization and transport: issuer trust, key purpose, validity, `sut_identifier`, and
  period are checked; `_target` runs for every redirect hop and `_budget_left` for every attempt;
  a write needs an active scope and the method must be listed; caller headers and credentials
  stay with the first origin; userinfo, other schemes, and a mixed public/private DNS answer are
  refused; NAT64, 6to4, Teredo, and IPv4-mapped forms are classified by the embedded address;
  the TLS host name check uses the URL host, not the pinned address (by code reading; no HTTPS
  loopback server was run).
- Untrusted input: the trust bundle comes only from `--trust`; a secret reference must be
  repeated by the operator and is limited to one prefix and one directory; `_confined` refuses
  `..`, absolute paths, and symbolic links at check time (by code reading and
  `test_an_ixit_path_cannot_leave_the_ixit_directory` in the existing suite, not re-run alone).
- The verifier's `_signatures` labels every `SignatureError`, including `TOO_LARGE` and
  `NOT_ALLOWED`, as "A signature does not verify". The outcome stays fail-closed; only the
  detail text conflates a limit with a bad signature, the same way F-01 does.

## Contract gaps

Claims in the contract or the threat model that the code does not meet.

1. Section 9 and threat model row 56: "time is limited". Only each socket operation is bounded (F-05).
2. Section 9 and `transport.py` docstring: a transport failure "is never raised". A non-ASCII
   redirect raises (F-06).
3. Threat model row 73 and ADR 0010: "A limit or a defect of the engine reads as a failure of
   the tested system" is listed as mitigated. F-01 and F-02 contradict it for `integrity.jws`.
4. ADR 0006: "JCS is the canonical form of the engine's own bodies only." `integrity.py`
   applies it to a third-party payload (F-02).
5. Section 8, row `access.restricted_fields`: "A role does not get fields that the declared
   policy withholds." The check does not establish that the role was authenticated (F-03).
6. Threat model row 70: "a partial look never passes". An encoded body passes (F-04).
7. ADR 0012: "a default-deny rule for header values". Response headers are default-allow (F-12).
8. Section 11.4, `counts`: "Verdict counts and coverage totals equal the recomputed ones." The
   `implementation` and `execution` ratios are only bounds-checked; they cannot be recomputed
   without the catalogue. Requirement verdicts are not re-derived from test results; only the
   overall outcome is recomputed from requirement results. The signature still binds all of
   them, so a change is detected, but an internally inconsistent signed report is accepted.
9. Section 11.4: verification "needs ... an explicit evaluation time". `report --trust` does
   not require it (F-15).
10. Section 9.1 and threat model row 59: a path "must stay inside the directory of the IXIT
    file". True at check time only (F-08).
11. Section 10: "`dppce purge` deletes recordings past that date." It deletes any directory
    with an expired index, and the date is set by the supplier's `retention_days` (F-09).
12. Threat model row 68: "Each issuer must be a certificate authority that can sign
    certificates, inside its path length." True, but name constraints and key usage of the leaf
    are not part of the check (F-16).

## Not reviewed

- `src/dppce/verdicts/aggregate.py` and `coverage.py`. The verifier depends on
  `overall_verdict`; its precedence was not re-derived here.
- `src/dppce/catalogue/` (YAML loading, approval records, pack hashing), `src/dppce/report/html.py`
  (escaping), `src/dppce/orchestrator/plan.py` (scope gating of steps), `src/dppce/models/`.
- Adapters other than `integrity.py` and `access.py`: `api.py`, `data.py`, `identifier.py`,
  `carrier.py`, `lifecycle.py`, `capabilities.py`, and the shared helpers in `common.py`
  beyond what the two reviewed adapters call.
- `src/dppce/infrastructure/reference_server.py` and `clock.py`.
- TLS against a real certificate: no HTTPS loopback server was run. DNS rebinding with the
  system resolver: the existing tests use a fake resolver, and no live rebinding was attempted.
- A timed race for F-08. The reproduction swapped the path between check and use deterministically.
- The internals of `joserfc`, `cryptography`, `rfc8785`, and `pydantic`.
- The CI workflows, the container build, dependency vulnerabilities, and `tests/core/`
  (another task is writing it).
- Validation records other than this one, and the full method validation (`just validate`).

## Commands run

| Command | Result |
| --- | --- |
| `git rev-parse HEAD` | `d53170c55eedbfce981ebd5071fab7352c7fd24f` |
| `uv run python - < repro_integrity.py` | exit 0; output quoted under F-01, F-02, F-07 |
| `uv run python - < repro_access.py` | exit 0; output quoted under F-03, F-04 |
| `uv run python - < repro_transport.py` | exit 0; output quoted under F-05, F-06 |
| `uv run python - < repro_misc.py` | exit 0; output quoted under F-08 to F-11 and "What holds up" |
| `uv run python - <<'EOF' ...` (address classes, JWK `kty`, redaction) | exit 0; output quoted under F-12, F-13 |
| `uv run pytest -m "not validation" --ignore=tests/core -q` | four progress lines of dots, no `F` or `E` marker; 287 dots counted; exit status not captured (shell variable name) |
| `uv run pytest -m "not validation" --ignore=tests/core --collect-only -q` | exit 0; per-file counts sum to 287, which matches the dot count (includes the untracked `tests/test_catalogue_content.py` that another task is writing) |

Not run: `uv run just check`, `uv run just validate`, `uv run mypy`, `uv run ruff`.

## Overall assessment

This record makes no claim that the engine is secure.

The evidence chain (canonical form, Merkle roots, salted commitments, encrypted records, one
signing profile, a standalone verifier with an operator-supplied trust bundle) resisted every
tampering case that was tried. The transport refuses the request-forgery and rebinding cases
that the tests name, and its authorization checks run on every hop and attempt.

The weak area is the honesty of outcomes in the two reviewed adapters. `integrity.jws` turns
several limits of this engine into a `fail` of the tested system (F-01, F-02). The access check
can report enforcement for a role that was never authenticated (F-03) and can be blinded by a
body encoding (F-04). F-01 to F-03 should be fixed before any result of these two checks is
cited, in any mode. The transport time bound (F-05) and the redirect exception (F-06) are
robustness defects that a hostile tested system can trigger.

A human maintainer must decide each item. An agent review is not an approval, and it is not
the independent security audit that the threat model lists as open.
