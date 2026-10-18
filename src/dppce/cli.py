"""Command-line entry point.

Exit codes (docs/explanation/architecture.md, section 12):
0 completed (run, replay: overall pass); 1 the system under test failed; 2 usage or input error;
3 execution error; 4 evidence verification failed or replay digest mismatch; 5 inconclusive.
Every command accepts ``--json`` and then writes one JSON document to standard output.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, get_args
from urllib.parse import urlsplit

from pydantic import ValidationError

from dppce import __version__
from dppce.adapters.access import ACCESS_CHECK, policy_roles
from dppce.adapters.capabilities import manifest as capability_manifest
from dppce.applicability import ApplicabilityError
from dppce.catalogue import (
    Catalogue,
    CatalogueError,
    check_ics,
    load_catalogue,
    load_ics,
    load_ixit,
    load_profiles,
    load_testpacks,
)
from dppce.catalogue.lint import lint, trace
from dppce.evidence import disclosure
from dppce.evidence import status as status_lists
from dppce.evidence.canonical import CanonicalizationError, canonical_bytes, is_exact, parse_strict
from dppce.evidence.envelope import decision_digest, in_layout_of, sign_envelope
from dppce.evidence.jws import SignatureError, header_of, public_jwk_from
from dppce.evidence.manual import (
    MANUAL_CHECK,
    SAMPLE_PREFIX,
    ManualResultError,
    claimed_test_purpose,
    test_purpose_digest,
)
from dppce.evidence.recording import RecordingError, purge_expired, read_recording, write_recording
from dppce.evidence.timestamp import (
    MAX_TOKEN_BYTES,
    MAX_TOKENS,
    TimestampError,
    format_time,
    imprint_hex,
    imprint_of,
    parse_token,
    token_from_response,
)
from dppce.evidence.timestamp import SHA256 as TIMESTAMP_SHA256
from dppce.infrastructure.authorization import AuthorizationError, issue_authorization, validate_authorization
from dppce.infrastructure.clock import STAMP_FORMAT, SystemClock, parse_stamp, utc_stamp
from dppce.infrastructure.keys import (
    FileDataKeyProvider,
    KeyError_,
    generate_signing_key,
    load_signing_key,
    resolve_secret,
    write_new_file,
)
from dppce.infrastructure.replay import ReplayAcquirer
from dppce.infrastructure.resources import data_root
from dppce.infrastructure.transport import (
    ANONYMOUS,
    MIN_SECRET_LENGTH,
    PolicyTransport,
    TransportConfig,
    origin_of,
)
from dppce.migrations import MigrationError, migrate
from dppce.models import (
    ICS,
    IXIT,
    NOT_ACCREDITED,
    Authorization,
    EvidenceEnvelope,
    ExecutionMode,
    InputHashes,
    IssuerStatement,
    Profile,
    RunInputsRecord,
    StatusReference,
    TestPack,
    TrustBundle,
    TrustedKey,
    Verdict,
)
from dppce.orchestrator.plan import PlanError
from dppce.orchestrator.run import RunInputs, bound_files, evaluate, input_hashes, make_plan
from dppce.report import render
from dppce.testdefs import registry
from dppce.verifier import verify_json
from dppce.verifier.verify import body_dimensions

EXIT_OK: Final = 0
EXIT_SUT_FAIL: Final = 1
EXIT_USAGE: Final = 2
EXIT_ERROR: Final = 3
EXIT_VERIFY: Final = 4
EXIT_INCONCLUSIVE: Final = 5

_VERDICT_EXIT: Final = {
    Verdict.PASS: EXIT_OK,
    Verdict.FAIL: EXIT_SUT_FAIL,
    Verdict.ERROR: EXIT_ERROR,
    Verdict.INCONCLUSIVE: EXIT_INCONCLUSIVE,
    Verdict.NOT_APPLICABLE: EXIT_INCONCLUSIVE,
}
_INPUT_ERRORS: Final = (
    # A comparison of two different types is a defect of the catalogue or of the ICS (section 5).
    ApplicabilityError,
    CatalogueError,
    PlanError,
    KeyError_,
    AuthorizationError,
    RecordingError,
    SignatureError,
    CanonicalizationError,
    ValidationError,
    OSError,
)


_STATUS_LIST_HELP: Final = "signed status list file of the report issuer; nothing is fetched"


class UsageError(ValueError):
    """The arguments or the input files cannot be used."""


def _emit(args: argparse.Namespace, document: Any, text: str) -> None:
    print(json.dumps(document, indent=2, sort_keys=True) if args.json else text)


def _now() -> datetime:
    return SystemClock().now().replace(microsecond=0)


def _time(text: str | None) -> datetime:
    if text is None:
        return _now()
    try:
        return datetime.strptime(text, STAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError as exc:
        raise UsageError(f"'{text}' is not a time such as 2026-10-13T12:00:00Z") from exc


def _trust(path: Path | None) -> TrustBundle | None:
    """Load a trust bundle. A ``dppce.trust/1`` bundle is migrated (architecture section 11.4)."""
    if path is None:
        return None
    document = parse_strict(path.read_bytes())
    if not isinstance(document, dict):
        raise UsageError(f"TRUST.BUNDLE.NOT_OBJECT: {path} is not a JSON object")
    try:
        return TrustBundle.model_validate(migrate("trust", document))
    except MigrationError as exc:
        raise UsageError(f"{path}: {exc}") from exc
    except ValidationError as exc:
        # The first message carries the reason code, for example TRUST.KEY.ROLE_CONFLICT.
        raise UsageError(f"{_first_message(exc)} ({path})") from exc


def _first_message(exc: ValidationError) -> str:
    return str(exc.errors()[0]["msg"]).removeprefix("Value error, ")


def _read_capped(path: Path | None, limit: int) -> bytes | None:
    """Read a file for the verifier. One byte over the limit is enough for the verifier to refuse it."""
    if path is None:
        return None
    with path.open("rb") as handle:
        return handle.read(limit + 1)


def _checked_envelope(path: Path) -> EvidenceEnvelope:
    """Read an envelope whose body passes the checks that need no trust (section 11.4)."""
    try:
        document = parse_strict(path.read_bytes())
    except CanonicalizationError as exc:
        # The verifier gives such a file `structure` fail, so the command names the same dimension.
        raise UsageError("ENVELOPE.BODY.INVALID: the envelope fails these checks: structure") from exc
    envelope, dimensions = body_dimensions(document)
    failed = [name for name, (outcome, _) in dimensions.items() if outcome == "fail"]
    if envelope is None or failed:
        raise UsageError(f"ENVELOPE.BODY.INVALID: the envelope fails these checks: {', '.join(failed)}")
    return envelope


def _new_path(path: Path, code: str) -> None:
    """Refuse an output path that exists. ``code`` is the literal reason code of the command."""
    if path.exists() or path.is_symlink():
        raise UsageError(f"{code}: {path} exists; --out names a new file")


def _passphrase(args: argparse.Namespace) -> str | None:
    """Resolve the passphrase reference. A message never holds the passphrase."""
    if args.passphrase_ref is None:
        return None
    return resolve_secret(args.passphrase_ref, secrets_dir=args.secrets)


def _replace(path: Path, data: bytes) -> None:
    """Replace ``path`` through a temporary file in its directory. The file keeps its mode."""
    mode = stat.S_IMODE(path.stat().st_mode)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".dppce-sign-")
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    except BaseException:
        # The input stays as it was. Only the temporary file is removed.
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


@dataclass(frozen=True)
class LoadedInputs:
    """The data that a run reads from the data root and the imported files, before any check."""

    root: Path
    profile: Profile
    catalogue: Catalogue
    testpacks: dict[str, TestPack]


def _load_inputs(
    *,
    root: Path,
    profile_id: str,
    extra_packs: Sequence[str],
    extra_testpacks: Sequence[str],
    import_packs: Sequence[Path],
    import_testpacks: Sequence[Path],
) -> LoadedInputs:
    profiles = load_profiles(root)
    if profile_id not in profiles:
        raise UsageError(f"profile '{profile_id}' is not found; available: {', '.join(sorted(profiles))}")
    profile = profiles[profile_id]
    if extra_packs:
        profile = profile.model_copy(update={"packs": (*profile.packs, *extra_packs)})
    if extra_testpacks:
        profile = profile.model_copy(update={"testpacks": (*profile.testpacks, *extra_testpacks)})
    return LoadedInputs(
        root=root,
        profile=profile,
        catalogue=load_catalogue(root, extra_packs=import_packs),
        testpacks=load_testpacks(root, extra_testpacks=import_testpacks),
    )


def _build_inputs(
    *,
    loaded: LoadedInputs,
    mode: ExecutionMode,
    ics: ICS,
    ixit: IXIT,
    evaluation_time: datetime,
    trust: TrustBundle | None,
    authorization_token: str | None,
    issuer: IssuerStatement,
    manual_results: frozenset[str] = frozenset(),
) -> RunInputs:
    profile, testpacks = loaded.profile, loaded.testpacks
    problems = check_ics(ics, profile)
    if problems:
        raise UsageError("the ICS does not fit the profile: " + " ".join(problems))
    if manual_results and trust is None:
        raise UsageError("a manual result needs a trust bundle that names the key of its performer")
    authorization = None
    if authorization_token is not None:
        if trust is None:
            raise UsageError("an authorization needs a trust bundle that names its issuer")
        authorization = validate_authorization(
            authorization_token, trust, evaluation_time, ics.sut.identifier
        )
    if undeclared := _undeclared_roles(loaded.root, profile, ixit, authorization, testpacks):
        raise UsageError(
            f"profile '{profile.id}' does not declare a role that the inputs name: " + " ".join(undeclared)
        )
    manual_steps = {
        p.id
        for name in profile.testpacks
        if name in testpacks
        for p in testpacks[name].test_purposes
        if p.manual and p.stimulus.check == MANUAL_CHECK
    }
    if unknown := sorted(manual_results - manual_steps):
        raise UsageError(
            "a manual result names a test purpose that is not a manual step with the check "
            f"{MANUAL_CHECK} in the selected test packs: {', '.join(unknown)}"
        )
    inputs = RunInputs(
        mode=mode,
        profile=profile,
        catalogue=loaded.catalogue,
        testpacks=testpacks,
        ics=ics,
        ixit=ixit,
        data_root=loaded.root,
        evaluation_time=evaluation_time,
        trust=trust,
        authorization=authorization,
        issuer=issuer,
        manual_results=manual_results,
    )
    if manual_results:
        _refuse_unused_manual_results(inputs)
    return inputs


def _undeclared_roles(
    root: Path,
    profile: Profile,
    ixit: IXIT,
    authorization: Authorization | None,
    testpacks: dict[str, TestPack],
) -> list[str]:
    """Each role that an input names and the profile does not declare, with its source.

    The IXIT and the authorization are untrusted text: ``repr`` makes a control character visible.
    """
    sources: dict[str, set[str]] = {
        "the access policy": set(policy_roles(root, profile)),
        "the IXIT": {i.role for i in ixit.identities},
        "the authorization": set(authorization.roles if authorization else ()),
    }
    for name in profile.testpacks:
        for purpose in testpacks[name].test_purposes if name in testpacks else ():
            named = set(purpose.roles)
            role = purpose.stimulus.params.get("role")
            if purpose.stimulus.check == ACCESS_CHECK and isinstance(role, str):
                named.add(role)
            sources[f"test purpose {purpose.id}"] = named
    return [
        f"{source} names the role {role!r}."
        for source, roles in sources.items()
        for role in sorted(roles - set(profile.roles))
    ]


def _refuse_unused_manual_results(inputs: RunInputs) -> None:
    """A supplied manual result must belong to a step that the plan executes. None is ignored silently."""
    plan = make_plan(inputs)
    steps = {s.test_purpose_id: s for s in plan.steps}
    exclusions = {e.id: e for e in plan.exclusions if e.kind == "test_purpose"}
    reasons = []
    for ident in sorted(inputs.manual_results):
        step, exclusion = steps.get(ident), exclusions.get(ident)
        if exclusion is not None:
            reasons.append(f"{ident}: excluded, {exclusion.reason_code}: {exclusion.reason}")
        elif step is None:
            reasons.append(f"{ident}: no selected requirement names it")
        elif step.planned_status is not None:
            reasons.append(f"{ident}: {step.planned_status.value}: {step.planned_reason}")
    if reasons:
        raise UsageError("a manual result names a step that the plan does not execute: " + "; ".join(reasons))


def _manual_results(paths: list[Path]) -> dict[str, Path]:
    """Map each supplied manual result to the test purpose that it names. Nothing is verified here."""
    found: dict[str, Path] = {}
    for path in paths:
        try:
            named = claimed_test_purpose(path.read_text(encoding="ascii").strip())
        except (OSError, UnicodeDecodeError, ManualResultError) as exc:
            raise UsageError(f"{path}: not a manual result that names a test purpose") from exc
        if named in found:
            raise UsageError(f"more than one manual result names the test purpose {named}")
        found[named] = path
    return found


def _inputs_from_args(
    args: argparse.Namespace,
) -> tuple[RunInputs, str | None, TrustBundle | None, dict[str, Path]]:
    ixit = load_ixit(args.ixit)
    reserved = sorted(name for name in ixit.samples if name.startswith(SAMPLE_PREFIX))
    if reserved:
        # Only the operator supplies a manual result. The IXIT cannot supply or select one.
        raise UsageError(
            f"the IXIT names samples in the reserved namespace '{SAMPLE_PREFIX}': {', '.join(reserved)}"
        )
    manual = _manual_results(args.manual_result)
    base = args.ixit.resolve().parent
    # Trust comes from the operator only. A trust bundle that the IXIT names is never loaded:
    # the supplier of the system under test could otherwise name its own key as trusted.
    trust = _trust(args.trust)
    token_path = getattr(args, "authorization", None) or (
        _confined(base, ixit.authorization_ref, "authorization_ref") if ixit.authorization_ref else None
    )
    token = token_path.read_text(encoding="ascii").strip() if token_path else None
    if args.accreditation_status != NOT_ACCREDITED and not args.accreditation_reference.strip():
        raise UsageError(
            "ISSUER.ACCREDITATION.NO_REFERENCE: an accreditation status other than "
            f"'{NOT_ACCREDITED}' needs --accreditation-reference"
        )
    issuer = IssuerStatement(
        name=args.issuer_name,
        identifier=args.issuer_id,
        accreditation_status=args.accreditation_status,
        accreditation_reference=args.accreditation_reference,
    )
    loaded = _load_inputs(
        root=data_root(args.data_root),
        profile_id=args.profile,
        extra_packs=args.pack,
        extra_testpacks=args.testpack,
        import_packs=args.import_pack,
        import_testpacks=args.import_testpack,
    )
    inputs = _build_inputs(
        loaded=loaded,
        mode=ExecutionMode(args.mode),
        ics=load_ics(args.ics),
        ixit=ixit,
        evaluation_time=_time(args.at),
        trust=trust,
        authorization_token=token,
        issuer=issuer,
        manual_results=frozenset(manual),
    )
    return inputs, token, trust, manual


def _confined(base: Path, value: str, what: str) -> Path | None:
    """Resolve an IXIT-relative path. It must stay inside the directory of the IXIT file.

    The IXIT can come from the supplier of the system under test. It must not make the engine
    read a file elsewhere on the host. Returns None if the value does not name an existing file.
    """
    root = base.resolve()
    try:
        path = (root / value).resolve()
    except (OSError, ValueError):
        return None
    if not path.is_file():
        return None
    if not path.is_relative_to(root):
        raise UsageError(f"{what} points outside the directory of the IXIT file")
    return path


def _credentials(args: argparse.Namespace, ixit: IXIT, origin: str) -> dict[str, tuple[str, str]]:
    """Resolve the role secrets that the operator confirmed for this run.

    The IXIT declares a reference. The operator must repeat exactly that reference with
    ``--role-secret ROLE=REFERENCE``. An IXIT alone can therefore never select a secret, for
    example one that belongs to a different system that the same laboratory tests.
    """
    confirmed: dict[str, str] = {}
    for item in args.role_secret:
        role, separator, reference = item.partition("=")
        if not separator or not role or not reference:
            raise UsageError(f"'{item}' is not ROLE=REFERENCE")
        confirmed[role] = reference
    credentials: dict[str, tuple[str, str]] = {}
    for identity in ixit.identities:
        if identity.secret_ref is None:
            continue
        if identity.role == ANONYMOUS:
            raise UsageError(
                "the IXIT names a secret for the role 'anonymous'; the anonymous role has no credential"
            )
        if confirmed.get(identity.role) != identity.secret_ref:
            raise UsageError(
                f"the IXIT names a secret for role '{identity.role}'; confirm it with "
                f"--role-secret {identity.role}=<the same reference>"
            )
        secret = resolve_secret(identity.secret_ref, secrets_dir=args.secrets)
        if len(secret) < MIN_SECRET_LENGTH:
            raise UsageError(
                f"the secret of role '{identity.role}' is shorter than {MIN_SECRET_LENGTH} characters; "
                "a short secret cannot be kept out of the recording reliably"
            )
        credentials[identity.role] = (origin, secret)
    return credentials


def _confirmed_origins(values: list[str], flag: str) -> frozenset[str]:
    """Parse the origins that the operator confirmed. A bare host would confirm every port of it."""
    # The value is not shown: its userinfo can hold a password.
    refusal = (
        f"{flag} takes an origin such as http://127.0.0.1:8765, without userinfo, a query, a fragment, "
        "a space, or a control character"
    )
    origins = set()
    for value in values:
        try:
            parts = urlsplit(value)
            origin = origin_of(value)
        except ValueError as exc:
            raise UsageError(refusal) from exc
        # An origin has no userinfo, query, or fragment. urlsplit drops an empty "?" or "#", drops tab,
        # CR, and LF, and strips edge controls and spaces, so test the text, as the transport does.
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.path not in ("", "/")
            # No service listens on port 0, so no operator confirms it.
            or parts.port == 0
            or any(mark in value for mark in "@?#")
            or any(c <= " " or c == "\x7f" for c in value)
        ):
            raise UsageError(refusal)
        origins.add(origin)
    return frozenset(origins)


def cmd_plan(args: argparse.Namespace) -> int:
    inputs, _, _, _ = _inputs_from_args(args)
    plan = make_plan(inputs)
    executed = sum(1 for s in plan.steps if s.planned_status is None)
    text = (
        f"profile {plan.profile_id}, mode {plan.mode.value}: {len(plan.requirements)} requirements planned, "
        f"{executed} of {len(plan.steps)} steps to execute, {len(plan.exclusions)} exclusions, "
        f"{len(plan.conflicts)} conflicts"
    )
    _emit(args, plan.model_dump(mode="json", by_alias=True), text)
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    inputs, token, trust, manual = _inputs_from_args(args)
    out: Path = args.out
    if out.exists() and any(out.iterdir()):
        raise UsageError(f"{out} is not empty; a run never overwrites an earlier run")
    ixit, base = inputs.ixit, args.ixit.resolve().parent
    if args.retention_days is not None and not 0 <= args.retention_days <= 3650:
        raise UsageError("--retention-days must be from 0 to 3650")
    private = _confirmed_origins(args.allow_private_host, "--allow-private-host")
    remote = _confirmed_origins(args.allow_remote_host, "--allow-remote-host")
    confirmed_hosts = {urlsplit(origin).hostname for origin in private}
    unconfirmed = sorted({h.lower() for h in ixit.network.allow_private_hosts} - confirmed_hosts)
    if unconfirmed:
        raise UsageError(
            "the IXIT asks for non-public hosts; confirm the origin of each with --allow-private-host: "
            + ", ".join(unconfirmed)
        )
    # A role credential goes only to an origin that a validated authorization names.
    try:
        target = origin_of(ixit.endpoints.get("origin_override") or ixit.endpoints.get("api", ""))
    except ValueError as exc:
        raise UsageError(f"the API endpoint of the IXIT is not a URL: {exc}") from exc
    authorized = set()
    for endpoint in inputs.authorization.endpoints if inputs.authorization else ():
        with contextlib.suppress(ValueError):
            authorized.add(origin_of(endpoint))
    credentials = _credentials(args, ixit, target)
    if credentials and target not in authorized:
        raise UsageError(
            f"the IXIT names role secrets, but no valid authorization names the origin {target}; "
            "a role credential is sent only to an origin that the owner authorized"
        )
    samples = {
        name: path
        for name, value in ixit.samples.items()
        if (path := _confined(base, value, f"sample '{name}'")) is not None
    }
    # The transport pins each file as it pins any sample. The check reads it as an artifact.
    samples |= {SAMPLE_PREFIX + ident: path.resolve() for ident, path in manual.items()}
    try:
        # Checked before the first request: a run whose recording cannot be written sends nothing.
        keys = FileDataKeyProvider(args.keys, args.data_key_id)
        if args.create_data_key:
            keys.create()
        keys.data_key(args.data_key_id)
    except (KeyError_, OSError) as exc:
        hint = (
            "--create-data-key could not create it and never replaces an existing key file"
            if args.create_data_key
            else "create it with --create-data-key, or name an existing key with --data-key-id"
        )
        raise UsageError(
            f"KEYS.DATA_KEY.UNAVAILABLE: data key {args.data_key_id!r} is not available in {args.keys}; "
            + hint
        ) from exc
    transport = PolicyTransport(
        TransportConfig(
            policy=ixit.network,
            engine_version=__version__,
            credentials=credentials,
            authorization=inputs.authorization,
            remote_read_origins=remote,
            private_origins=private,
            samples=samples,
        ),
        SystemClock(),
    )
    decision = evaluate(inputs, transport)
    envelope = EvidenceEnvelope(schema_version="dppce.envelope/1", decision=decision)
    out.mkdir(parents=True, exist_ok=True)
    write_recording(
        out / "recording",
        transport.records(),
        keys,
        created=inputs.evaluation_time.date(),
        # The IXIT asks for a retention period. The operator decides it.
        retention_days=ixit.observation.retention_days
        if args.retention_days is None
        else args.retention_days,
    )
    bound = decision.manifest.bound_files
    if bound is None:  # a new run writes dppce.decision/2, which always holds bound_files
        raise RuntimeError("the decision body of a new run has no bound_files")
    record = RunInputsRecord(
        schema_version="dppce.runinputs/3",
        mode=inputs.mode,
        profile=args.profile,
        evaluation_time=utc_stamp(inputs.evaluation_time),
        ics=inputs.ics,
        ixit=ixit,
        import_packs=tuple(str(p.resolve()) for p in args.import_pack),
        extra_packs=tuple(args.pack),
        import_testpacks=tuple(str(p.resolve()) for p in args.import_testpack),
        extra_testpacks=tuple(args.testpack),
        trust=trust,
        authorization_token=token,
        issuer=inputs.issuer,
        # The test purposes only. The signed results are in the encrypted recording.
        manual_results=tuple(sorted(inputs.manual_results)),
        data_root=str(inputs.data_root.resolve()),
        # The models that the run used and the bound-file values of the manifest: no file is read twice.
        input_hashes=input_hashes(inputs.profile, inputs.catalogue, inputs.testpacks, bound),
    )
    (out / "inputs.json").write_bytes(canonical_bytes(record) + b"\n")
    (out / "envelope.json").write_text(envelope.model_dump_json(by_alias=True) + "\n", encoding="utf-8")
    (out / "report.html").write_text(render(envelope), encoding="utf-8")
    digest = decision_digest(decision)
    summary = {"overall": decision.overall.value, "decision_digest": digest, "run": str(out)}
    _emit(
        args,
        summary,
        f"overall {decision.overall.value}: {decision.overall_reason}\ndigest {digest}\nrun {out}",
    )
    return _VERDICT_EXIT[decision.overall]


def cmd_replay(args: argparse.Namespace) -> int:
    if args.times < 1:
        # Zero replays would report "match" for an evaluation that never took place.
        raise UsageError("--times must be 1 or more")
    run: Path = args.run
    record = _run_inputs_record(run / "inputs.json")
    original = EvidenceEnvelope.model_validate(parse_strict((run / "envelope.json").read_bytes()))
    records = read_recording(run / "recording", FileDataKeyProvider(args.keys))
    if args.data_root is not None:
        root = data_root(args.data_root)
    elif record.data_root is not None:
        root = Path(record.data_root)
        if not root.is_dir():
            raise UsageError(
                f"REPLAY.DATA_ROOT.MISSING: the run recorded the data root {root}, which is not a "
                "directory; give the data root with --data-root"
            )
    else:
        root = data_root(None)
    loaded = _load_inputs(
        root=root,
        profile_id=record.profile,
        extra_packs=record.extra_packs,
        extra_testpacks=record.extra_testpacks,
        import_packs=[Path(p) for p in record.import_packs],
        import_testpacks=[Path(p) for p in record.import_testpacks],
    )
    # The input check runs before the ICS, the authorization, or the manual results are checked.
    input_check = "not_run"
    if record.input_hashes is not None:
        now = input_hashes(
            loaded.profile, loaded.catalogue, loaded.testpacks, bound_files(loaded.profile, root)
        )
        if changed := _changed_inputs(record.input_hashes, now):
            raise UsageError(
                f"REPLAY.INPUT.CHANGED: these inputs differ from the run: {', '.join(changed)}; "
                f"data root {root}"
            )
        input_check = "pass"
    inputs = _build_inputs(
        loaded=loaded,
        mode=record.mode,
        ics=record.ics,
        ixit=record.ixit,
        evaluation_time=parse_stamp(record.evaluation_time),
        trust=record.trust,
        authorization_token=record.authorization_token,
        issuer=record.issuer,
        manual_results=frozenset(record.manual_results),
    )
    expected = decision_digest(original.decision)
    digests: list[str] = []
    complete = True
    overall = original.decision.overall
    for _ in range(args.times):
        acquirer = ReplayAcquirer(records)
        decision = evaluate(inputs, acquirer)
        digests.append(decision_digest(in_layout_of(decision, original.decision.schema_version)))
        complete = complete and acquirer.complete()
        overall = decision.overall
    match = complete and all(d == expected for d in digests)
    summary = {
        "expected_digest": expected,
        "replay_digests": digests,
        "match": match,
        "every_record_replayed": complete,
        "overall": overall.value,
        "data_root": str(root),
        "input_check": input_check,
    }
    state = "match" if match else "MISMATCH"
    checked = (
        f"inputs: compared with the run (data root {root})"
        if input_check == "pass"
        else "inputs: not compared: REPLAY.INPUT.NOT_RECORDED: the record holds no input hashes"
    )
    text = f"{checked}\n{args.times} replays: {state}\nexpected {expected}\noverall {overall.value}"
    _emit(args, summary, text)
    return _VERDICT_EXIT[overall] if match else EXIT_VERIFY


def _run_inputs_record(path: Path) -> RunInputsRecord:
    """Read inputs.json. A version 1 record is migrated. A damaged file is an input error."""
    try:
        document = parse_strict(path.read_bytes())
        if not isinstance(document, dict):
            raise MigrationError("the document is not a JSON object")
        return RunInputsRecord.model_validate(migrate("runinputs", document))
    except (MigrationError, ValidationError, CanonicalizationError) as exc:
        first = str(exc).splitlines()[0]
        raise UsageError(f"{path} is not a valid record of run inputs: {first}") from exc


def _labelled(hashes: InputHashes) -> dict[str, str]:
    return {
        "profile": hashes.profile,
        "source catalogue": hashes.sources,
        **{f"requirement pack {name}": value for name, value in hashes.packs.items()},
        **{f"test pack {name}": value for name, value in hashes.testpacks.items()},
        **{f"bound file {path}": value for path, value in hashes.bound_files.items()},
    }


def _changed_inputs(recorded: InputHashes, current: InputHashes) -> list[str]:
    """Each input whose digest differs, or that exists on one side only."""
    before, after = _labelled(recorded), _labelled(current)
    return sorted(label for label in before.keys() | after.keys() if before.get(label) != after.get(label))


def cmd_report(args: argparse.Namespace) -> int:
    raw = args.envelope.read_bytes()
    envelope = EvidenceEnvelope.model_validate(parse_strict(raw))
    if args.status_list is not None and (args.trust is None or args.at is None):
        raise UsageError("STATUSLIST.FILE.OPTION: a status list needs --trust and --at")
    if args.format == "json":
        text = envelope.model_dump_json(by_alias=True, indent=2) + "\n"
    else:
        trust = _trust(args.trust)
        if trust is not None and args.at is None:
            # Verification needs an explicit evaluation time. "Now" is never assumed.
            raise UsageError("a report with a verification section needs an explicit time: --at")
        verification = (
            verify_json(
                raw,
                trust,
                _time(args.at),
                status_list=_read_capped(args.status_list, status_lists.MAX_TOKEN_BYTES),
            )
            if trust
            else None
        )
        text = render(envelope, verification)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        _emit(args, {"written": str(args.out)}, f"wrote {args.out}")
    else:
        sys.stdout.write(text)
    return EXIT_OK


def cmd_sign(args: argparse.Namespace) -> int:
    source: Path = args.envelope
    if args.in_place and source.is_symlink():
        # os.replace would put a regular file in place of the link.
        raise UsageError(f"SIGN.INPUT.LINK: {source} is a symbolic link; sign the target file, or use --out")
    envelope = _checked_envelope(source)
    if args.out is not None:
        if args.out.resolve() == source.resolve():
            raise UsageError(
                "SIGN.OUTPUT.IS_INPUT: --out names the input envelope; use --in-place to replace it"
            )
        _new_path(args.out, "SIGN.OUTPUT.EXISTS")
    signer = load_signing_key(
        args.key, args.kid, _passphrase(args), allow_unencrypted=args.allow_unencrypted_key
    )
    if (args.status_list_id is None) != (args.status_index is None):
        raise UsageError("SIGN.OPTION.INVALID: --status-list-id and --status-index go together")
    try:
        entry = (
            None
            if args.status_list_id is None
            else StatusReference(list_id=args.status_list_id, index=args.status_index)
        )
        signed = sign_envelope(
            envelope,
            signer,
            issuer=args.issuer,
            signed_at=utc_stamp(_now()),
            role=args.role,
            status=entry,
            valid_until=args.valid_until,
            supersedes=args.supersedes,
        )
    except ValidationError as exc:
        raise UsageError(f"SIGN.OPTION.INVALID: {_first_message(exc)}") from exc
    data = (signed.model_dump_json(by_alias=True) + "\n").encode("utf-8")
    out: Path = source if args.in_place else args.out
    if args.in_place:
        _replace(source, data)
    else:
        write_new_file(out, data)
    summary = {"written": str(out), "signatures": len(signed.signatures), "kid": args.kid, "role": args.role}
    _emit(args, summary, f"signed with key '{args.kid}'; wrote {out}")
    return EXIT_OK


def cmd_keys_generate(args: argparse.Namespace) -> int:
    """Write a new encrypted P-256 key file and print its public JWK (section 11.3)."""
    passphrase = resolve_secret(args.passphrase_ref, secrets_dir=args.secrets)
    jwk = generate_signing_key(args.out, passphrase)
    if args.json:
        _emit(args, {"written": str(args.out), "public_jwk": jwk}, "")
    else:
        # Standard output holds the JWK only, so that the operator can redirect it to a file.
        print(json.dumps(jwk, sort_keys=True))
        print(
            f"wrote {args.out}: a P-256 private key, encrypted with the passphrase; mode 0600",
            file=sys.stderr,
        )
    return EXIT_OK


def cmd_authorize(args: argparse.Namespace) -> int:
    """Sign a dppce.authorization/1 document with the key of the system owner (section 11.3)."""
    invalid = "AUTHORIZE.DOCUMENT.INVALID"
    try:
        document = parse_strict(args.document.read_bytes())
        if not isinstance(document, dict):
            raise UsageError(f"{invalid}: the document is not a JSON object")
        authorization = Authorization.model_validate(document)
    except CanonicalizationError as exc:
        raise UsageError(f"{invalid}: the document is not strict JSON") from exc
    except ValidationError as exc:
        # The model refuses a stamp that is not canonical or names no real moment. Section 11.3
        # gives that its own code when the period is the only fault. A non-string stays a document fault.
        if all(
            error["loc"][:1] in (("not_before",), ("not_after",))
            and error["type"] in ("string_pattern_mismatch", "value_error")
            for error in exc.errors()
        ):
            raise UsageError(
                "AUTHORIZE.PERIOD.INVALID: not_before and not_after must be times such as "
                "2026-10-13T12:00:00Z"
            ) from exc
        raise UsageError(f"{invalid}: {_first_message(exc)}") from exc
    if not is_exact(document, authorization):
        # The owner signs what the owner wrote. A coerced value, such as "10" for 10, is refused.
        raise UsageError(
            f"{invalid}: the document is not in the exact canonical form of the schema "
            "(a field is missing, a type differs, or a number is not an integer)"
        )
    start, end = (parse_stamp(value) for value in (authorization.not_before, authorization.not_after))
    if start > end:
        raise UsageError("AUTHORIZE.PERIOD.INVALID: not_before is after not_after")
    try:
        _confirmed_origins(list(authorization.endpoints), "endpoint")
    except UsageError as exc:
        raise UsageError(f"AUTHORIZE.ENDPOINT.INVALID: {exc}") from exc
    _new_path(args.out, "AUTHORIZE.OUTPUT.EXISTS")
    signer = load_signing_key(
        args.key, args.kid, _passphrase(args), allow_unencrypted=args.allow_unencrypted_key
    )
    write_new_file(args.out, (issue_authorization(authorization, signer) + "\n").encode("ascii"))
    summary = {
        "written": str(args.out),
        "authorization_id": authorization.authorization_id,
        "kid": args.kid,
        "issuer": authorization.issuer,
    }
    _emit(
        args,
        summary,
        f"signed authorization {authorization.authorization_id!r} with key '{args.kid}'; wrote {args.out}",
    )
    return EXIT_OK


def cmd_trust_add_key(args: argparse.Namespace) -> int:
    """Write a dppce.trust/2 bundle with one more key. Nothing is trusted that the operator did not add."""
    if (args.bundle is None) == (args.policy_version is None):
        raise UsageError("TRUST.BUNDLE.OPTION: give exactly one of --bundle and --policy-version")
    bundle = _trust(args.bundle) or TrustBundle(
        schema_version="dppce.trust/2", policy_version=args.policy_version
    )
    _new_path(args.out, "TRUST.OUTPUT.EXISTS")
    try:
        jwk = public_jwk_from(parse_strict(args.public_key.read_bytes()))
    except SignatureError as exc:
        if exc.code == "PRIVATE":
            raise UsageError(f"TRUST.KEY.PRIVATE: {exc}") from exc
        raise UsageError(f"TRUST.KEY.NOT_P256: {exc}") from exc
    except CanonicalizationError as exc:
        raise UsageError("TRUST.KEY.NOT_P256: the public key file is not strict JSON") from exc
    if any(key.kid == args.kid for key in bundle.keys):
        raise UsageError(f"TRUST.KEY.DUPLICATE_KID: the bundle already holds the key {args.kid!r}")
    times = []
    for value in (args.not_before, args.not_after):
        try:
            times.append(parse_stamp(value))
        except ValueError as exc:
            raise UsageError(
                f"TRUST.KEY.PERIOD_INVALID: '{value}' is not a time such as 2026-10-13T12:00:00Z"
            ) from exc
    start, end = times
    if start > end:
        raise UsageError("TRUST.KEY.PERIOD_INVALID: --not-before is after --not-after")
    purposes = tuple(dict.fromkeys(args.purpose))
    try:
        added = TrustedKey(
            kid=args.kid,
            issuer=args.issuer,
            purposes=purposes,
            public_jwk=jwk,
            not_before=args.not_before,
            not_after=args.not_after,
        )
        written = TrustBundle.model_validate({**bundle.model_dump(), "keys": [*bundle.keys, added]})
    except ValidationError as exc:
        # The first message carries the reason code, for example TRUST.KEY.ROLE_CONFLICT.
        raise UsageError(_first_message(exc)) from exc
    write_new_file(args.out, (written.model_dump_json(indent=2) + "\n").encode("utf-8"))
    summary = {
        "written": str(args.out),
        "kid": args.kid,
        "purposes": list(purposes),
        "keys": len(written.keys),
    }
    _emit(args, summary, f"added key {args.kid!r} for {', '.join(purposes)}; wrote {args.out}")
    return EXIT_OK


def cmd_open(args: argparse.Namespace) -> int:
    """Write the salt and the plaintext of one record for a disclosure (section 10.2)."""
    _new_path(args.out, "OPEN.OUTPUT.EXISTS")
    envelope = _checked_envelope(args.envelope or args.run / "envelope.json")
    records = read_recording(args.run / "recording", FileDataKeyProvider(args.keys))
    record = next((r for r in records if r.record_id == args.record), None)
    if record is None:
        raise UsageError(f"OPEN.RECORD.UNKNOWN: the recording holds no record {args.record!r}")
    try:
        opening = disclosure.open_record(envelope.decision, record)
    except disclosure.DisclosureError as exc:
        raise UsageError(f"{exc.code}: {exc}") from exc
    warning = (
        f"WARNING: {args.out} holds the plaintext of record {record.record_id}: the request without "
        "secrets, the response headers, and the response body. Give it only to a party that is "
        "entitled to it."
    )
    # Before the write: no plaintext is ever on disk without the warning.
    print(warning, file=sys.stderr)
    write_new_file(args.out, canonical_bytes(opening) + b"\n", 0o600)
    _emit(
        args,
        {"written": str(args.out), "record_id": record.record_id, "warning": warning},
        f"wrote {args.out}",
    )
    return EXIT_OK


def cmd_prove(args: argparse.Namespace) -> int:
    """Write the inclusion proof of one result (section 11.2)."""
    _new_path(args.out, "PROVE.OUTPUT.EXISTS")
    envelope = _checked_envelope(args.envelope)
    try:
        proof = disclosure.prove(envelope.decision, args.result)
    except disclosure.DisclosureError as exc:
        raise UsageError(f"{exc.code}: {exc}") from exc
    write_new_file(args.out, canonical_bytes(proof) + b"\n")
    summary = {"written": str(args.out), "key": proof.key, "index": proof.index, "size": proof.size}
    _emit(
        args, summary, f"wrote the proof of {proof.key!r}, leaf {proof.index} of {proof.size}, to {args.out}"
    )
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    trust = _trust(args.trust)
    if trust is None:
        raise UsageError("verification needs an explicit trust bundle")
    report = verify_json(
        args.envelope.read_bytes(),
        trust,
        _time(args.at),
        status_list=_read_capped(args.status_list, status_lists.MAX_TOKEN_BYTES),
        opening=_read_capped(args.opening, disclosure.MAX_OPENING_BYTES),
        proof=_read_capped(args.proof, disclosure.MAX_PROOF_BYTES),
    )
    lines = [f"{d.name:14} {d.outcome:12} {d.detail}" for d in report.dimensions]
    state = "complete" if report.complete else "NOT complete"
    text = "\n".join([*lines, f"verification is {state} at {report.evaluation_time}", report.note])
    _emit(args, report.model_dump(mode="json"), text)
    return EXIT_OK if report.complete else EXIT_VERIFY


def cmd_timestamp_imprint(args: argparse.Namespace) -> int:
    """Print the SHA-256 imprint of each signature. The operator makes the request with it."""
    envelope = EvidenceEnvelope.model_validate(parse_strict(args.envelope.read_bytes()))
    if not envelope.signatures:
        raise UsageError("TIMESTAMP.SIGNATURE.NONE: the envelope has no signature to timestamp")
    rows: list[dict[str, Any]] = []
    for token in envelope.signatures:
        try:
            rows.append({"kid": header_of(token).get("kid"), "imprint": f"sha256:{imprint_hex(token)}"})
        except SignatureError as exc:
            raise UsageError(
                "TIMESTAMP.SIGNATURE.MALFORMED: a signature of the envelope is not a compact JWS"
            ) from exc
    _emit(args, {"imprints": rows}, "\n".join(f"{row['kid']!r} {row['imprint']}" for row in rows))
    return EXIT_OK


def _signature_with_imprint(signatures: Sequence[str], imprint: bytes) -> str | None:
    for token in signatures:
        with contextlib.suppress(SignatureError):
            if imprint_of(token) == imprint:
                return token
    return None


def cmd_timestamp_attach(args: argparse.Namespace) -> int:
    """Add the token of a TimeStampResp file to a copy of the envelope. It verifies no trust."""
    if args.out.resolve() == args.envelope.resolve():
        raise UsageError("--out must name a new file; the input envelope is never overwritten")
    envelope = EvidenceEnvelope.model_validate(parse_strict(args.envelope.read_bytes()))
    with args.response.open("rb") as file:
        response = file.read(MAX_TOKEN_BYTES + 1)
    if len(response) > MAX_TOKEN_BYTES:
        raise UsageError(f"TIMESTAMP.RESPONSE.TOO_LARGE: the response is larger than {MAX_TOKEN_BYTES} bytes")
    try:
        status, der = token_from_response(response)
    except TimestampError as exc:
        raise UsageError(f"TIMESTAMP.RESPONSE.MALFORMED: {exc}") from exc
    if status not in ("granted", "granted_with_mods"):
        raise UsageError(f"TIMESTAMP.RESPONSE.REJECTED: the response has the status {status!r}")
    try:
        if not der:
            raise TimestampError("TIMESTAMP.TOKEN.MALFORMED", "the response holds no token")
        token = parse_token(der)
    except TimestampError as exc:
        raise UsageError(f"TIMESTAMP.RESPONSE.MALFORMED: {exc}") from exc
    if token.imprint_oid != TIMESTAMP_SHA256:
        raise UsageError("TIMESTAMP.IMPRINT.ALGORITHM: the imprint of the token does not use SHA-256")
    signature = _signature_with_imprint(envelope.signatures, token.imprint)
    if signature is None:
        raise UsageError("TIMESTAMP.IMPRINT.MISMATCH: the token is not over a signature of this envelope")
    text = base64.b64encode(der).decode("ascii")
    if text in envelope.timestamp_evidence:
        raise UsageError("TIMESTAMP.TOKEN.DUPLICATE: the envelope already holds this token")
    if len(envelope.timestamp_evidence) >= MAX_TOKENS:
        raise UsageError(f"TIMESTAMP.EVIDENCE.TOO_MANY: the envelope already holds {MAX_TOKENS} tokens")
    stamped = envelope.model_copy(update={"timestamp_evidence": (*envelope.timestamp_evidence, text)})
    args.out.write_text(stamped.model_dump_json(by_alias=True) + "\n", encoding="utf-8")
    kid, gen_time = header_of(signature).get("kid"), format_time(token.gen_time)
    summary = {
        "written": str(args.out),
        "kid": kid,
        "gen_time": gen_time,
        "timestamps": len(stamped.timestamp_evidence),
    }
    message = (
        f"attached a timestamp of {gen_time} for the signature of key {kid!r}; "
        f"not verified: run dppce verify; wrote {args.out}"
    )
    _emit(args, summary, message)
    return EXIT_OK


def cmd_catalogue_lint(args: argparse.Namespace) -> int:
    root = data_root(args.data_root)
    findings = lint(
        load_catalogue(root, extra_packs=args.import_pack),
        load_profiles(root),
        load_testpacks(root, extra_testpacks=args.import_testpack),
        registry.param_models(),
        root,
    )
    errors = sum(1 for f in findings if f.severity == "error")
    lines = [f"{f.severity:8} {f.code} {f.location}: {f.message}" for f in findings]
    lines.append(f"{errors} errors, {len(findings) - errors} other findings")
    _emit(args, [asdict(f) for f in findings], "\n".join(lines))
    return EXIT_USAGE if errors else EXIT_OK


def cmd_catalogue_trace(args: argparse.Namespace) -> int:
    root = data_root(args.data_root)
    rows = trace(
        load_catalogue(root, extra_packs=args.import_pack),
        load_testpacks(root, extra_testpacks=args.import_testpack),
    )
    lines = [
        f"{r.source_id} {r.citation or '-'} -> {r.requirement_id} [{r.review_status}] -> "
        f"{r.test_purpose_id or '(no test)'} -> {r.check or '-'}"
        for r in rows
    ]
    _emit(args, [asdict(r) for r in rows], "\n".join(lines))
    return EXIT_OK


def cmd_manual_digest(args: argparse.Namespace) -> int:
    """Print the digest that a manual result must name. It writes and signs nothing."""
    testpacks = load_testpacks(data_root(args.data_root), extra_testpacks=args.import_testpack)
    ident = args.test_purpose
    found = sorted(
        ((name, p) for name, pack in testpacks.items() for p in pack.test_purposes if p.id == ident),
        key=lambda pair: pair[0],
    )
    if args.testpack is not None:
        found = [(name, p) for name, p in found if name == args.testpack]
    if not found:
        raise UsageError(
            f"MANUAL.DIGEST.PURPOSE_UNKNOWN: no loaded test pack defines the test purpose {ident}"
        )
    if len(found) > 1:
        names = ", ".join(name for name, _ in found)
        raise UsageError(
            f"MANUAL.DIGEST.PURPOSE_AMBIGUOUS: the test purpose {ident} is defined in the test packs "
            f"{names}; select one with --testpack"
        )
    ((testpack_id, purpose),) = found
    if not purpose.manual or purpose.stimulus.check != MANUAL_CHECK:
        raise UsageError(
            f"MANUAL.DIGEST.NOT_MANUAL: the test purpose {ident} is not a manual step with the check "
            f"{MANUAL_CHECK}"
        )
    value = test_purpose_digest(purpose)
    document = {"test_purpose_id": ident, "testpack_id": testpack_id, "test_purpose_digest": value}
    _emit(args, document, value)
    return EXIT_OK


def cmd_coverage(args: argparse.Namespace) -> int:
    envelope = EvidenceEnvelope.model_validate(parse_strict(args.envelope.read_bytes()))
    coverage = envelope.decision.coverage
    lines = [f"scope: {coverage.scope_statement}", f"known requirements: {coverage.total_requirements}"]
    for label, ratio in (
        ("implementation", coverage.implementation),
        ("execution", coverage.execution),
        ("passing", coverage.passing),
    ):
        lines.append(f"{label}: {ratio.numerator} of {ratio.denominator} {ratio.of}")
    lines.append(f"by verdict: {coverage.by_verdict}")
    lines.append(
        f"placeholders {coverage.placeholders}, unknown applicability {coverage.unknown_applicability}, "
        f"excluded {coverage.excluded}, manual assessment missing {coverage.manual_missing}"
    )
    _emit(args, coverage.model_dump(mode="json"), "\n".join(lines))
    return EXIT_OK


def _dependency_note(module: str | None, available: bool) -> str:
    if module is None:
        return ""
    return f"needs '{module}': " + ("installed" if available else "NOT installed")


def cmd_capabilities(args: argparse.Namespace) -> int:
    manifest = capability_manifest()
    caps = manifest.capabilities
    lines = [
        f"{c.id:26} {c.state.value:15} {_dependency_note(c.optional_dependency, c.available)}" for c in caps
    ]
    _emit(args, manifest.model_dump(mode="json"), "\n".join(lines))
    return EXIT_OK


def cmd_purge(args: argparse.Namespace) -> int:
    """List the expired recordings. Delete them only with ``--yes``."""
    today, keys = _time(args.at).date(), FileDataKeyProvider(args.keys)
    expired: list[str] = []
    kept: list[dict[str, str]] = []
    for run in sorted(p for p in args.runs.iterdir() if p.is_dir() and not p.is_symlink()):
        result = purge_expired(run, today, keys, delete=args.yes)
        expired += [str(p) for p in result.expired]
        kept += [{"path": str(p), "reason": reason} for p, reason in result.kept]
    verb = "deleted" if args.yes else "would delete (run again with --yes)"
    lines = [f"{verb}: {p}" for p in expired] + [f"left alone: {k['path']}: {k['reason']}" for k in kept]
    _emit(
        args, {"deleted": args.yes, "expired": expired, "kept": kept}, "\n".join(lines) or "nothing to purge"
    )
    return EXIT_OK


def _parser() -> argparse.ArgumentParser:  # noqa: PLR0915 - a flat declaration of the command line
    parser = argparse.ArgumentParser(
        prog="dppce", description="Conformance test engine for Digital Product Passports."
    )
    parser.add_argument("--version", action="version", version=f"dppce {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    def add(name: str, handler: Callable[[argparse.Namespace], int], summary: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=summary, description=summary)
        sub.add_argument("--json", action="store_true", help="write one JSON document to standard output")
        sub.set_defaults(handler=handler)
        return sub

    def catalogue_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--data-root", type=Path, help="directory with catalogue, profiles, and testpacks")
        sub.add_argument(
            "--import-pack", type=Path, action="append", default=[], help="import a requirement pack file"
        )
        sub.add_argument(
            "--import-testpack", type=Path, action="append", default=[], help="import a test pack file"
        )

    def run_options(sub: argparse.ArgumentParser) -> None:
        catalogue_options(sub)
        sub.add_argument("--profile", required=True, help="profile identifier, for example battery/ev")
        sub.add_argument("--ics", type=Path, required=True, help="implementation conformance statement")
        sub.add_argument("--ixit", type=Path, required=True, help="extra information for testing")
        sub.add_argument("--mode", choices=[m.value for m in ExecutionMode], default="illustrative")
        sub.add_argument("--pack", action="append", default=[], help="select one more pack by identifier")
        sub.add_argument(
            "--testpack", action="append", default=[], help="select one more test pack by identifier"
        )
        sub.add_argument("--trust", type=Path, help="trust bundle (JSON); only the operator supplies it")
        sub.add_argument("--authorization", type=Path, help="signed test authorization (compact JWS)")
        sub.add_argument(
            "--manual-result",
            type=Path,
            action="append",
            default=[],
            metavar="PATH",
            help="signed result of one manual step (compact JWS); only the operator supplies it; "
            "repeat for each",
        )
        sub.add_argument("--at", help="evaluation time, for example 2026-10-13T12:00:00Z; default: now")
        sub.add_argument(
            "--issuer-name",
            default="unspecified",
            help="issuer name, declared by the operator; the verifier does not check it",
        )
        sub.add_argument(
            "--issuer-id",
            default="unspecified",
            help="issuer identifier; it must equal the issuer that the trust bundle names for the report "
            "signing key",
        )
        sub.add_argument(
            "--accreditation-status",
            default=NOT_ACCREDITED,
            help="declared by the operator and not validated by the engine; a value other than "
            f"'{NOT_ACCREDITED}' needs --accreditation-reference",
        )
        sub.add_argument("--accreditation-reference", default="")

    run_options(add("plan", cmd_plan, "Show which requirements and test steps a run would select."))
    run = add("run", cmd_run, "Execute the plan, record the observations, and write the report.")
    run_options(run)
    run.add_argument("--out", type=Path, required=True, help="new directory for the run")
    run.add_argument("--keys", type=Path, required=True, help="directory with the data keys; keep it apart")
    run.add_argument(
        "--data-key-id",
        default="local-data-key-1",
        help="identifier of the data key in --keys; default: local-data-key-1",
    )
    run.add_argument(
        "--create-data-key",
        action="store_true",
        help="create the data key from operating-system randomness if it does not exist",
    )
    run.add_argument("--secrets", type=Path, help="directory that holds the file secrets of the roles")
    run.add_argument(
        "--role-secret",
        action="append",
        default=[],
        metavar="ROLE=REFERENCE",
        help="confirm the secret reference that the IXIT declares for one role; repeat for each role",
    )
    run.add_argument(
        "--allow-private-host",
        action="append",
        default=[],
        metavar="ORIGIN",
        help="confirm one loopback or private origin, such as http://127.0.0.1:8765; repeat for each origin",
    )
    run.add_argument(
        "--allow-remote-host",
        action="append",
        default=[],
        metavar="ORIGIN",
        help="state that the owner of one public origin permits bounded read-only access; repeat for each",
    )
    run.add_argument(
        "--retention-days",
        type=int,
        help="days to keep the recording; the operator decides; default: the value that the IXIT asks for",
    )

    replay = add("replay", cmd_replay, "Evaluate a recording again and compare the decision digest.")
    replay.add_argument("--run", type=Path, required=True)
    replay.add_argument("--keys", type=Path, required=True)
    replay.add_argument("--data-root", type=Path)
    replay.add_argument("--times", type=int, default=1)

    report = add("report", cmd_report, "Render a report as HTML or JSON.")
    report.add_argument("--envelope", type=Path, required=True)
    report.add_argument("--format", choices=["html", "json"], default="html")
    report.add_argument("--out", type=Path)
    report.add_argument("--trust", type=Path, help="include a verification section (HTML only)")
    report.add_argument("--at")
    report.add_argument("--status-list", type=Path, help=_STATUS_LIST_HELP)

    def key_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--key", type=Path, required=True, help="PEM private key, P-256, encrypted")
        sub.add_argument("--kid", required=True, help="key identifier that the trust bundle names")
        sub.add_argument(
            "--passphrase-ref",
            metavar="REFERENCE",
            help="secret reference of the key passphrase: env:DPPCE_SECRET_<NAME> or file:<name>",
        )
        sub.add_argument("--secrets", type=Path, help="directory that holds the file secrets")
        sub.add_argument(
            "--allow-unencrypted-key",
            action="store_true",
            help="accept a key that is not encrypted; for TEST-ONLY keys",
        )

    sign = add("sign", cmd_sign, "Sign an envelope with a local key file.")
    sign.add_argument("--envelope", type=Path, required=True)
    key_options(sign)
    sign.add_argument("--issuer", required=True, help="issuer identifier that the trust bundle names")
    target = sign.add_mutually_exclusive_group(required=True)
    target.add_argument("--out", type=Path, help="new file for the signed envelope")
    target.add_argument("--in-place", action="store_true", help="replace the input envelope")
    sign.add_argument(
        "--role",
        choices=["issuer", "reviewer"],
        default="issuer",
        help="declared role; reviewer: a person signs with a key that only that person holds",
    )
    sign.add_argument("--valid-until", help="issuer only: last time at which the report is valid")
    sign.add_argument(
        "--supersedes", help="issuer only: decision digest of the earlier report that this replaces"
    )
    sign.add_argument("--status-list-id", help="issuer only: identifier of the status list of the report")
    sign.add_argument("--status-index", type=int, help="issuer only: index of the report in that status list")

    verify = add("verify", cmd_verify, "Verify a signed envelope against an explicit trust bundle.")
    verify.add_argument("--envelope", type=Path, required=True)
    verify.add_argument("--trust", type=Path, required=True)
    verify.add_argument("--at", required=True, help="explicit evaluation time")
    verify.add_argument("--status-list", type=Path, help=_STATUS_LIST_HELP)
    verify.add_argument("--opening", type=Path, help="record opening to check against the report")
    verify.add_argument("--proof", type=Path, help="inclusion proof to check against the report")

    authorize = add("authorize", cmd_authorize, "Sign a test authorization with the key of the system owner.")
    authorize.add_argument(
        "--document", type=Path, required=True, help="dppce.authorization/1 document (JSON)"
    )
    key_options(authorize)
    authorize.add_argument("--out", type=Path, required=True, help="new file for the compact JWS")

    opening = add("open", cmd_open, "Write the salt and the plaintext of one record for a disclosure.")
    opening.add_argument("--run", type=Path, required=True, help="run directory")
    opening.add_argument("--keys", type=Path, required=True, help="directory with the data keys")
    opening.add_argument("--record", required=True, help="record identifier, for example r0001")
    opening.add_argument("--envelope", type=Path, help="envelope of the run; default: RUN/envelope.json")
    opening.add_argument(
        "--out", type=Path, required=True, help="new file; it holds the plaintext of the record"
    )

    prove = add("prove", cmd_prove, "Write the inclusion proof of one result of a report.")
    prove.add_argument("--envelope", type=Path, required=True)
    prove.add_argument(
        "--result",
        required=True,
        help="R: plus a requirement identifier, or T: plus a test purpose identifier",
    )
    prove.add_argument("--out", type=Path, required=True, help="new file for the proof")

    keys = commands.add_parser("keys", help="Signing key tools.").add_subparsers(
        dest="keys_command", required=True
    )
    summary = "Write a new P-256 signing key, encrypted with a passphrase, and print its public JWK."
    generate = keys.add_parser("generate", help=summary, description=summary)
    generate.add_argument("--json", action="store_true", help="write one JSON document to standard output")
    generate.set_defaults(handler=cmd_keys_generate)
    generate.add_argument("--out", type=Path, required=True, help="new key file; mode 0600")
    generate.add_argument(
        "--passphrase-ref",
        required=True,
        metavar="REFERENCE",
        help="secret reference: env:DPPCE_SECRET_<NAME> or file:<name>; use a generated passphrase of "
        "at least 32 bytes, for example from secrets.token_urlsafe(32)",
    )
    generate.add_argument("--secrets", type=Path, help="directory that holds the file secrets")

    trust_bundle = commands.add_parser("trust-bundle", help="Trust bundle tools.").add_subparsers(
        dest="trust_bundle_command", required=True
    )
    summary = "Write a dppce.trust/2 bundle with one more public key."
    add_key = trust_bundle.add_parser("add-key", help=summary, description=summary)
    add_key.add_argument("--json", action="store_true", help="write one JSON document to standard output")
    add_key.set_defaults(handler=cmd_trust_add_key)
    add_key.add_argument("--bundle", type=Path, help="bundle to extend; a version 1 bundle is upgraded")
    add_key.add_argument("--policy-version", help="start a new empty bundle with this policy version")
    add_key.add_argument("--kid", required=True, help="key identifier")
    add_key.add_argument("--issuer", required=True, help="issuer identifier of the key")
    add_key.add_argument(
        "--purpose",
        required=True,
        action="append",
        # The Literal inside tuple[Literal[...], ...]: the model stays the one source of the purposes.
        choices=get_args(get_args(TrustedKey.model_fields["purposes"].annotation)[0]),
        help="purpose of the key; repeat for each",
    )
    add_key.add_argument("--public-key", type=Path, required=True, help="public JWK file of a P-256 key")
    add_key.add_argument(
        "--not-before", required=True, help="start of validity, for example 2026-01-01T00:00:00Z"
    )
    add_key.add_argument(
        "--not-after", required=True, help="end of validity, for example 2027-01-01T00:00:00Z"
    )
    add_key.add_argument("--out", type=Path, required=True, help="new bundle file")

    catalogue = commands.add_parser("catalogue", help="Catalogue tools.").add_subparsers(
        dest="catalogue_command", required=True
    )
    for name, handler, summary in (
        ("lint", cmd_catalogue_lint, "Check the catalogue, the profiles, and the test packs."),
        ("trace", cmd_catalogue_trace, "Print the trace from source provision to executable check."),
    ):
        sub = catalogue.add_parser(name, help=summary, description=summary)
        sub.add_argument("--json", action="store_true")
        sub.set_defaults(handler=handler)
        catalogue_options(sub)

    manual = commands.add_parser("manual", help="Manual-step tools.").add_subparsers(
        dest="manual_command", required=True
    )
    summary = "Print the test_purpose_digest that a signed manual result must name."
    digest_command = manual.add_parser("digest", help=summary, description=summary)
    digest_command.add_argument("--json", action="store_true")
    digest_command.set_defaults(handler=cmd_manual_digest)
    digest_command.add_argument(
        "--data-root", type=Path, help="directory with catalogue, profiles, and testpacks"
    )
    digest_command.add_argument(
        "--import-testpack", type=Path, action="append", default=[], help="import a test pack file"
    )
    digest_command.add_argument("--test-purpose", required=True, help="identifier of the manual test purpose")
    digest_command.add_argument("--testpack", help="look in this test pack only, by identifier")

    timestamp = commands.add_parser(
        "timestamp", help="Timestamp tools. No command contacts a timestamp authority."
    ).add_subparsers(dest="timestamp_command", required=True)
    summary = "Print the SHA-256 imprint of each signature of an envelope, for a timestamp request."
    imprint_command = timestamp.add_parser("imprint", help=summary, description=summary)
    imprint_command.add_argument("--json", action="store_true")
    imprint_command.set_defaults(handler=cmd_timestamp_imprint)
    imprint_command.add_argument("--envelope", type=Path, required=True)
    summary = "Add the token of a TimeStampResp file to a copy of an envelope. It does not verify the token."
    attach_command = timestamp.add_parser("attach", help=summary, description=summary)
    attach_command.add_argument("--json", action="store_true")
    attach_command.set_defaults(handler=cmd_timestamp_attach)
    attach_command.add_argument("--envelope", type=Path, required=True)
    attach_command.add_argument(
        "--response", type=Path, required=True, help="DER TimeStampResp that the operator obtained"
    )
    attach_command.add_argument("--out", type=Path, required=True, help="new envelope file; never the input")

    coverage = add("coverage", cmd_coverage, "Show the coverage of the selected catalogue for a run.")
    coverage.add_argument("--envelope", type=Path, required=True)

    add("capabilities", cmd_capabilities, "Show the capability manifest of this installation.")

    purge = add("purge", cmd_purge, "Delete recordings whose retention period has ended.")
    purge.add_argument("--runs", type=Path, required=True, help="directory that holds run directories")
    purge.add_argument("--keys", type=Path, required=True, help="directory with the data keys")
    purge.add_argument("--yes", action="store_true", help="delete; without it the command only lists")
    purge.add_argument("--at", help="reference time; default: now")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (UsageError, *_INPUT_ERRORS) as exc:
        print(f"error: {str(exc).splitlines()[0]}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:
        # An unexpected defect is an execution error. It is never reported as a failure of the system.
        print(
            f"execution error: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}",
            file=sys.stderr,
        )
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
