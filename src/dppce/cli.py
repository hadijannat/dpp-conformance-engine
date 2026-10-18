"""Command-line entry point.

Exit codes (docs/explanation/architecture.md, section 12):
0 completed (run, replay: overall pass); 1 the system under test failed; 2 usage or input error;
3 execution error; 4 evidence verification failed or replay digest mismatch; 5 inconclusive.
Every command accepts ``--json`` and then writes one JSON document to standard output.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from pydantic import ValidationError

from dppce import __version__
from dppce.adapters.capabilities import manifest as capability_manifest
from dppce.applicability import ApplicabilityError
from dppce.catalogue import (
    CatalogueError,
    check_ics,
    load_catalogue,
    load_ics,
    load_ixit,
    load_profiles,
    load_testpacks,
)
from dppce.catalogue.lint import lint, trace
from dppce.evidence.canonical import CanonicalizationError, canonical_bytes, parse_strict
from dppce.evidence.envelope import decision_digest, in_layout_of, sign_envelope
from dppce.evidence.jws import LocalSigner, SignatureError
from dppce.evidence.recording import RecordingError, purge_expired, read_recording, write_recording
from dppce.infrastructure.authorization import AuthorizationError, validate_authorization
from dppce.infrastructure.clock import STAMP_FORMAT, SystemClock, parse_stamp, utc_stamp
from dppce.infrastructure.keys import FileDataKeyProvider, KeyError_, resolve_secret
from dppce.infrastructure.replay import ReplayAcquirer
from dppce.infrastructure.resources import data_root
from dppce.infrastructure.transport import (
    ANONYMOUS,
    MIN_SECRET_LENGTH,
    PolicyTransport,
    TransportConfig,
    origin_of,
)
from dppce.models import (
    ICS,
    IXIT,
    EvidenceEnvelope,
    ExecutionMode,
    IssuerStatement,
    TrustBundle,
    Verdict,
)
from dppce.orchestrator.plan import PlanError
from dppce.orchestrator.run import RunInputs, evaluate, make_plan
from dppce.report import render
from dppce.testdefs import registry
from dppce.verifier import verify_json

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
    return TrustBundle.model_validate(parse_strict(path.read_bytes())) if path else None


def _build_inputs(
    *,
    root: Path,
    mode: ExecutionMode,
    profile_id: str,
    ics: ICS,
    ixit: IXIT,
    evaluation_time: datetime,
    import_packs: list[Path],
    extra_packs: list[str],
    import_testpacks: list[Path],
    extra_testpacks: list[str],
    trust: TrustBundle | None,
    authorization_token: str | None,
    issuer: IssuerStatement,
) -> RunInputs:
    profiles = load_profiles(root)
    if profile_id not in profiles:
        raise UsageError(f"profile '{profile_id}' is not found; available: {', '.join(sorted(profiles))}")
    profile = profiles[profile_id]
    if extra_packs:
        profile = profile.model_copy(update={"packs": (*profile.packs, *extra_packs)})
    if extra_testpacks:
        profile = profile.model_copy(update={"testpacks": (*profile.testpacks, *extra_testpacks)})
    problems = check_ics(ics, profile)
    if problems:
        raise UsageError("the ICS does not fit the profile: " + " ".join(problems))
    authorization = None
    if authorization_token is not None:
        if trust is None:
            raise UsageError("an authorization needs a trust bundle that names its issuer")
        authorization = validate_authorization(
            authorization_token, trust, evaluation_time, ics.sut.identifier
        )
    return RunInputs(
        mode=mode,
        profile=profile,
        catalogue=load_catalogue(root, extra_packs=import_packs),
        testpacks=load_testpacks(root, extra_testpacks=import_testpacks),
        ics=ics,
        ixit=ixit,
        data_root=root,
        evaluation_time=evaluation_time,
        trust=trust,
        authorization=authorization,
        issuer=issuer,
    )


def _inputs_from_args(args: argparse.Namespace) -> tuple[RunInputs, str | None, TrustBundle | None]:
    ixit = load_ixit(args.ixit)
    base = args.ixit.resolve().parent
    # Trust comes from the operator only. A trust bundle that the IXIT names is never loaded:
    # the supplier of the system under test could otherwise name its own key as trusted.
    trust = _trust(args.trust)
    token_path = getattr(args, "authorization", None) or (
        _confined(base, ixit.authorization_ref, "authorization_ref") if ixit.authorization_ref else None
    )
    token = token_path.read_text(encoding="ascii").strip() if token_path else None
    issuer = IssuerStatement(
        name=args.issuer_name,
        identifier=args.issuer_id,
        accreditation_status=args.accreditation_status,
        accreditation_reference=args.accreditation_reference,
    )
    inputs = _build_inputs(
        root=data_root(args.data_root),
        mode=ExecutionMode(args.mode),
        profile_id=args.profile,
        ics=load_ics(args.ics),
        ixit=ixit,
        evaluation_time=_time(args.at),
        import_packs=args.import_pack,
        extra_packs=args.pack,
        import_testpacks=args.import_testpack,
        extra_testpacks=args.testpack,
        trust=trust,
        authorization_token=token,
        issuer=issuer,
    )
    return inputs, token, trust


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
    origins = set()
    for value in values:
        try:
            parts = urlsplit(value)
            origin = origin_of(value)
        except ValueError as exc:
            raise UsageError(f"{flag} {value!r} is not an origin") from exc
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.path not in ("", "/"):
            raise UsageError(f"{flag} takes an origin such as http://127.0.0.1:8765, not {value!r}")
        origins.add(origin)
    return frozenset(origins)


def cmd_plan(args: argparse.Namespace) -> int:
    inputs, _, _ = _inputs_from_args(args)
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
    inputs, token, trust = _inputs_from_args(args)
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
    keys = FileDataKeyProvider(args.keys)
    keys.create()
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
    stored = {
        "schema_version": "dppce.runinputs/1",
        "mode": inputs.mode.value,
        "profile": args.profile,
        "evaluation_time": utc_stamp(inputs.evaluation_time),
        "ics": inputs.ics.model_dump(mode="json"),
        "ixit": ixit.model_dump(mode="json"),
        "import_packs": [str(p.resolve()) for p in args.import_pack],
        "extra_packs": list(args.pack),
        "import_testpacks": [str(p.resolve()) for p in args.import_testpack],
        "extra_testpacks": list(args.testpack),
        "trust": trust.model_dump(mode="json") if trust else None,
        "authorization_token": token,
        "issuer": inputs.issuer.model_dump(mode="json"),
    }
    (out / "inputs.json").write_bytes(canonical_bytes(stored) + b"\n")
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
    stored = parse_strict((run / "inputs.json").read_bytes())
    original = EvidenceEnvelope.model_validate(parse_strict((run / "envelope.json").read_bytes()))
    records = read_recording(run / "recording", FileDataKeyProvider(args.keys))
    try:
        # Only the reading of the stored fields is guarded: a damaged file is an input error.
        fields: dict[str, Any] = {
            "mode": ExecutionMode(stored["mode"]),
            "profile_id": str(stored["profile"]),
            "ics": ICS.model_validate(stored["ics"]),
            "ixit": IXIT.model_validate(stored["ixit"]),
            "evaluation_time": parse_stamp(stored["evaluation_time"]),
            "import_packs": [Path(p) for p in stored["import_packs"]],
            "extra_packs": list(stored["extra_packs"]),
            # A run recorded before the test-pack import existed imported no test pack.
            "import_testpacks": [Path(p) for p in stored.get("import_testpacks", [])],
            "extra_testpacks": list(stored.get("extra_testpacks", [])),
            "trust": TrustBundle.model_validate(stored["trust"]) if stored["trust"] else None,
            "authorization_token": stored["authorization_token"],
            "issuer": IssuerStatement.model_validate(stored["issuer"]),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise UsageError(
            f"{run / 'inputs.json'} is not a valid record of run inputs: {type(exc).__name__}"
        ) from exc
    inputs = _build_inputs(root=data_root(args.data_root), **fields)
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
    }
    state = "match" if match else "MISMATCH"
    _emit(args, summary, f"{args.times} replays: {state}\nexpected {expected}\noverall {overall.value}")
    return _VERDICT_EXIT[overall] if match else EXIT_VERIFY


def cmd_report(args: argparse.Namespace) -> int:
    raw = args.envelope.read_bytes()
    envelope = EvidenceEnvelope.model_validate(parse_strict(raw))
    if args.format == "json":
        text = envelope.model_dump_json(by_alias=True, indent=2) + "\n"
    else:
        trust = _trust(args.trust)
        if trust is not None and args.at is None:
            # Verification needs an explicit evaluation time. "Now" is never assumed.
            raise UsageError("a report with a verification section needs an explicit time: --at")
        verification = verify_json(raw, trust, _time(args.at)) if trust else None
        text = render(envelope, verification)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        _emit(args, {"written": str(args.out)}, f"wrote {args.out}")
    else:
        sys.stdout.write(text)
    return EXIT_OK


def cmd_sign(args: argparse.Namespace) -> int:
    envelope = EvidenceEnvelope.model_validate(parse_strict(args.envelope.read_bytes()))
    signer = LocalSigner.from_pem(args.key, args.kid)
    signed = sign_envelope(envelope, signer, issuer=args.issuer, signed_at=utc_stamp(_now()))
    out: Path = args.out or args.envelope
    out.write_text(signed.model_dump_json(by_alias=True) + "\n", encoding="utf-8")
    summary = {"written": str(out), "signatures": len(signed.signatures), "kid": args.kid}
    _emit(args, summary, f"signed with key '{args.kid}'; wrote {out}")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    trust = _trust(args.trust)
    if trust is None:
        raise UsageError("verification needs an explicit trust bundle")
    report = verify_json(args.envelope.read_bytes(), trust, _time(args.at))
    lines = [f"{d.name:14} {d.outcome:12} {d.detail}" for d in report.dimensions]
    state = "complete" if report.complete else "NOT complete"
    text = "\n".join([*lines, f"verification is {state} at {report.evaluation_time}", report.note])
    _emit(args, report.model_dump(mode="json"), text)
    return EXIT_OK if report.complete else EXIT_VERIFY


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
        sub.add_argument("--at", help="evaluation time, for example 2026-10-13T12:00:00Z; default: now")
        sub.add_argument("--issuer-name", default="unspecified")
        sub.add_argument("--issuer-id", default="unspecified")
        sub.add_argument("--accreditation-status", default="not accredited")
        sub.add_argument("--accreditation-reference", default="")

    run_options(add("plan", cmd_plan, "Show which requirements and test steps a run would select."))
    run = add("run", cmd_run, "Execute the plan, record the observations, and write the report.")
    run_options(run)
    run.add_argument("--out", type=Path, required=True, help="new directory for the run")
    run.add_argument("--keys", type=Path, required=True, help="directory with the data keys; keep it apart")
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

    sign = add("sign", cmd_sign, "Sign an envelope with a local key (development and tests).")
    sign.add_argument("--envelope", type=Path, required=True)
    sign.add_argument("--key", type=Path, required=True, help="PEM private key, P-256")
    sign.add_argument("--kid", required=True)
    sign.add_argument("--issuer", required=True, help="issuer identifier that the trust bundle names")
    sign.add_argument("--out", type=Path)

    verify = add("verify", cmd_verify, "Verify a signed envelope against an explicit trust bundle.")
    verify.add_argument("--envelope", type=Path, required=True)
    verify.add_argument("--trust", type=Path, required=True)
    verify.add_argument("--at", required=True, help="explicit evaluation time")

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
