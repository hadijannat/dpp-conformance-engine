"""A local test rig: the reference system plus the declarations that a run needs.

The rig starts the synthetic reference system on a free loopback port, writes an IXIT that
points at it, issues a test authorization for that origin with the TEST-ONLY owner key, and
drives the engine through its command-line entry point. Nothing here reaches another host.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import urlsplit

import yaml

from dppce.catalogue import load_testpacks
from dppce.cli import main
from dppce.evidence.canonical import digest
from dppce.evidence.jws import LocalSigner
from dppce.evidence.manual import declared_sut_version, issue_manual_result
from dppce.infrastructure.authorization import issue_authorization
from dppce.infrastructure.reference_server import ReferenceServer, ReferenceSystem, Reply
from dppce.models import Authorization, EvidenceEnvelope, ManualResult, SutIdentity

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures" / "reference"
TRUST = FIXTURES / "trust" / "TEST-ONLY-trust-bundle.json"
REPORT_KEY = FIXTURES / "trust" / "TEST-ONLY-report-signing.key.pem"
REPORT_KID = "TEST-ONLY-report-key-1"
MANUAL_KEY = FIXTURES / "trust" / "TEST-ONLY-manual-signing.key.pem"
MANUAL_KID = "TEST-ONLY-manual-key-1"
# Before DEFAULT_AT. A manual result here describes the synthetic reference system only.
MANUAL_PERFORMED_AT = "2026-10-13T08:00:00Z"
LAB = "urn:example:test-lab"
DEFAULT_AT = "2026-10-13T12:00:00Z"
# Nothing listens here, so a connection is refused at once.
UNREACHABLE_ORIGIN = "http://127.0.0.1:1"
_ROLES = ("legitimate_interest", "authority")

# -- a second URL layout (gap D3-01, criterion 3) -----------------------------------------------

_ALT_ITEM: Final = re.compile(
    r"^/passports/(?P<gtin>[0-9]{14})/(?P<serial>[A-Za-z0-9]+)"
    r"/(?P<what>data|model-data|jws|history|export|view)$"
)
_ALT_LOOKUP: Final = re.compile(r"^/lookup/(?P<gtin>[0-9]{14})/(?P<serial>[A-Za-z0-9]+)$")
_ALT_RESOLVER: Final = re.compile(r"^/01/[0-9]{14}/21/[A-Za-z0-9]+$")
_REFERENCE_ITEM: Final = re.compile(r"^/dpp/(?P<gtin>[0-9]{14})-(?P<serial>[A-Za-z0-9]+)$")
_SUFFIX: Final = {
    "data": "",
    "model-data": "/model",
    "jws": "/signed",
    "history": "/versions",
    "export": "/export",
    "view": ".html",
}
_ALT_PATHS: Final = {
    "/dpp/{id}": "/passports/{gtin}/{serial}/data",
    "/dpp/{id}/model": "/passports/{gtin}/{serial}/model-data",
}
_ALT_CHANNELS: Final = {
    "fetch": "/passports/{gtin}/{serial}/data",
    "export": "/passports/{gtin}/{serial}/export",
    "search": "/find?q={serial}",
    "error": "/passports/{gtin}/{serial}/missing",
    "html": "/passports/{gtin}/{serial}/view",
}
_ALT_IXIT: Final[dict[str, Any]] = {
    "resources": {
        "item": {"endpoint": "api", "path": "/passports/{gtin}/{serial}/data"},
        "model": {"endpoint": "api", "path": "/passports/{gtin}/{serial}/model-data"},
        "signed": {"endpoint": "api", "path": "/passports/{gtin}/{serial}/jws"},
        "versions": {"endpoint": "api", "path": "/passports/{gtin}/{serial}/history"},
        "registry_record": {"endpoint": "registry", "path": "/lookup/{gtin}/{serial}"},
    },
    "id_parts": {"separator": ".", "names": ["gtin", "serial"]},
}
CONTRACT: Final = Path("profiles/battery/contracts/reference-api.openapi.yaml")
POLICY: Final = Path("profiles/battery/access/reference-policy.yaml")


class AlternateLayout(ReferenceSystem):
    """The reference system under a different URL layout. Test use only, on loopback.

    Each alternate path maps to one reference path. Every other path, each reference path
    included, is not found. The resolver path does not change.
    """

    def handle(self, target: str, authorization: str | None) -> Reply:
        parts = urlsplit(target)
        path = parts.path
        if _ALT_RESOLVER.match(path):
            status, media_type, body, headers = super().handle(target, authorization)
            moved = _REFERENCE_ITEM.match(headers.get("Location", ""))
            if moved is not None:
                headers = {**headers, "Location": f"/passports/{moved['gtin']}/{moved['serial']}/data"}
            return status, media_type, body, headers
        if (item := _ALT_ITEM.match(path)) is not None:
            reference = f"/dpp/{item['gtin']}-{item['serial']}{_SUFFIX[item['what']]}"
            return super().handle(reference, authorization)
        if (lookup := _ALT_LOOKUP.match(path)) is not None:
            return super().handle(f"/registry/{lookup['gtin']}-{lookup['serial']}", authorization)
        if path == "/find":
            return super().handle("/search" + (f"?{parts.query}" if parts.query else ""), authorization)
        return self.not_found(path)


def _alternate_data(data: Path) -> None:
    """Rewrite the copied contract and policy for the alternate layout."""
    contract_file = data / CONTRACT
    contract = yaml.safe_load(contract_file.read_text(encoding="utf-8"))
    # Each path item moves unchanged, so its x-dppce-resource marker moves with it.
    contract["paths"] = {_ALT_PATHS.get(key, key): item for key, item in contract["paths"].items()}
    contract["x-dppce-contract-id"] = "battery/alternate-api"
    contract_file.write_text(yaml.safe_dump(contract, sort_keys=False), encoding="utf-8")
    policy_file = data / POLICY
    policy = yaml.safe_load(policy_file.read_text(encoding="utf-8"))
    policy["channels"] = dict(_ALT_CHANNELS)
    policy["policy_id"] = "battery/alternate-policy"
    policy_file.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    summary: dict[str, Any]
    run_dir: Path
    envelope: EvidenceEnvelope

    def step(self, test_purpose_id: str) -> dict[str, str]:
        result = next(t for t in self.envelope.decision.test_results if t.test_purpose_id == test_purpose_id)
        return {
            "verdict": result.verdict.value,
            "reason_code": result.reason_code,
            "status": result.execution_status.value,
        }

    def requirement(self, requirement_id: str) -> str:
        return next(
            r.verdict.value
            for r in self.envelope.decision.requirement_results
            if r.requirement_id == requirement_id
        )


def _merge(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in changes.items():
        out[key] = (
            _merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else value
        )
    return out


def _cli(arguments: list[str]) -> tuple[int, Any]:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = main([*arguments, "--json"])
    text = captured.getvalue().strip()
    return code, json.loads(text) if text else None


class ReferenceRig:
    """One configured rig. Use it as a context manager so that the server stops."""

    def __init__(
        self,
        work: Path,
        profile: str = "ev",
        *,
        faults: frozenset[str] = frozenset(),
        ics_changes: dict[str, Any] | None = None,
        ixit_changes: dict[str, Any] | None = None,
        qr: str | None = None,
        serve: bool = True,
        layout: Literal["reference", "alternate"] = "reference",
        data_root: Path | None = None,
        manual: Mapping[str, Literal["pass", "fail"]] | None = None,
    ) -> None:
        self.work = work
        self.profile = profile
        self._manual = dict(manual or {})
        self._manual_files: list[Path] = []
        self._ics_changes = ics_changes or {}
        self._ixit_changes = ixit_changes or {}
        self._qr = qr or profile
        self._alternate = layout == "alternate"
        system = AlternateLayout(FIXTURES, faults) if self._alternate else None
        self._server = ReferenceServer(FIXTURES, faults=faults, system=system) if serve else None
        self.data_root = data_root or (work / "data" if self._alternate else ROOT)
        self._runs = 0

    def _data_arguments(self) -> list[str]:
        return [] if self.data_root == ROOT else ["--data-root", str(self.data_root)]

    def __enter__(self) -> ReferenceRig:
        if self._server is not None:
            self._server.start()
        origin = self._server.origin if self._server is not None else UNREACHABLE_ORIGIN
        self.origin = origin
        rig = self.work / "rig"
        shutil.copytree(FIXTURES / "qr", rig / "qr")
        ixit = yaml.safe_load((FIXTURES / f"{self.profile}.ixit.yaml").read_text(encoding="utf-8"))
        ixit["endpoints"]["origin_override"] = origin
        ixit["samples"]["qr_image"] = f"qr/{self._qr}.png"
        ics = yaml.safe_load((FIXTURES / f"{self.profile}.ics.yaml").read_text(encoding="utf-8"))
        if self._alternate:
            if not (self.data_root / CONTRACT).exists():
                for name in ("catalogue", "profiles", "testpacks"):
                    shutil.copytree(ROOT / name, self.data_root / name)
            _alternate_data(self.data_root)
            ixit |= _ALT_IXIT
            ixit["samples"]["passport_id"] = ixit["samples"]["passport_id"].replace("-", ".", 1)
            alternate_ids = {
                "api": {"contract": "battery/alternate-api"},
                "access": {"policy": "battery/alternate-policy"},
            }
            ics = _merge(ics, alternate_ids)
        ics = _merge(ics, self._ics_changes)
        ixit = _merge(ixit, self._ixit_changes)
        (rig / "ixit.yaml").write_text(yaml.safe_dump(ixit, sort_keys=False), encoding="utf-8")
        (rig / "ics.yaml").write_text(yaml.safe_dump(ics, sort_keys=False), encoding="utf-8")
        owner = LocalSigner.from_pem(
            FIXTURES / "authorization" / "TEST-ONLY-owner.key.pem", "TEST-ONLY-owner-key-1"
        )
        authorization = Authorization(
            schema_version="dppce.authorization/1",
            authorization_id="TEST-ONLY-rig-authorization",
            issuer="urn:example:operator:0001",
            subject=LAB,
            sut_identifier=ics["sut"]["identifier"],
            endpoints=(origin,),
            methods=("GET",),
            roles=("anonymous", *_ROLES),
            scopes=("read", "access_probe"),
            not_before="2026-01-01T00:00:00Z",
            not_after="2036-01-01T00:00:00Z",
            max_requests=1000,
        )
        (rig / "authorization").mkdir()
        token = issue_authorization(authorization, owner)
        (rig / "authorization" / "TEST-ONLY-authorization.jws").write_text(token + "\n", encoding="ascii")
        self._rig = rig
        self._write_manual_results(rig, SutIdentity.model_validate(ics["sut"]))
        return self

    def _write_manual_results(self, rig: Path, sut: SutIdentity) -> None:
        """Sign a TEST-ONLY manual result for each named step of the synthetic reference system."""
        if not self._manual:
            return
        purposes = {p.id: p for pack in load_testpacks(self.data_root).values() for p in pack.test_purposes}
        signer = LocalSigner.from_pem(MANUAL_KEY, MANUAL_KID)
        (rig / "manual").mkdir()
        for number, (ident, outcome) in enumerate(sorted(self._manual.items()), start=1):
            result = ManualResult(
                schema_version="dppce.manualresult/1",
                test_purpose_id=ident,
                test_purpose_digest=digest(purposes[ident]),
                sut_identifier=sut.identifier,
                sut_version=declared_sut_version(sut),
                role="inspector",
                performed_at=MANUAL_PERFORMED_AT,
                outcome=outcome,
                evidence=purposes[ident].expected_evidence,
            )
            path = rig / "manual" / f"TEST-ONLY-manual-{number}.jws"
            path.write_text(issue_manual_result(result, signer) + "\n", encoding="ascii")
            self._manual_files.append(path)

    def __exit__(self, *exc: object) -> None:
        if self._server is not None:
            self._server.stop()

    def run(
        self,
        mode: str = "illustrative",
        at: str = DEFAULT_AT,
        extra: Sequence[str] = (),
        *,
        create_data_key: bool = True,
    ) -> RunResult:
        """Run the engine. It reads the envelope, so use it only for a run that writes one."""
        self._runs += 1
        out = self.work / f"run-{self._runs}"
        arguments = self.run_arguments(out, mode, at)
        if create_data_key:
            arguments.append("--create-data-key")
        code, summary = _cli([*arguments, *extra])
        envelope = EvidenceEnvelope.model_validate_json((out / "envelope.json").read_bytes())
        return RunResult(code, summary, out, envelope)

    def run_arguments(self, out: Path, mode: str = "illustrative", at: str = DEFAULT_AT) -> list[str]:
        """The arguments of ``dppce run`` for this rig, without --create-data-key."""
        arguments = [
            "run",
            "--profile", f"battery/{self.profile}",
            "--ics", str(self._rig / "ics.yaml"),
            "--ixit", str(self._rig / "ixit.yaml"),
            "--mode", mode,
            "--trust", str(TRUST),
            "--at", at,
            "--out", str(out),
            "--keys", str(self.work / "keys"),
            "--secrets", str(FIXTURES / "secrets"),
            "--allow-private-host", self.origin,
            "--issuer-name", "dppce test rig (synthetic)",
            "--issuer-id", LAB,
            *self._data_arguments(),
        ]  # fmt: skip
        for role in _ROLES:
            arguments += ["--role-secret", f"{role}=file:TEST-ONLY-{role}.token"]
        for path in self._manual_files:
            arguments += ["--manual-result", str(path)]
        return arguments

    def replay(self, run: RunResult, times: int = 1) -> tuple[int, dict[str, Any]]:
        arguments = [
            "replay",
            "--run", str(run.run_dir),
            "--keys", str(self.work / "keys"),
            "--times", str(times),
            *self._data_arguments(),
        ]  # fmt: skip
        return _cli(arguments)

    def sign(self, run: RunResult) -> Path:
        envelope = run.run_dir / "envelope.json"
        code, _ = _cli(
            [
                "sign",
                "--envelope",
                str(envelope),
                "--key",
                str(REPORT_KEY),
                "--kid",
                REPORT_KID,
                "--issuer",
                LAB,
                # The fixture key is a TEST-ONLY key and is not encrypted.
                "--allow-unencrypted-key",
                "--in-place",
            ]
        )
        if code != 0:
            raise RuntimeError(f"signing failed with exit code {code}")
        return envelope

    def verify(self, envelope: Path, at: str = "2026-10-14T00:00:00Z") -> tuple[int, dict[str, Any]]:
        return _cli(["verify", "--envelope", str(envelope), "--trust", str(TRUST), "--at", at])
