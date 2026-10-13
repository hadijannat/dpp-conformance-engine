"""A local test rig: the reference system plus the declarations that a run needs.

The rig starts the synthetic reference system on a free loopback port, writes an IXIT that
points at it, issues a test authorization for that origin with the TEST-ONLY owner key, and
drives the engine through its command-line entry point. Nothing here reaches another host.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from dppce.cli import main
from dppce.evidence.jws import LocalSigner
from dppce.infrastructure.authorization import issue_authorization
from dppce.infrastructure.reference_server import ReferenceServer
from dppce.models import Authorization, EvidenceEnvelope

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures" / "reference"
TRUST = FIXTURES / "trust" / "TEST-ONLY-trust-bundle.json"
REPORT_KEY = FIXTURES / "trust" / "TEST-ONLY-report-signing.key.pem"
REPORT_KID = "TEST-ONLY-report-key-1"
LAB = "urn:example:test-lab"
DEFAULT_AT = "2026-10-13T12:00:00Z"
# Nothing listens here, so a connection is refused at once.
UNREACHABLE_ORIGIN = "http://127.0.0.1:1"
_ROLES = ("legitimate_interest", "authority")


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
        qr: str | None = None,
        serve: bool = True,
    ) -> None:
        self.work = work
        self.profile = profile
        self._ics_changes = ics_changes or {}
        self._qr = qr or profile
        self._server = ReferenceServer(FIXTURES, faults=faults) if serve else None
        self._runs = 0

    def __enter__(self) -> ReferenceRig:
        if self._server is not None:
            self._server.start()
        origin = self._server.origin if self._server is not None else UNREACHABLE_ORIGIN
        rig = self.work / "rig"
        shutil.copytree(FIXTURES / "qr", rig / "qr")
        ixit = yaml.safe_load((FIXTURES / f"{self.profile}.ixit.yaml").read_text(encoding="utf-8"))
        ixit["endpoints"]["origin_override"] = origin
        ixit["samples"]["qr_image"] = f"qr/{self._qr}.png"
        (rig / "ixit.yaml").write_text(yaml.safe_dump(ixit, sort_keys=False), encoding="utf-8")
        ics = yaml.safe_load((FIXTURES / f"{self.profile}.ics.yaml").read_text(encoding="utf-8"))
        (rig / "ics.yaml").write_text(
            yaml.safe_dump(_merge(ics, self._ics_changes), sort_keys=False), encoding="utf-8"
        )
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
        return self

    def __exit__(self, *exc: object) -> None:
        if self._server is not None:
            self._server.stop()

    def run(self, mode: str = "illustrative", at: str = DEFAULT_AT) -> RunResult:
        self._runs += 1
        out = self.work / f"run-{self._runs}"
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
            "--allow-private-host", "127.0.0.1",
            "--issuer-name", "dppce test rig (synthetic)",
            "--issuer-id", LAB,
        ]  # fmt: skip
        for role in _ROLES:
            arguments += ["--role-secret", f"{role}=file:TEST-ONLY-{role}.token"]
        code, summary = _cli(arguments)
        envelope = EvidenceEnvelope.model_validate_json((out / "envelope.json").read_bytes())
        return RunResult(code, summary, out, envelope)

    def replay(self, run: RunResult, times: int = 1) -> tuple[int, dict[str, Any]]:
        return _cli(
            ["replay", "--run", str(run.run_dir), "--keys", str(self.work / "keys"), "--times", str(times)]
        )

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
            ]
        )
        if code != 0:
            raise RuntimeError(f"signing failed with exit code {code}")
        return envelope

    def verify(self, envelope: Path, at: str = "2026-10-14T00:00:00Z") -> tuple[int, dict[str, Any]]:
        return _cli(["verify", "--envelope", str(envelope), "--trust", str(TRUST), "--at", at])
