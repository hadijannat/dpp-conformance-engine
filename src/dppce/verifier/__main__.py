"""Run the verifier without the rest of the engine: ``python -m dppce.verifier``.

Exit status: 0 if the verification is complete, 4 if it failed or is incomplete, 2 on bad input.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from dppce.evidence.canonical import parse_strict
from dppce.evidence.status import MAX_TOKEN_BYTES
from dppce.migrations import migrate
from dppce.models import TrustBundle
from dppce.verifier.verify import verify_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dppce.verifier", description=__doc__)
    parser.add_argument("envelope", type=Path, help="evidence envelope (JSON)")
    parser.add_argument("--trust", type=Path, required=True, help="explicit trust bundle (JSON)")
    parser.add_argument("--at", required=True, help="evaluation time, for example 2026-10-13T12:00:00Z")
    parser.add_argument(
        "--status-list", type=Path, help="signed status list file of the report issuer; nothing is fetched"
    )
    args = parser.parse_args(argv)
    status_list: bytes | None = None
    try:
        raw = args.envelope.read_bytes()
        document = parse_strict(args.trust.read_bytes())
        if not isinstance(document, dict):
            raise ValueError(f"TRUST.BUNDLE.NOT_OBJECT: {args.trust} is not a JSON object")
        # A dppce.trust/1 bundle is migrated. A MigrationError is a ValueError: exit status 2.
        trust = TrustBundle.model_validate(migrate("trust", document))
        at = datetime.strptime(args.at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        if args.status_list is not None:
            with args.status_list.open("rb") as handle:
                # One byte over the limit is enough for the verifier to refuse the file.
                status_list = handle.read(MAX_TOKEN_BYTES + 1)
    except ValidationError as exc:
        # The first message carries the reason code, for example TRUST.KEY.ROLE_CONFLICT.
        print(f"error: {str(exc.errors()[0]['msg']).removeprefix('Value error, ')}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"error: {str(exc).splitlines()[0]}", file=sys.stderr)
        return 2
    report = verify_json(raw, trust, at, status_list=status_list)
    print(report.model_dump_json(indent=2))
    return 0 if report.complete else 4


if __name__ == "__main__":
    sys.exit(main())
