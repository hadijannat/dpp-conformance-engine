"""Standalone report verification. Never imports the orchestrator, the adapters, or the transport."""

from dppce.verifier.verify import verify, verify_json

__all__ = ["verify", "verify_json"]
