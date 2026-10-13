"""Standalone report verification. Never imports the orchestrator, the adapters, or the transport."""

from dppce.verifier.verify import verify

__all__ = ["verify"]
