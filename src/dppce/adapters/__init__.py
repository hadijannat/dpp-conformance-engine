"""Adapters implement and register the executable checks.

Importing this package registers every check. There is no plugin discovery: a check exists
because one of the modules below registers it.
"""

from dppce.adapters import (
    aas,
    access,
    api,
    carrier,
    data,
    did,
    gs1,
    identifier,
    integrity,
    jose,
    lifecycle,
    manual,
    negotiation,
    resolver,
    status_list,
)
from dppce.adapters.capabilities import manifest

__all__ = [
    "aas",
    "access",
    "api",
    "carrier",
    "data",
    "did",
    "gs1",
    "identifier",
    "integrity",
    "jose",
    "lifecycle",
    "manifest",
    "manual",
    "negotiation",
    "resolver",
    "status_list",
]
