"""Adapters implement and register the executable checks.

Importing this package registers every check. There is no plugin discovery: a check exists
because one of the modules below registers it.
"""

from dppce.adapters import access, api, carrier, data, gs1, identifier, integrity, lifecycle, manual, resolver
from dppce.adapters.capabilities import manifest

__all__ = [
    "access",
    "api",
    "carrier",
    "data",
    "gs1",
    "identifier",
    "integrity",
    "lifecycle",
    "manifest",
    "manual",
    "resolver",
]
