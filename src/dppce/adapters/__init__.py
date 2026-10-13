"""Adapters implement and register the executable checks.

Importing this package registers every check. There is no plugin discovery.
"""

from dppce.adapters.capabilities import manifest

__all__ = ["manifest"]
