"""Family modules of the reference system.

The core in ``dppce.infrastructure.reference_server`` serves the battery passport routes. A
family module adds the behavior of one implementation family, for example a resolver, a
credential issuer, a DID document, or an AAS server. All behavior is synthetic and loopback only.

Contract of a family module (``base.Family``):

- ``FLAGS: Final[frozenset[str]]``: the fault flags that the module owns. A flag name is in
  exactly one place: the core set or one family.
- ``respond(system, request) -> Reply | None``: the answer to a ``GET`` or ``HEAD`` request
  that the module serves, or ``None`` to pass the request on. ``system`` is the
  ``ReferenceSystem``. ``system.faults`` holds the active flags, and ``system.handle`` gives
  the core answer. ``request`` is a ``base.Request``. Return the body of a ``GET``: the server
  drops it for ``HEAD``. The module never changes state: the reference system has no write
  operation.

The reference system asks each family in ``FAMILIES`` order, before the core. Under
``deny_all`` no family is asked. A family must not change the answer to a request of the
version 1 snapshot, unless one of its own flags is active. The snapshot holds each route of
each layout, each role, and each fault flag of version 1, for ``GET`` with no ``Accept`` header
or with ``Accept: */*``. ``tests/test_reference_system_v2.py`` checks the snapshot. A family may
add answers for other paths, queries, or ``Accept`` values.

To add a family: write ``reference/<name>.py`` and add one entry to ``FAMILIES``. The core
handler and the HTTP server do not change. Document each new flag in
``docs/reference/reference-system.md``, section 6.

A family answers paths of the reference layout. The alternate layout of the test rig maps only
the core routes.
"""

from __future__ import annotations

from typing import Final

from dppce.infrastructure.reference import credentials, did, jose, resolver
from dppce.infrastructure.reference.base import Family

FAMILIES: Final[tuple[Family, ...]] = (resolver, jose, credentials, did)
