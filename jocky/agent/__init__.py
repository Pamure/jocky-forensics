"""
Central management (SIH26148): a TLS job server and the polling agents that
make a multi-host engagement auditable from one place.

* :mod:`jocky.agent.server` — job/finding store plus the HTTPS API and the
  ``jocky serve`` entry point.
* :mod:`jocky.agent.client` — ``jocky agent``, which enrols, polls, executes a
  job with the shared runtime and reports the result.

Both are imported lazily by the CLI so that neither side pulls in the other's
dependencies (in particular, an agent never needs the server module).
"""
from __future__ import annotations

__all__ = ["server", "client"]
