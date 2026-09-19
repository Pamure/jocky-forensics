"""
Loopback channel transports for the pillar-4 wire protocols (SIH26148).

Domain fronting is dead on tier-1 CDNs, so pillar 4's working transports are
a control channel smuggled through trusted DNS resolvers and a relayed
websocket for bulk traffic.  Both implementations here are real protocol
cores bound to loopback only: they become operational transports the moment
an operator attaches a real authoritative zone or a real relay worker.

* :mod:`jocky.agent.channel.dns_txt` — job delivery as TXT answers to
  ``<job-id>.jky.<zone>`` TXT queries, implemented with stdlib sockets and
  ``struct`` only.
* :mod:`jocky.agent.channel.ws_relay` — a minimal RFC 6455 text-frame
  websocket relay (handshake, masking, close) with no dependencies.
"""
from __future__ import annotations

__all__ = ["dns_txt", "ws_relay"]
