"""Error type for the capability-checks-first execution lab.

Every refusal the lab emits is a :class:`LabRefusal` and nothing else, so a
caller (or a test) can distinguish "the harness declined this action" from an
ordinary runtime failure inside a technique that was allowed to proceed.
"""
from __future__ import annotations

__all__ = ["LabRefusal"]


class LabRefusal(RuntimeError):
    """The harness declined an action; the message carries the reason."""
