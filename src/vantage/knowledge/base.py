"""RequestKnowledgeBase - what has already been tested this scan.

Engines share what they have covered so the planner and adapters can avoid
re-testing the same (endpoint, method, parameter, test-class) tuple. This is
what lets multiple engines cooperate without duplicating traffic.

The canonical key normalizes the endpoint the same way correlation does, so a
family of per-id URLs counts as one coverage entry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vantage.findings.correlation import normalize_endpoint


def coverage_key(host: str, port: int, path: str, method: str, parameter: str | None) -> str:
    return "|".join(
        [host.lower(), str(port), normalize_endpoint(path), method.upper(), parameter or "*"]
    )


@dataclass
class RequestKnowledgeBase:
    """In-memory coverage tracker for a single scan.

    A persistent variant lives in :mod:`vantage.persistence` via
    ``KnowledgeRepository``; this in-memory form is what engines consult during a
    run. The orchestrator flushes entries to the repository between stages.
    """

    _covered: dict[str, set[str]] = field(default_factory=dict)

    def mark(self, key: str, test_class: str) -> None:
        self._covered.setdefault(key, set()).add(test_class)

    def seen(self, key: str, test_class: str) -> bool:
        return test_class in self._covered.get(key, set())

    def should_test(self, key: str, test_class: str) -> bool:
        """Return True and record intent if this tuple has not been tested."""
        if self.seen(key, test_class):
            return False
        self.mark(key, test_class)
        return True

    def coverage(self) -> dict[str, set[str]]:
        return {k: set(v) for k, v in self._covered.items()}

    def __len__(self) -> int:
        return sum(len(v) for v in self._covered.values())
