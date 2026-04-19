"""Latency measurement utilities for RAG fingerprinting.

Used by R1 techniques (RD-0101) to detect RAG presence through
response timing analysis.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TimingResult:
    """Result of a timed HTTP request."""

    url: str
    query: str
    elapsed_ms: float
    status_code: int
    response_text: str = ""


@dataclass
class TimingStats:
    """Aggregate timing statistics from multiple requests."""

    results: list[TimingResult] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.results)

    @property
    def mean_ms(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.elapsed_ms for r in self.results) / len(self.results)

    @property
    def min_ms(self) -> float:
        if not self.results:
            return 0.0
        return min(r.elapsed_ms for r in self.results)

    @property
    def max_ms(self) -> float:
        if not self.results:
            return 0.0
        return max(r.elapsed_ms for r in self.results)

    @property
    def delta_ms(self) -> float:
        return self.max_ms - self.min_ms

    def add(self, result: TimingResult) -> None:
        self.results.append(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "mean_ms": round(self.mean_ms, 2),
            "min_ms": round(self.min_ms, 2),
            "max_ms": round(self.max_ms, 2),
            "delta_ms": round(self.delta_ms, 2),
        }


def measure_elapsed(start: float) -> float:
    """Return elapsed milliseconds since start."""
    return (time.monotonic() - start) * 1000
