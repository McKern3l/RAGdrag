"""Shared data structures for RAGdrag phase modules.

All phase result classes and the shared Finding dataclass live here
to prevent circular imports as the number of phase modules grows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, get_args

Confidence = Literal["high", "medium", "low"]
VALID_CONFIDENCE: tuple[str, ...] = get_args(Confidence)


@dataclass
class Finding:
    """A single finding from any RAGdrag phase.

    Every finding maps to a technique in the RAGdrag taxonomy (RD-XXXX)
    and carries structured evidence for reproducibility.
    """

    technique_id: str
    technique_name: str
    confidence: Confidence
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.confidence not in VALID_CONFIDENCE:
            raise ValueError(
                f"Invalid confidence {self.confidence!r}; "
                f"must be one of {VALID_CONFIDENCE}"
            )
