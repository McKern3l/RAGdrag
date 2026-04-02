"""Shared data structures for RAGdrag phase modules.

All phase result classes and the shared Finding dataclass live here
to prevent circular imports as the number of phase modules grows.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single finding from any RAGdrag phase.

    Every finding maps to a technique in the RAGdrag taxonomy (RD-XXXX)
    and carries structured evidence for reproducibility.
    """

    technique_id: str
    technique_name: str
    confidence: str  # "high", "medium", "low"
    detail: str
    evidence: dict = field(default_factory=dict)
