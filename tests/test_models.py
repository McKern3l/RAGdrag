"""Tests for shared RAGdrag data structures."""

import pytest

from ragdrag.core.models import VALID_CONFIDENCE, Finding


class TestFinding:
    def test_basic_creation(self):
        f = Finding(
            technique_id="RD-0201",
            technique_name="Chunk Boundary Detection",
            confidence="high",
            detail="Detected fixed top-k=3",
        )
        assert f.technique_id == "RD-0201"
        assert f.confidence == "high"

    def test_evidence_default_empty(self):
        f = Finding("RD-0201", "test", "high", "detail")
        assert f.evidence == {}

    def test_evidence_with_data(self):
        evidence = {"source_counts": [3, 3, 3], "estimated_top_k": 3}
        f = Finding("RD-0203", "Retrieval Count", "high", "Fixed top-k", evidence=evidence)
        assert f.evidence["estimated_top_k"] == 3
        assert len(f.evidence["source_counts"]) == 3

    def test_all_confidence_levels(self):
        for level in ("high", "medium", "low"):
            f = Finding("RD-0201", "test", level, "detail")
            assert f.confidence == level

    def test_finding_equality(self):
        f1 = Finding("RD-0201", "test", "high", "detail")
        f2 = Finding("RD-0201", "test", "high", "detail")
        assert f1 == f2

    def test_finding_inequality(self):
        f1 = Finding("RD-0201", "test", "high", "detail A")
        f2 = Finding("RD-0201", "test", "high", "detail B")
        assert f1 != f2

    def test_rejects_invalid_confidence(self):
        """Typos like 'hgih' or 'High' must fail at construction, not silently serialize."""
        for bad in ("High", "HIGH", "hgih", "confidence", "critical", "", None):
            with pytest.raises(ValueError, match="Invalid confidence"):
                Finding("RD-0201", "test", bad, "detail")

    def test_valid_confidence_tuple_matches_literal(self):
        """VALID_CONFIDENCE must stay in lockstep with the Literal type alias."""
        assert VALID_CONFIDENCE == ("high", "medium", "low")
