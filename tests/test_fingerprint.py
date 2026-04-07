"""Tests for R1 Fingerprint techniques (RD-0101, RD-0102).

Uses respx to mock httpx requests. Tests cover RAG presence detection
(latency, citations, retrieval failures, knowledge freshness) and
vector DB fingerprinting (error probing, endpoint scanning).
"""

import httpx
import pytest
import respx

from ragdrag.core.fingerprint import (
    FingerprintResult,
    _detect_citation_patterns,
    _detect_retrieval_failures,
    detect_knowledge_freshness,
    detect_rag_presence,
    fingerprint_vector_db,
    run_full_fingerprint,
)
from ragdrag.core.models import Finding


TARGET = "http://testrag.local/chat"


# --- FingerprintResult ---


class TestFingerprintResult:
    def test_default_fields(self):
        r = FingerprintResult(target=TARGET)
        assert r.rag_detected is False
        assert r.vector_db is None
        assert r.findings == []
        assert r.timing_stats is None

    def test_to_dict(self):
        r = FingerprintResult(target=TARGET, rag_detected=True, vector_db="chromadb")
        r.findings.append(Finding(
            technique_id="RD-0101",
            technique_name="Test",
            confidence="high",
            detail="test detail",
            evidence={"key": "val"},
        ))
        d = r.to_dict()
        assert d["target"] == TARGET
        assert d["rag_detected"] is True
        assert d["vector_db"] == "chromadb"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["technique_id"] == "RD-0101"


# --- Citation pattern detection ---


class TestCitationPatterns:
    def test_detects_according_to(self):
        hits = _detect_citation_patterns(["According to our documentation, the policy is..."])
        assert any("according to" in h for h in hits)

    def test_detects_source_reference(self):
        hits = _detect_citation_patterns(["The answer is yes. Source: internal-wiki"])
        assert any("source:" in h for h in hits)

    def test_detects_document_reference(self):
        hits = _detect_citation_patterns(["[doc 3] The procedure requires..."])
        assert len(hits) > 0

    def test_no_false_positive_on_plain_text(self):
        hits = _detect_citation_patterns(["Hello, I can help you with that."])
        assert hits == []


# --- Retrieval failure detection ---


class TestRetrievalFailures:
    def test_detects_no_relevant_documents(self):
        hits = _detect_retrieval_failures("No relevant documents found for that query.")
        assert len(hits) > 0

    def test_detects_outside_knowledge_base(self):
        hits = _detect_retrieval_failures("That's outside of my knowledge base.")
        assert len(hits) > 0

    def test_no_false_positive(self):
        hits = _detect_retrieval_failures("Here is the information you requested.")
        assert hits == []


# --- RD-0101: RAG Presence Detection ---


class TestDetectRagPresence:
    @respx.mock
    def test_detects_latency_delta(self):
        """High latency on knowledge queries vs general queries indicates RAG."""
        import time

        call_count = {"knowledge": 0, "general": 0}

        def slow_response(request):
            body = request.content.decode()
            if "policy" in body or "documentation" in body or "procedures" in body or "incident" in body or "onboarding" in body:
                call_count["knowledge"] += 1
                time.sleep(0.35)
                return httpx.Response(200, json={"answer": "Based on the documentation, the policy states..."})
            else:
                call_count["general"] += 1
                return httpx.Response(200, json={"answer": "4"})

        respx.post(TARGET).mock(side_effect=slow_response)
        client = httpx.Client()
        findings, k_stats, g_stats = detect_rag_presence(TARGET, client)
        client.close()

        assert k_stats.count == 5
        assert g_stats.count == 5
        # Should detect latency delta
        latency_findings = [f for f in findings if "Latency" in f.technique_name]
        assert len(latency_findings) >= 1

    @respx.mock
    def test_detects_citation_patterns_in_responses(self):
        """Responses with citations indicate RAG."""
        respx.post(TARGET).mock(return_value=httpx.Response(
            200,
            json={"answer": "According to our documentation, section 3.2 describes the procedure."},
        ))
        client = httpx.Client()
        findings, _, _ = detect_rag_presence(TARGET, client)
        client.close()

        citation_findings = [f for f in findings if "Citations" in f.technique_name]
        assert len(citation_findings) >= 1

    @respx.mock
    def test_detects_retrieval_failures(self):
        """Retrieval failure messages indicate RAG tried and failed."""
        respx.post(TARGET).mock(return_value=httpx.Response(
            200,
            json={"answer": "No relevant documents found for that query."},
        ))
        client = httpx.Client()
        findings, _, _ = detect_rag_presence(TARGET, client)
        client.close()

        failure_findings = [f for f in findings if "Retrieval Failures" in f.technique_name]
        assert len(failure_findings) >= 1

    @respx.mock
    def test_handles_connection_errors_gracefully(self):
        """HTTP errors during probing should not crash."""
        respx.post(TARGET).mock(side_effect=httpx.ConnectError("refused"))
        client = httpx.Client()
        findings, k_stats, g_stats = detect_rag_presence(TARGET, client)
        client.close()

        # Should still return results (with status_code 0 for failed requests)
        assert k_stats.count == 5
        assert g_stats.count == 5

    @respx.mock
    def test_custom_response_field(self):
        """Should extract text from a custom response field."""
        respx.post(TARGET).mock(return_value=httpx.Response(
            200,
            json={"result": "According to our records, the policy is updated quarterly."},
        ))
        client = httpx.Client()
        findings, _, _ = detect_rag_presence(
            TARGET, client, response_field="result",
        )
        client.close()

        citation_findings = [f for f in findings if "Citations" in f.technique_name]
        assert len(citation_findings) >= 1


# --- RD-0101: Knowledge Freshness ---


class TestKnowledgeFreshness:
    @respx.mock
    def test_detects_recent_dates(self):
        respx.post(TARGET).mock(return_value=httpx.Response(
            200,
            json={"answer": "The documentation was recently updated on March 2026."},
        ))
        client = httpx.Client()
        findings = detect_knowledge_freshness(TARGET, client)
        client.close()

        assert len(findings) >= 1
        assert findings[0].technique_id == "RD-0101"

    @respx.mock
    def test_no_finding_on_old_dates(self):
        respx.post(TARGET).mock(return_value=httpx.Response(
            200,
            json={"answer": "I was trained on data up to 2023."},
        ))
        client = httpx.Client()
        findings = detect_knowledge_freshness(TARGET, client)
        client.close()

        assert len(findings) == 0

    @respx.mock
    def test_handles_errors_gracefully(self):
        respx.post(TARGET).mock(side_effect=httpx.ConnectError("refused"))
        client = httpx.Client()
        findings = detect_knowledge_freshness(TARGET, client)
        client.close()

        assert findings == []


# --- RD-0102: Vector DB Fingerprinting ---


class TestFingerprintVectorDb:
    @respx.mock
    def test_detects_chromadb_in_errors(self):
        """Error responses mentioning ChromaDB should trigger a finding."""
        respx.post(TARGET).mock(return_value=httpx.Response(
            500,
            text="chromadb.errors.InvalidCollectionException: collection not found",
        ))
        # Mock port scans to fail (not testing that here)
        respx.route().mock(return_value=httpx.Response(500))
        client = httpx.Client()
        findings = fingerprint_vector_db(TARGET, client, scan_ports=False)
        client.close()

        db_names = [f.evidence.get("database") for f in findings]
        assert "chromadb" in db_names

    @respx.mock
    def test_detects_qdrant_in_errors(self):
        respx.post(TARGET).mock(return_value=httpx.Response(
            500,
            text='{"error": "qdrant: points_count mismatch"}',
        ))
        client = httpx.Client()
        findings = fingerprint_vector_db(TARGET, client, scan_ports=False)
        client.close()

        db_names = [f.evidence.get("database") for f in findings]
        assert "qdrant" in db_names

    @respx.mock
    def test_no_false_positives_on_clean_errors(self):
        respx.post(TARGET).mock(return_value=httpx.Response(
            400,
            text='{"error": "invalid input"}',
        ))
        client = httpx.Client()
        findings = fingerprint_vector_db(TARGET, client, scan_ports=False)
        client.close()

        assert len(findings) == 0

    @respx.mock
    def test_endpoint_scan_detects_open_service(self):
        """Accessible vector DB endpoints should be reported."""
        # Mock the error probes to return nothing useful
        respx.post(TARGET).mock(return_value=httpx.Response(400, text="bad request"))
        # Mock a ChromaDB heartbeat endpoint
        respx.get("http://testrag.local:8000/api/v1/heartbeat").mock(
            return_value=httpx.Response(200, json={"nanosecond heartbeat": 1234}),
        )
        # All other endpoints fail
        respx.route().mock(side_effect=httpx.ConnectError("refused"))

        client = httpx.Client()
        findings = fingerprint_vector_db(TARGET, client, scan_ports=True)
        client.close()

        endpoint_findings = [f for f in findings if "Endpoint Scan" in f.technique_name]
        assert len(endpoint_findings) >= 1

    @respx.mock
    def test_skip_port_scan(self):
        """scan_ports=False should skip endpoint scanning."""
        respx.post(TARGET).mock(return_value=httpx.Response(400, text="bad"))
        client = httpx.Client()
        findings = fingerprint_vector_db(TARGET, client, scan_ports=False)
        client.close()

        endpoint_findings = [f for f in findings if "Endpoint Scan" in f.technique_name]
        assert len(endpoint_findings) == 0


# --- run_full_fingerprint ---


class TestRunFullFingerprint:
    @respx.mock
    def test_full_run_aggregates_findings(self):
        """Full fingerprint run should combine RD-0101 and RD-0102 findings."""
        respx.post(TARGET).mock(return_value=httpx.Response(
            200,
            json={"answer": "According to our documentation from March 2026, the policy states..."},
        ))
        # Mock port scans to fail
        respx.route().mock(side_effect=httpx.ConnectError("refused"))

        client = httpx.Client()
        result = run_full_fingerprint(TARGET, client, scan_ports=False)
        client.close()

        assert isinstance(result, FingerprintResult)
        assert result.target == TARGET
        assert result.rag_detected is True
        assert result.timing_stats is not None
        assert "knowledge_queries" in result.timing_stats
        assert "general_queries" in result.timing_stats
        assert len(result.findings) >= 1

    @respx.mock
    def test_no_detection_on_empty_responses(self):
        """No RAG indicators should mean rag_detected=False."""
        respx.post(TARGET).mock(return_value=httpx.Response(200, text="OK"))
        respx.route().mock(side_effect=httpx.ConnectError("refused"))

        client = httpx.Client()
        result = run_full_fingerprint(TARGET, client, scan_ports=False)
        client.close()

        assert result.rag_detected is False
        assert result.vector_db is None
