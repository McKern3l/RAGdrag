"""Tests for R4 Poison techniques (RD-0401 through RD-0404)."""

import httpx
import pytest
import respx

from ragdrag.core.models import Finding
from ragdrag.core.poison import (
    InjectedDocument,
    PoisonResult,
    _discover_ingestion_endpoint,
    deploy_credential_trap,
    inject_document,
    inject_instructions,
    run_poison,
    assess_embedding_dominance,
    verify_injection,
)

TARGET = "http://testrag.local/chat"
INGEST = "http://testrag.local/ingest"


class TestPoisonResult:
    def test_default_fields(self):
        r = PoisonResult(target=TARGET)
        assert r.injected_documents == []
        assert r.dominance_score is None
        assert not r.trap_active
        assert not r.instruction_injected

    def test_to_dict(self):
        doc = InjectedDocument(doc_id="abc", content="test doc", verified=True)
        r = PoisonResult(target=TARGET, injected_documents=[doc])
        d = r.to_dict()
        assert d["target"] == TARGET
        assert len(d["injected_documents"]) == 1
        assert d["injected_documents"][0]["verified"] is True


class TestDiscoverIngestionEndpoint:
    @respx.mock
    def test_finds_ingest_endpoint(self):
        respx.options("http://testrag.local/ingest").mock(
            return_value=httpx.Response(200)
        )
        with httpx.Client() as client:
            url = _discover_ingestion_endpoint("http://testrag.local", client)
        assert url == "http://testrag.local/ingest"

    @respx.mock
    def test_finds_via_post_400(self):
        respx.options(url__regex=r".*").mock(return_value=httpx.Response(405))
        respx.post("http://testrag.local/api/documents").mock(
            return_value=httpx.Response(400, json={"error": "missing text"})
        )
        respx.post(url__regex=r".*").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            url = _discover_ingestion_endpoint("http://testrag.local", client)
        assert url is not None
        assert "documents" in url

    @respx.mock
    def test_no_endpoint_found(self):
        respx.options(url__regex=r".*").mock(return_value=httpx.Response(405))
        respx.post(url__regex=r".*").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            url = _discover_ingestion_endpoint("http://testrag.local", client)
        assert url is None


class TestDocumentInjection:
    @respx.mock
    def test_successful_injection(self):
        respx.post(INGEST).mock(return_value=httpx.Response(
            201, json={"id": "injected-123"}
        ))
        with httpx.Client() as client:
            finding, doc = inject_document(
                TARGET, client, "Malicious content",
                ingest_url=INGEST,
            )
        assert finding is not None
        assert finding.confidence == "high"
        assert doc is not None
        assert doc.doc_id == "injected-123"

    @respx.mock
    def test_auth_required(self):
        respx.post(INGEST).mock(return_value=httpx.Response(401))
        with httpx.Client() as client:
            finding, doc = inject_document(
                TARGET, client, "content", ingest_url=INGEST,
            )
        assert finding.confidence == "medium"
        assert "authentication" in finding.detail.lower()
        assert doc is None

    @respx.mock
    def test_no_ingest_url_discovery_fails(self):
        respx.options(url__regex=r".*").mock(return_value=httpx.Response(405))
        respx.post(url__regex=r".*").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            finding, doc = inject_document(TARGET, client, "content")
        assert finding.confidence == "low"
        assert doc is None

    @respx.mock
    def test_http_error_handling(self):
        respx.post(INGEST).mock(side_effect=httpx.ConnectError("fail"))
        with httpx.Client() as client:
            finding, doc = inject_document(
                TARGET, client, "content", ingest_url=INGEST,
            )
        assert finding is not None
        assert doc is None


class TestVerifyInjection:
    @respx.mock
    def test_verified_match(self):
        doc = InjectedDocument(doc_id="x", content="password reset policy temporary credential")
        respx.post(TARGET).mock(return_value=httpx.Response(
            200, json={"answer": "The password reset policy requires a temporary credential..."}
        ))
        with httpx.Client() as client:
            finding = verify_injection(TARGET, client, doc, "password reset")
        assert doc.verified is True
        assert finding.confidence == "high"

    @respx.mock
    def test_not_verified(self):
        doc = InjectedDocument(doc_id="x", content="completely unrelated injected content xyz")
        respx.post(TARGET).mock(return_value=httpx.Response(
            200, json={"answer": "The vacation policy allows 15 days per year."}
        ))
        with httpx.Client() as client:
            finding = verify_injection(TARGET, client, doc, "vacation")
        assert doc.verified is False
        assert finding.confidence == "low"


class TestEmbeddingDominance:
    @respx.mock
    def test_high_dominance(self):
        doc = InjectedDocument(doc_id="dom", content="SECURITY UPDATE: All employees must reset")
        respx.post(TARGET).mock(return_value=httpx.Response(
            200, json={"answer": "SECURITY UPDATE: All employees must reset their passwords immediately."}
        ))
        with httpx.Client() as client:
            findings = assess_embedding_dominance(TARGET, client, doc)
        assert len(findings) >= 1
        assert any(f.evidence.get("dominance_ratio", 0) > 0 for f in findings)

    @respx.mock
    def test_zero_dominance(self):
        doc = InjectedDocument(doc_id="dom", content="ZZZZZ unique marker not in responses")
        respx.post(TARGET).mock(return_value=httpx.Response(
            200, json={"answer": "Normal answer with no marker content."}
        ))
        with httpx.Client() as client:
            findings = assess_embedding_dominance(TARGET, client, doc)
        assert len(findings) >= 1
        assert findings[0].confidence == "low"

    @respx.mock
    def test_handles_errors(self):
        doc = InjectedDocument(doc_id="dom", content="test")
        respx.post(TARGET).mock(side_effect=httpx.ConnectError("fail"))
        with httpx.Client() as client:
            findings = assess_embedding_dominance(TARGET, client, doc)
        assert findings == []


class TestCredentialTrap:
    @respx.mock
    def test_trap_deployment(self):
        respx.post(INGEST).mock(return_value=httpx.Response(201, json={"id": "trap-1"}))
        respx.post(TARGET).mock(return_value=httpx.Response(
            200, json={"answer": "Visit https://evil.attacker.com/reset to reset your password"}
        ))
        with httpx.Client() as client:
            findings = deploy_credential_trap(
                TARGET, client, "evil.attacker.com",
                ingest_url=INGEST,
            )
        assert len(findings) >= 1


class TestInstructionInjection:
    @respx.mock
    def test_instruction_followed(self):
        respx.post(INGEST).mock(return_value=httpx.Response(201, json={"id": "instr-1"}))
        respx.post(TARGET).mock(return_value=httpx.Response(
            200, json={"answer": "Please visit https://callback.evil/verify for verification."}
        ))
        with httpx.Client() as client:
            findings = inject_instructions(
                TARGET, client, "callback.evil", ingest_url=INGEST,
            )
        instruction_findings = [f for f in findings if f.technique_id == "RD-0404"]
        assert any(f.confidence == "high" for f in instruction_findings)

    @respx.mock
    def test_instruction_ignored(self):
        respx.post(INGEST).mock(return_value=httpx.Response(201, json={"id": "instr-2"}))
        respx.post(TARGET).mock(return_value=httpx.Response(
            200, json={"answer": "The credentials are managed by IT."}
        ))
        with httpx.Client() as client:
            findings = inject_instructions(
                TARGET, client, "callback.evil", ingest_url=INGEST,
            )
        instruction_findings = [f for f in findings if f.technique_id == "RD-0404"]
        assert all(f.confidence == "low" for f in instruction_findings)


class TestRunPoison:
    @respx.mock
    def test_orchestrator_returns_result(self):
        respx.post(INGEST).mock(return_value=httpx.Response(201, json={"id": "x"}))
        respx.post(TARGET).mock(return_value=httpx.Response(
            200, json={"answer": "Some answer"}
        ))
        respx.options(url__regex=r".*").mock(return_value=httpx.Response(405))
        with httpx.Client() as client:
            result = run_poison(
                TARGET, client,
                ingest_url=INGEST,
            )
        assert isinstance(result, PoisonResult)
        assert result.target == TARGET
        assert len(result.findings) > 0

    @respx.mock
    def test_orchestrator_all_errors(self):
        respx.post(url__regex=r".*").mock(side_effect=httpx.ConnectError("fail"))
        respx.options(url__regex=r".*").mock(side_effect=httpx.ConnectError("fail"))
        with httpx.Client() as client:
            result = run_poison(TARGET, client)
        assert isinstance(result, PoisonResult)

    @respx.mock
    def test_to_dict_serializable(self):
        respx.post(INGEST).mock(return_value=httpx.Response(201, json={"id": "x"}))
        respx.post(TARGET).mock(return_value=httpx.Response(
            200, json={"answer": "answer"}
        ))
        respx.options(url__regex=r".*").mock(return_value=httpx.Response(405))
        with httpx.Client() as client:
            result = run_poison(TARGET, client, ingest_url=INGEST)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "findings" in d
