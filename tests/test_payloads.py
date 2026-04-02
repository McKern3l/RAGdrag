"""Tests for RAGdrag payload loader utility."""

import pytest

from ragdrag.utils.payloads import list_payloads, load_payload, load_queries


class TestLoadPayload:
    def test_load_existing_payload(self):
        data = load_payload("fingerprint_rag_presence")
        assert isinstance(data, dict)
        assert "queries" in data or len(data) > 0

    def test_load_with_json_extension(self):
        data = load_payload("fingerprint_rag_presence.json")
        assert isinstance(data, dict)

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError):
            load_payload("nonexistent_payload_xyz")

    def test_load_embedding_model_payload(self):
        data = load_payload("fingerprint_embedding_model")
        assert isinstance(data, dict)


class TestListPayloads:
    def test_list_queries_dir(self):
        payloads = list_payloads("queries")
        assert len(payloads) > 0
        assert "fingerprint_rag_presence" in payloads

    def test_list_nonexistent_dir(self):
        payloads = list_payloads("nonexistent_subdir")
        assert payloads == []

    def test_returns_sorted(self):
        payloads = list_payloads("queries")
        assert payloads == sorted(payloads)


class TestLoadQueries:
    def test_load_queries_with_correct_key(self):
        queries = load_queries("fingerprint_rag_presence", key="knowledge_queries")
        assert isinstance(queries, list)
        assert len(queries) > 0

    def test_load_queries_default_key_empty_if_missing(self):
        """Default key 'queries' may not exist in all payloads."""
        queries = load_queries("fingerprint_rag_presence")
        assert isinstance(queries, list)

    def test_empty_key_returns_empty(self):
        """If the key doesn't exist in the payload, return empty list."""
        queries = load_queries("fingerprint_rag_presence", key="nonexistent_key")
        assert queries == []
