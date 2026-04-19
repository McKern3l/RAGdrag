"""Tests for CLI helpers, especially URL validation and normalization."""

import pytest
from click import BadParameter

from ragdrag.cli import _validate_url


class TestValidateUrl:
    def test_accepts_http(self):
        assert _validate_url("http://example.com") == "http://example.com"

    def test_accepts_https(self):
        assert _validate_url("https://example.com") == "https://example.com"

    def test_rejects_missing_scheme(self):
        with pytest.raises(BadParameter, match="must start with"):
            _validate_url("example.com")

    def test_rejects_ftp(self):
        with pytest.raises(BadParameter, match="must start with"):
            _validate_url("ftp://example.com")

    def test_rejects_empty_host(self):
        """'http://' alone used to slip through prefix-only validation."""
        with pytest.raises(BadParameter, match="missing host"):
            _validate_url("http://")

    def test_strips_trailing_slash(self):
        """Canonicalization: trailing slash on non-root paths is stripped."""
        assert _validate_url("https://example.com/api/") == "https://example.com/api"

    def test_preserves_root_slash(self):
        """Root path '/' should not be stripped to empty."""
        assert _validate_url("https://example.com/") == "https://example.com/"

    def test_drops_fragment(self):
        """Fragments don't travel over the wire; drop them during canonicalization."""
        assert _validate_url("https://example.com/api#anchor") == "https://example.com/api"

    def test_preserves_query_string(self):
        assert _validate_url("https://example.com/api?key=value") == "https://example.com/api?key=value"

    def test_preserves_port(self):
        assert _validate_url("http://example.com:8080/api") == "http://example.com:8080/api"

    def test_preserves_path(self):
        assert _validate_url("https://example.com/v1/query") == "https://example.com/v1/query"
