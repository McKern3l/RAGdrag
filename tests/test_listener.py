"""Tests for the credential capture listener and TLS helper."""

import subprocess
from unittest.mock import patch

import pytest

from ragdrag.core.listener import OpenSSLUnavailable, generate_self_signed_cert


class TestOpenSSLWrapping:
    def test_missing_openssl_raises_friendly_error(self, tmp_path):
        """If openssl is not on PATH, the error should guide the operator, not raise FileNotFoundError."""
        with patch("ragdrag.core.listener.subprocess.run", side_effect=FileNotFoundError()):
            with pytest.raises(OpenSSLUnavailable, match="openssl not found"):
                generate_self_signed_cert(cert_dir=str(tmp_path))

    def test_openssl_failure_surfaces_stderr(self, tmp_path):
        """If openssl fails (e.g., permission denied), stderr should be surfaced."""
        err = subprocess.CalledProcessError(returncode=1, cmd="openssl", stderr=b"no write permission")
        with patch("ragdrag.core.listener.subprocess.run", side_effect=err):
            with pytest.raises(OpenSSLUnavailable, match="no write permission"):
                generate_self_signed_cert(cert_dir=str(tmp_path))

    def test_openssl_success_returns_paths(self, tmp_path):
        """Happy path: successful openssl run returns cert/key paths in cert_dir."""
        with patch("ragdrag.core.listener.subprocess.run") as m:
            m.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            cert_path, key_path = generate_self_signed_cert(cert_dir=str(tmp_path))
            assert cert_path.endswith("cert.pem")
            assert key_path.endswith("key.pem")
            assert str(tmp_path) in cert_path
            assert str(tmp_path) in key_path
