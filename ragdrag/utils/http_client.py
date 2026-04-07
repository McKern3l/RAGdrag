"""Shared HTTP client configuration for RAGdrag."""

from __future__ import annotations

import httpx

from ragdrag import __version__

DEFAULT_TIMEOUT = 30.0
DEFAULT_HEADERS = {
    "User-Agent": f"ragdrag/{__version__}",
}


def build_client(
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
    verify_ssl: bool = True,
) -> httpx.Client:
    """Build a configured httpx client."""
    merged_headers = {**DEFAULT_HEADERS}
    if headers:
        merged_headers.update(headers)
    return httpx.Client(
        timeout=timeout,
        headers=merged_headers,
        verify=verify_ssl,
        follow_redirects=True,
    )


def build_async_client(
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
    verify_ssl: bool = True,
) -> httpx.AsyncClient:
    """Build a configured async httpx client."""
    merged_headers = {**DEFAULT_HEADERS}
    if headers:
        merged_headers.update(headers)
    return httpx.AsyncClient(
        timeout=timeout,
        headers=merged_headers,
        verify=verify_ssl,
        follow_redirects=True,
    )
