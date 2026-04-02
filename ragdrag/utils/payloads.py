"""Payload loader for RAGdrag query and document templates.

Loads JSON payload files from ragdrag/payloads/ subdirectories.
Enables modules to use curated query sets instead of hardcoded lists,
and supports a future --payload CLI flag for custom query sets.
"""

from __future__ import annotations

import json
from pathlib import Path

_PAYLOADS_DIR = Path(__file__).resolve().parent.parent / "payloads"


def load_payload(name: str, subdirectory: str = "queries") -> dict:
    """Load a JSON payload file by name.

    Args:
        name: Payload filename (with or without .json extension).
        subdirectory: Subdirectory under payloads/ to search.
            Defaults to "queries".

    Returns:
        Parsed JSON as a dictionary.

    Raises:
        FileNotFoundError: If the payload file doesn't exist.
    """
    if not name.endswith(".json"):
        name = f"{name}.json"

    path = _PAYLOADS_DIR / subdirectory / name
    if not path.exists():
        raise FileNotFoundError(f"Payload not found: {path}")

    with open(path) as f:
        return json.load(f)


def list_payloads(subdirectory: str = "queries") -> list[str]:
    """List available payload files in a subdirectory.

    Args:
        subdirectory: Subdirectory under payloads/ to list.

    Returns:
        List of payload filenames (without .json extension).
    """
    subdir = _PAYLOADS_DIR / subdirectory
    if not subdir.exists():
        return []
    return sorted(p.stem for p in subdir.glob("*.json"))


def load_queries(name: str, key: str = "queries") -> list[str]:
    """Load just the query strings from a payload file.

    Convenience function that extracts the query text from the
    standard payload schema: {queries: [{query: "..."}, ...]}.

    Args:
        name: Payload filename.
        key: Top-level key containing the query list. Defaults to "queries".

    Returns:
        List of query strings.
    """
    payload = load_payload(name)
    items = payload.get(key, [])

    # Handle both flat string lists and structured query objects
    queries = []
    for item in items:
        if isinstance(item, str):
            queries.append(item)
        elif isinstance(item, dict) and "query" in item:
            queries.append(item["query"])
    return queries
