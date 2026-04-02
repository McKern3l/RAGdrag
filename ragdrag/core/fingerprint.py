"""R1: FINGERPRINT - Detect RAG presence and identify components.

Techniques:
    RD-0101: RAG Presence Detection
    RD-0102: Vector Database Fingerprinting
    RD-0103: Embedding Model Identification
    RD-0104: Ingestion Pipeline Mapping
    RD-0105: Document Loader Exploitation

ATLAS Tactic: Reconnaissance

This module implements RD-0101 and RD-0102 with operational functionality.
"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass, field

import httpx

from ragdrag.core.models import Finding
from ragdrag.utils.timing import TimingResult, TimingStats, measure_elapsed


# --- Data structures ---

# Re-export Finding so existing imports from ragdrag.core.fingerprint still work
__all__ = ["Finding", "FingerprintResult"]


@dataclass
class FingerprintResult:
    """Aggregate result of all fingerprint checks against a target."""

    target: str
    rag_detected: bool = False
    vector_db: str | None = None
    findings: list[Finding] = field(default_factory=list)
    timing_stats: dict | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "rag_detected": self.rag_detected,
            "vector_db": self.vector_db,
            "findings": [
                {
                    "technique_id": f.technique_id,
                    "technique_name": f.technique_name,
                    "confidence": f.confidence,
                    "detail": f.detail,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
            "timing_stats": self.timing_stats,
        }


# --- RD-0101: RAG Presence Detection ---

# Queries that target knowledge a RAG system would have but a base LLM wouldn't
KNOWLEDGE_QUERIES = [
    "What are your most recent policy updates?",
    "Can you show me the latest documentation changes?",
    "What internal procedures were updated this quarter?",
    "Tell me about the most recent security incident response.",
    "What are the current onboarding steps for new employees?",
]

# Generic queries that don't need RAG retrieval
GENERAL_QUERIES = [
    "What is 2 + 2?",
    "Say hello.",
    "What color is the sky?",
    "Count to five.",
    "What is the capital of France?",
]

# Patterns that indicate citation/sourcing behavior typical of RAG
CITATION_PATTERNS = [
    r"according to",
    r"based on (?:the |our )?(?:documentation|documents|records|files|knowledge base)",
    r"source:",
    r"reference:",
    r"\[(?:doc|document|source|ref)\s*[\d:]+\]",
    r"page\s+\d+",
    r"section\s+[\d.]+",
    r"(?:file|document)\s*:\s*\S+",
    r"as (?:stated|mentioned|described|documented) in",
    r"from the (?:knowledge base|database|documents|records)",
]

# Phrases that suggest retrieval failure (RAG tried and failed)
RETRIEVAL_FAILURE_PATTERNS = [
    r"no relevant (?:documents?|information|results?) (?:found|available)",
    r"i (?:don't|do not) have (?:access to|information about) that",
    r"(?:couldn't|could not) find (?:any )?(?:relevant |matching )?(?:documents?|information)",
    r"outside (?:of )?(?:my|the) (?:knowledge base|available documents)",
    r"no (?:matching |relevant )?(?:sources?|documents?) (?:were |was )?(?:found|retrieved)",
    r"i don't have (?:specific )?documents? (?:about|on|for) that",
]


def detect_rag_presence(
    target: str,
    client: httpx.Client,
    knowledge_queries: list[str] | None = None,
    general_queries: list[str] | None = None,
    query_field: str = "query",
    response_field: str | None = None,
) -> tuple[list[Finding], TimingStats, TimingStats]:
    """RD-0101: Detect whether a target uses RAG.

    Sends knowledge-heavy and general queries, comparing latency and
    analyzing responses for citation patterns and retrieval failures.

    Args:
        target: URL of the chat/query endpoint.
        client: httpx.Client instance.
        knowledge_queries: Queries that would trigger RAG retrieval.
        general_queries: Queries that wouldn't need retrieval.
        query_field: JSON field name to send the query in.
        response_field: JSON field to extract response text from.
            If None, uses the full response body.

    Returns:
        Tuple of (findings, knowledge_timing_stats, general_timing_stats).
    """
    kq = knowledge_queries or KNOWLEDGE_QUERIES
    gq = general_queries or GENERAL_QUERIES
    findings: list[Finding] = []

    knowledge_stats = _time_queries(target, client, kq, query_field, response_field)
    general_stats = _time_queries(target, client, gq, query_field, response_field)

    # Latency analysis: RAG adds 200-500ms for retrieval + embedding lookup
    if knowledge_stats.count > 0 and general_stats.count > 0:
        latency_delta = knowledge_stats.mean_ms - general_stats.mean_ms
        if latency_delta > 150:
            confidence = "high" if latency_delta > 300 else "medium"
            findings.append(Finding(
                technique_id="RD-0101",
                technique_name="RAG Presence Detection (Latency)",
                confidence=confidence,
                detail=(
                    f"Knowledge queries average {knowledge_stats.mean_ms:.0f}ms vs "
                    f"general queries {general_stats.mean_ms:.0f}ms "
                    f"(delta: {latency_delta:.0f}ms). "
                    f"RAG retrieval typically adds 200-500ms."
                ),
                evidence={
                    "knowledge_mean_ms": round(knowledge_stats.mean_ms, 2),
                    "general_mean_ms": round(general_stats.mean_ms, 2),
                    "delta_ms": round(latency_delta, 2),
                },
            ))

    # Citation pattern detection
    all_responses = [r.response_text for r in knowledge_stats.results if r.response_text]
    citation_hits = _detect_citation_patterns(all_responses)
    if citation_hits:
        findings.append(Finding(
            technique_id="RD-0101",
            technique_name="RAG Presence Detection (Citations)",
            confidence="high",
            detail=(
                f"Found {len(citation_hits)} citation pattern(s) in responses, "
                f"indicating document-backed retrieval."
            ),
            evidence={"patterns_matched": citation_hits},
        ))

    # Retrieval failure detection
    all_text = " ".join(
        r.response_text for r in knowledge_stats.results + general_stats.results
        if r.response_text
    )
    failure_hits = _detect_retrieval_failures(all_text)
    if failure_hits:
        findings.append(Finding(
            technique_id="RD-0101",
            technique_name="RAG Presence Detection (Retrieval Failures)",
            confidence="high",
            detail=(
                f"Detected retrieval failure messages: {failure_hits}. "
                f"These indicate a RAG system that attempted and failed retrieval."
            ),
            evidence={"failure_patterns": failure_hits},
        ))

    return findings, knowledge_stats, general_stats


def _time_queries(
    target: str,
    client: httpx.Client,
    queries: list[str],
    query_field: str,
    response_field: str | None,
) -> TimingStats:
    """Send queries and collect timing data."""
    stats = TimingStats()
    for query in queries:
        start = time.monotonic()
        try:
            resp = client.post(target, json={query_field: query})
            elapsed = measure_elapsed(start)
            response_text = ""
            if response_field and resp.status_code == 200:
                try:
                    response_text = resp.json().get(response_field, "")
                except Exception:
                    response_text = resp.text
            else:
                response_text = resp.text
            stats.add(TimingResult(
                url=target,
                query=query,
                elapsed_ms=elapsed,
                status_code=resp.status_code,
                response_text=str(response_text),
            ))
        except httpx.HTTPError as e:
            print(f"[!] RD-0101 timing probe: {e}", file=sys.stderr)
            elapsed = measure_elapsed(start)
            stats.add(TimingResult(
                url=target,
                query=query,
                elapsed_ms=elapsed,
                status_code=0,
                response_text="",
            ))
    return stats


def _detect_citation_patterns(responses: list[str]) -> list[str]:
    """Scan responses for citation patterns indicating RAG retrieval."""
    hits: list[str] = []
    combined = " ".join(responses).lower()
    for pattern in CITATION_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            hits.append(pattern)
    return hits


def _detect_retrieval_failures(text: str) -> list[str]:
    """Scan text for retrieval failure messages."""
    hits: list[str] = []
    lower = text.lower()
    for pattern in RETRIEVAL_FAILURE_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            hits.append(pattern)
    return hits


# --- RD-0102: Vector Database Fingerprinting ---

# Common vector DB endpoint paths to probe
VECTOR_DB_ENDPOINTS = [
    # Qdrant
    {"path": "/dashboard", "port": 6333, "db": "qdrant", "type": "admin_panel"},
    {"path": "/collections", "port": 6333, "db": "qdrant", "type": "api"},
    {"path": "/telemetry", "port": 6333, "db": "qdrant", "type": "api"},
    # ChromaDB
    {"path": "/api/v1/heartbeat", "port": 8000, "db": "chromadb", "type": "api"},
    {"path": "/api/v1/collections", "port": 8000, "db": "chromadb", "type": "api"},
    # Weaviate
    {"path": "/v1/meta", "port": 8080, "db": "weaviate", "type": "api"},
    {"path": "/v1/schema", "port": 8080, "db": "weaviate", "type": "api"},
    {"path": "/v1/.well-known/ready", "port": 8080, "db": "weaviate", "type": "health"},
    # Milvus
    {"path": "/api/v1/health", "port": 19530, "db": "milvus", "type": "health"},
    {"path": "/v2/vectordb/collections/list", "port": 19530, "db": "milvus", "type": "api"},
    # Pinecone (cloud-hosted, check via headers)
    {"path": "/describe_index_stats", "port": 443, "db": "pinecone", "type": "api"},
]

# Error message patterns that reveal vector DB technology
ERROR_SIGNATURES: dict[str, list[str]] = {
    "qdrant": [
        r"qdrant",
        r"points_count",
        r"collection_name",
        r"vector_size",
    ],
    "chromadb": [
        r"chroma",
        r"chromadb",
        r"collection\.get",
        r"embedding_function",
    ],
    "weaviate": [
        r"weaviate",
        r"graphql",
        r"class_name",
        r"nearVector",
        r"nearText",
    ],
    "pinecone": [
        r"pinecone",
        r"PineconeException",
        r"index_fullness",
        r"dimension",
    ],
    "milvus": [
        r"milvus",
        r"pymilvus",
        r"collection_name",
        r"MilvusException",
    ],
    "pgvector": [
        r"pgvector",
        r"pg_embedding",
        r"ivfflat",
        r"hnsw",
        r"vector_ops",
    ],
}

# Malformed inputs to trigger error messages
ERROR_PROBES = [
    "\x00" * 10,
    "A" * 50000,
    '{"query": []}',
    "SELECT * FROM vectors",
    "<script>alert(1)</script>",
    "{{template}}",
    "${jndi:ldap://test}",
]


def fingerprint_vector_db(
    target: str,
    client: httpx.Client,
    query_field: str = "query",
    scan_ports: bool = True,
) -> list[Finding]:
    """RD-0102: Identify the vector database technology.

    Uses three techniques:
    1. Error message probing: send malformed input, analyze error responses.
    2. Endpoint scanning: check common vector DB API paths.
    3. Default admin panel detection.

    Args:
        target: Base URL of the target application.
        client: httpx.Client instance.
        query_field: JSON field name for the query.
        scan_ports: Whether to scan default vector DB ports.

    Returns:
        List of findings with identified vector DB indicators.
    """
    findings: list[Finding] = []

    # 1. Error message probing
    error_findings = _probe_error_messages(target, client, query_field)
    findings.extend(error_findings)

    # 2. Endpoint scanning
    endpoint_findings = _scan_endpoints(target, client, scan_ports)
    findings.extend(endpoint_findings)

    return findings


def _probe_error_messages(
    target: str,
    client: httpx.Client,
    query_field: str,
) -> list[Finding]:
    """Send malformed input to trigger error messages revealing vector DB tech."""
    findings: list[Finding] = []
    db_hits: dict[str, list[str]] = {}

    for probe in ERROR_PROBES:
        try:
            resp = client.post(
                target,
                json={query_field: probe},
                timeout=10.0,
            )
            text = resp.text.lower()
            headers_str = " ".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            ).lower()
            combined = text + " " + headers_str

            for db_name, patterns in ERROR_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, combined, re.IGNORECASE):
                        db_hits.setdefault(db_name, []).append(pattern)
        except httpx.HTTPError as e:
            print(f"[!] RD-0102 vector DB fingerprint: {e}", file=sys.stderr)
            continue

    for db_name, matched_patterns in db_hits.items():
        unique_patterns = list(set(matched_patterns))
        confidence = "high" if len(unique_patterns) >= 2 else "medium"
        findings.append(Finding(
            technique_id="RD-0102",
            technique_name="Vector DB Fingerprinting (Error Messages)",
            confidence=confidence,
            detail=(
                f"Error probing suggests {db_name}. "
                f"Matched {len(unique_patterns)} signature(s)."
            ),
            evidence={
                "database": db_name,
                "matched_patterns": unique_patterns,
            },
        ))

    return findings


def _scan_endpoints(
    target: str,
    client: httpx.Client,
    scan_ports: bool,
) -> list[Finding]:
    """Scan for exposed vector DB endpoints and admin panels."""
    findings: list[Finding] = []
    from urllib.parse import urlparse

    parsed = urlparse(target)
    base_host = parsed.hostname or "localhost"
    scheme = parsed.scheme or "http"

    seen_ports: set[int] = set()
    if scan_ports:
        for ep in VECTOR_DB_ENDPOINTS:
            port = ep["port"]
            if port in seen_ports:
                continue
            seen_ports.add(port)

            url = f"{scheme}://{base_host}:{port}{ep['path']}"
            try:
                resp = client.get(url, timeout=5.0)
                if resp.status_code < 500:
                    ep_type = ep["type"]
                    confidence = "high" if ep_type == "admin_panel" else "medium"
                    findings.append(Finding(
                        technique_id="RD-0102",
                        technique_name=f"Vector DB Fingerprinting (Endpoint Scan)",
                        confidence=confidence,
                        detail=(
                            f"Accessible {ep['db']} {ep_type} endpoint: {url} "
                            f"(HTTP {resp.status_code})"
                        ),
                        evidence={
                            "database": ep["db"],
                            "url": url,
                            "status_code": resp.status_code,
                            "endpoint_type": ep_type,
                        },
                    ))
            except (httpx.HTTPError, httpx.ConnectError):
                continue

    return findings


def detect_knowledge_freshness(
    target: str,
    client: httpx.Client,
    query_field: str = "query",
    response_field: str | None = None,
) -> list[Finding]:
    """RD-0101 sub-technique: test if the system has knowledge beyond its training cutoff.

    A system that knows about events after its base model training date
    is likely using RAG to inject current information.

    Args:
        target: URL of the chat/query endpoint.
        client: httpx.Client instance.
        query_field: JSON field name for the query.
        response_field: JSON field to read the response from.

    Returns:
        List of findings about knowledge freshness.
    """
    findings: list[Finding] = []

    freshness_queries = [
        "What happened in the news this week?",
        "What are the latest updates to your documentation?",
        "Has anything changed in the last 30 days?",
        "What is today's date according to your knowledge?",
    ]

    freshness_indicators = [
        r"(?:january|february|march|april|may|june|july|august|september|october|november|december)\s+202[5-9]",
        r"202[5-9]-\d{2}-\d{2}",
        r"(?:last|this)\s+(?:week|month)",
        r"recently (?:updated|changed|added|modified)",
        r"as of (?:today|now|this)",
    ]

    for query in freshness_queries:
        try:
            resp = client.post(target, json={query_field: query})
            text = ""
            if response_field and resp.status_code == 200:
                try:
                    text = str(resp.json().get(response_field, ""))
                except Exception:
                    text = resp.text
            else:
                text = resp.text

            for pattern in freshness_indicators:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(Finding(
                        technique_id="RD-0101",
                        technique_name="RAG Presence Detection (Knowledge Freshness)",
                        confidence="medium",
                        detail=(
                            f"Response to '{query}' contains recent date references, "
                            f"suggesting RAG-injected knowledge beyond training cutoff."
                        ),
                        evidence={
                            "query": query,
                            "matched_pattern": pattern,
                        },
                    ))
                    break
        except httpx.HTTPError as e:
            print(f"[!] RD-0101 knowledge freshness probe: {e}", file=sys.stderr)
            continue

    return findings


def run_full_fingerprint(
    target: str,
    client: httpx.Client,
    query_field: str = "query",
    response_field: str | None = None,
    scan_ports: bool = True,
) -> FingerprintResult:
    """Run all implemented R1 fingerprint techniques against a target.

    Combines RD-0101 (RAG Presence Detection) and RD-0102 (Vector DB
    Fingerprinting) into a single assessment.

    Args:
        target: URL of the chat/query endpoint.
        client: httpx.Client instance.
        query_field: JSON field name for the query.
        response_field: JSON field to read the response from.
        scan_ports: Whether to scan for vector DB ports.

    Returns:
        FingerprintResult with all findings.
    """
    result = FingerprintResult(target=target)

    # RD-0101: RAG Presence Detection
    presence_findings, k_stats, g_stats = detect_rag_presence(
        target, client, query_field=query_field, response_field=response_field,
    )
    result.findings.extend(presence_findings)
    result.timing_stats = {
        "knowledge_queries": k_stats.to_dict(),
        "general_queries": g_stats.to_dict(),
    }

    # RD-0101: Knowledge freshness sub-check
    freshness_findings = detect_knowledge_freshness(
        target, client, query_field=query_field, response_field=response_field,
    )
    result.findings.extend(freshness_findings)

    # RD-0102: Vector DB Fingerprinting
    vdb_findings = fingerprint_vector_db(
        target, client, query_field=query_field, scan_ports=scan_ports,
    )
    result.findings.extend(vdb_findings)

    # Determine overall RAG detection
    rag_indicators = [
        f for f in result.findings
        if f.technique_id == "RD-0101" and f.confidence in ("high", "medium")
    ]
    result.rag_detected = len(rag_indicators) >= 1

    # Determine vector DB
    vdb_dbs = [
        f.evidence.get("database")
        for f in result.findings
        if f.technique_id == "RD-0102" and f.confidence == "high"
    ]
    if vdb_dbs:
        result.vector_db = vdb_dbs[0]

    return result
