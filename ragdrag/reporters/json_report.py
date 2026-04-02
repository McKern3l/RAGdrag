"""JSON report generator for RAGdrag findings.

Produces machine-readable output compatible with security tooling pipelines.
Accepts any phase result object that implements .to_dict() and has a .findings list.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

import click

from ragdrag import __version__
from ragdrag.core.models import Finding


# --- Protocol for any phase result ---

@runtime_checkable
class PhaseResult(Protocol):
    """Any object with .to_dict() and .findings that we can report on."""

    target: str
    findings: list[Finding]

    def to_dict(self) -> dict: ...


# Confidence level colors
_CONFIDENCE_COLORS = {
    "high": "red",
    "medium": "yellow",
    "low": "green",
}


def generate_report(
    result: PhaseResult,
    output_path: str | Path | None = None,
) -> dict:
    """Generate a JSON report from any phase result.

    Args:
        result: Results from any RAGdrag phase (fingerprint, probe, exfiltrate, etc.).
            Must have .to_dict() and .findings attributes.
        output_path: Optional file path to write the report. If None,
            returns the dict without writing.

    Returns:
        The report as a dictionary.
    """
    result_dict = result.to_dict()

    # Build standardized report envelope
    findings = result.findings
    report = {
        "tool": "ragdrag",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": result.target,
        "summary": {
            "total_findings": len(findings),
            "high_confidence": sum(1 for f in findings if f.confidence == "high"),
            "medium_confidence": sum(1 for f in findings if f.confidence == "medium"),
            "low_confidence": sum(1 for f in findings if f.confidence == "low"),
        },
        "findings": [
            {
                "technique_id": f.technique_id,
                "technique_name": f.technique_name,
                "confidence": f.confidence,
                "detail": f.detail,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }

    # Merge in phase-specific fields from to_dict()
    for key, value in result_dict.items():
        if key not in ("target", "findings"):
            report[key] = value

    if output_path is not None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")

    return report


def _build_summary_box(report: dict) -> str:
    """Build a bordered summary box for CLI output.

    Returns plain text (no ANSI) so callers can apply click.style() or
    tests can assert on content.
    """
    summary = report["summary"]
    h = summary["high_confidence"]
    m = summary["medium_confidence"]
    lo = summary["low_confidence"]
    total = summary["total_findings"]

    target = report["target"]
    findings_str = f"{total} ({h}H / {m}M / {lo}L)"

    rows = [
        f"  Target:       {target}",
        f"  Findings:     {findings_str}",
    ]

    # Add phase-specific summary fields
    if "rag_detected" in report:
        rag = str(report["rag_detected"])
        vdb = report.get("vector_db") or "unknown"
        rows.insert(1, f"  RAG Detected: {rag}")
        rows.insert(2, f"  Vector DB:    {vdb}")

    if "chunk_size_estimate" in report and report["chunk_size_estimate"]:
        rows.insert(-1, f"  Chunk Size:   ~{report['chunk_size_estimate']} chars")
    if "retrieval_count" in report and report["retrieval_count"]:
        rows.insert(-1, f"  Top-K:        {report['retrieval_count']}")
    if "embedding_model" in report and report["embedding_model"]:
        rows.insert(-1, f"  Embedding:    {report['embedding_model']}")
    if "kb_domains" in report and report["kb_domains"]:
        rows.insert(-1, f"  KB Domains:   {', '.join(report['kb_domains'])}")

    inner_width = max(len(r) for r in rows) + 2
    top = "\u2554" + "\u2550" * inner_width + "\u2557"
    bot = "\u255a" + "\u2550" * inner_width + "\u255d"
    mid_lines = [
        "\u2551" + r.ljust(inner_width) + "\u2551"
        for r in rows
    ]
    return "\n".join([top, *mid_lines, bot])


def format_summary(report: dict, *, color: bool = True) -> str:
    """Format a report summary for CLI output.

    Args:
        report: Report dictionary from generate_report.
        color: Whether to apply ANSI color codes via click.style().

    Returns:
        Human-readable summary string.
    """
    box = _build_summary_box(report)
    lines = [box, ""]

    for f in report["findings"]:
        conf = f["confidence"]
        tag = conf.upper()
        conf_color = _CONFIDENCE_COLORS.get(conf, "white")
        if color:
            label = click.style(f"[{tag}]", fg=conf_color, bold=True)
        else:
            label = f"[{tag}]"
        lines.append(f"  [!] {label} {f['technique_id']}: {f['technique_name']}")
        lines.append(f"      {f['detail']}")
        lines.append("")

    return "\n".join(lines)
