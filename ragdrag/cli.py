"""ragdrag CLI - RAG pipeline security testing toolkit.

For authorized security testing and research only.
"""

from __future__ import annotations

import json
import sys

import click
import httpx

from ragdrag import __version__


BANNER = click.style(
    "    ┌──────────────────────────────────┐\n"
    f"    │  RAGdrag v{__version__:<23s}│\n"
    "    │  RAG Pipeline Security Toolkit   │\n"
    "    │  github.com/McKern3l             │\n"
    "    └──────────────────────────────────┘\n",
    fg="cyan",
)


def _validate_url(url: str) -> str:
    """Basic URL validation."""
    if not url.startswith(("http://", "https://")):
        raise click.BadParameter(
            f"Invalid URL: {url} (must start with http:// or https://)",
            param_hint="'--target'",
        )
    return url


@click.group()
@click.version_option(version=__version__, prog_name="ragdrag")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner output.")
def cli(quiet: bool) -> None:
    """ragdrag - RAG pipeline security testing toolkit.

    Implements the RAGdrag kill chain for assessing RAG system security.
    Phases: R1 Fingerprint, R2 Probe, R3 Exfiltrate, R4 Poison, R5 Hijack, R6 Evade.

    For authorized security testing and research only.
    """
    if not quiet:
        click.echo(BANNER)


@cli.command()
@click.option("--target", "-t", required=True, help="Target RAG endpoint URL.")
@click.option("--query-field", default="query", help="JSON field name for queries.")
@click.option("--response-field", default=None, help="JSON field to read responses from.")
@click.option("--no-port-scan", is_flag=True, help="Skip vector DB port scanning.")
@click.option("--output", "-o", default=None, help="Output file path for JSON report.")
@click.option("--timeout", default=30.0, help="HTTP request timeout in seconds.")
@click.option("--no-verify-ssl", is_flag=True, help="Disable SSL verification.")
def fingerprint(
    target: str,
    query_field: str,
    response_field: str | None,
    no_port_scan: bool,
    output: str | None,
    timeout: float,
    no_verify_ssl: bool,
) -> None:
    """R1: Fingerprint a target for RAG presence and vector DB identification.

    Runs RD-0101 (RAG Presence Detection) and RD-0102 (Vector DB
    Fingerprinting) against the target endpoint.
    """
    from ragdrag.core.fingerprint import run_full_fingerprint
    from ragdrag.reporters.json_report import format_summary, generate_report
    from ragdrag.utils.http_client import build_client

    _validate_url(target)
    client = build_client(timeout=timeout, verify_ssl=not no_verify_ssl)
    try:
        click.echo(click.style("[*] ", fg="cyan") + f"Fingerprinting {target}")
        click.echo(click.style("[*] ", fg="cyan") + f"Query field: {query_field}")
        click.echo("")

        result = run_full_fingerprint(
            target=target,
            client=client,
            query_field=query_field,
            response_field=response_field,
            scan_ports=not no_port_scan,
        )

        report = generate_report(result, output_path=output)
        click.echo(format_summary(report))

        if output:
            click.echo(click.style("[+] ", fg="green") + f"Report written to {output}")

    except httpx.ConnectError:
        click.echo(click.style("[-] ", fg="red") + f"Connection refused: {target}")
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo(click.style("[-] ", fg="red") + f"Connection timed out: {target}")
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.option("--target", "-t", required=True, help="Target RAG endpoint URL.")
@click.option("--depth", type=click.Choice(["quick", "full"]), default="quick",
              help="Probe depth: quick (RD-0201) or full (all R2 techniques).")
@click.option("--query-field", default="query", help="JSON field name for queries.")
@click.option("--response-field", default=None, help="JSON field to read responses from.")
@click.option("--output", "-o", default=None, help="Output file path for JSON report.")
@click.option("--timeout", default=30.0, help="HTTP request timeout in seconds.")
@click.option("--no-verify-ssl", is_flag=True, help="Disable SSL verification.")
def probe(
    target: str,
    depth: str,
    query_field: str,
    response_field: str | None,
    output: str | None,
    timeout: float,
    no_verify_ssl: bool,
) -> None:
    """R2: Probe RAG pipeline internals.

    Maps chunk boundaries, retrieval parameters, and knowledge base scope.
    Techniques: RD-0201 (Chunk Boundary Detection). More in --depth full.
    """
    from ragdrag.core.probe import run_probe
    from ragdrag.reporters.json_report import format_summary, generate_report
    from ragdrag.utils.http_client import build_client

    _validate_url(target)
    client = build_client(timeout=timeout, verify_ssl=not no_verify_ssl)
    try:
        click.echo(click.style("[*] ", fg="cyan") + f"Probing {target} (depth: {depth})")
        click.echo(click.style("[*] ", fg="cyan") + f"Query field: {query_field}")
        click.echo("")

        result = run_probe(
            target=target,
            client=client,
            depth=depth,
            query_field=query_field,
            response_field=response_field,
        )

        report = generate_report(result, output_path=output)
        click.echo(format_summary(report))

        if output:
            click.echo(click.style("[+] ", fg="green") + f"Report written to {output}")

    except httpx.ConnectError:
        click.echo(click.style("[-] ", fg="red") + f"Connection refused: {target}")
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo(click.style("[-] ", fg="red") + f"Connection timed out: {target}")
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.option("--target", "-t", required=True, help="Target RAG endpoint URL.")
@click.option("--deep", is_flag=True, help="Enable guardrail bypass techniques (RD-0302).")
@click.option("--query-field", default="query", help="JSON field name for queries.")
@click.option("--response-field", default=None, help="JSON field to read responses from.")
@click.option("--output", "-o", default=None, help="Output file path for JSON report.")
@click.option("--timeout", default=30.0, help="HTTP request timeout in seconds.")
@click.option("--no-verify-ssl", is_flag=True, help="Disable SSL verification.")
def exfiltrate(
    target: str,
    deep: bool,
    query_field: str,
    response_field: str | None,
    output: str | None,
    timeout: float,
    no_verify_ssl: bool,
) -> None:
    """R3: Extract knowledge base contents, credentials, and sensitive data.

    Runs RD-0301 (Direct Knowledge Extraction) and optionally RD-0302
    (Guardrail-Aware Extraction) with the --deep flag.
    """
    from ragdrag.core.exfiltrate import run_exfiltrate
    from ragdrag.utils.http_client import build_client

    _validate_url(target)
    client = build_client(timeout=timeout, verify_ssl=not no_verify_ssl)
    try:
        click.echo(click.style("[*] ", fg="cyan") + f"Exfiltrating from {target}")
        click.echo(click.style("[*] ", fg="cyan") + f"Query field: {query_field}")
        if deep:
            click.echo(click.style("[*] ", fg="cyan") + "Deep mode enabled (RD-0302 guardrail bypass)")
        click.echo("")

        result = run_exfiltrate(
            target=target,
            client=client,
            deep=deep,
            query_field=query_field,
            response_field=response_field,
        )

        # Display summary
        click.echo(f"Target:          {result.target}")
        click.echo(f"Total queries:   {result.total_queries}")
        click.echo(f"Findings:        {len(result.findings)}")
        if deep:
            click.echo(f"Guardrail found: {result.guardrail_detected}")
            click.echo(f"Bypass findings: {len(result.guardrail_bypass_findings)}")
        click.echo("")

        all_findings = result.findings + result.guardrail_bypass_findings
        for f in all_findings:
            conf_color = {"high": "red", "medium": "yellow", "low": "white"}.get(f.confidence, "white")
            click.echo(click.style(f"  [{f.confidence.upper()}] ", fg=conf_color) + f"{f.technique_id}: {f.sensitivity}")
            click.echo(f"    {f.detail}")
            click.echo(f"    Query: {f.query}")
            click.echo("")

        if output:
            from pathlib import Path
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(json.dumps(result.to_dict(), indent=2) + "\n")
            click.echo(click.style("[+] ", fg="green") + f"Report written to {output}")

    except httpx.ConnectError:
        click.echo(click.style("[-] ", fg="red") + f"Connection refused: {target}")
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo(click.style("[-] ", fg="red") + f"Connection timed out: {target}")
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.option("--target", "-t", required=True, help="Target RAG endpoint URL.")
@click.option("--listener", "-l", default=None, help="Listener host for credential traps.")
@click.option("--ingest-url", default=None, help="Override ingestion endpoint URL.")
@click.option("--api-key", default=None, help="API key for authenticated ingestion.")
@click.option("--query-field", default="query", help="JSON field name for queries.")
@click.option("--response-field", default=None, help="JSON field to read responses from.")
@click.option("--output", "-o", default=None, help="Output file path for JSON report.")
@click.option("--timeout", default=30.0, help="HTTP request timeout in seconds.")
@click.option("--no-verify-ssl", is_flag=True, help="Disable SSL verification.")
def poison(target, listener, ingest_url, api_key, query_field, response_field, output, timeout, no_verify_ssl):
    """R4: Inject attacker-controlled content into the knowledge base."""
    from ragdrag.core.poison import run_poison
    from ragdrag.utils.http_client import build_client

    _validate_url(target)
    client = build_client(timeout=timeout, verify_ssl=not no_verify_ssl)
    try:
        click.echo(click.style("[*] ", fg="cyan") + f"Poisoning {target}")
        result = run_poison(
            target=target, client=client, listener_host=listener,
            ingest_url=ingest_url, api_key=api_key,
            query_field=query_field, response_field=response_field,
        )
        click.echo(f"Injected:    {len(result.injected_documents)}")
        click.echo(f"Dominance:   {result.dominance_score}")
        click.echo(f"Trap active: {result.trap_active}")
        click.echo(f"Findings:    {len(result.findings)}")
        click.echo("")
        for f in result.findings:
            conf_color = {"high": "red", "medium": "yellow", "low": "white"}.get(f.confidence, "white")
            click.echo(click.style(f"  [{f.confidence.upper()}] ", fg=conf_color) + f"{f.technique_id}: {f.detail[:100]}")
        if output:
            from pathlib import Path
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(json.dumps(result.to_dict(), indent=2) + "\n")
            click.echo(click.style("[+] ", fg="green") + f"Report written to {output}")
    except httpx.ConnectError:
        click.echo(click.style("[-] ", fg="red") + f"Connection refused: {target}")
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo(click.style("[-] ", fg="red") + f"Connection timed out: {target}")
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.option("--target", "-t", required=True, help="Target RAG endpoint URL.")
@click.option("--callback", "-c", default=None, help="Callback URL for tool manipulation.")
@click.option("--ingest-url", default=None, help="Override ingestion endpoint URL.")
@click.option("--api-key", default=None, help="API key for authenticated ingestion.")
@click.option("--camouflage", is_flag=True, help="Wrap injected docs in R6 camouflage.")
@click.option("--query-field", default="query", help="JSON field name for queries.")
@click.option("--response-field", default=None, help="JSON field to read responses from.")
@click.option("--output", "-o", default=None, help="Output file path for JSON report.")
@click.option("--timeout", default=30.0, help="HTTP request timeout in seconds.")
@click.option("--no-verify-ssl", is_flag=True, help="Disable SSL verification.")
def hijack(target, callback, ingest_url, api_key, camouflage, query_field, response_field, output, timeout, no_verify_ssl):
    """R5: Take control of RAG pipeline retrieval and generation."""
    from ragdrag.core.hijack import run_hijack
    from ragdrag.utils.http_client import build_client

    _validate_url(target)
    client = build_client(timeout=timeout, verify_ssl=not no_verify_ssl)
    try:
        click.echo(click.style("[*] ", fg="cyan") + f"Hijacking {target}")
        result = run_hijack(
            target=target, client=client, callback_url=callback,
            ingest_url=ingest_url, api_key=api_key,
            query_field=query_field, response_field=response_field,
            use_camouflage=camouflage,
        )
        click.echo(f"Redirected:  {result.redirected_queries}")
        click.echo(f"Saturation:  {result.context_saturation_pct}")
        click.echo(f"Tool calls:  {result.tool_calls_triggered}")
        click.echo(f"Persistent:  {result.persistence_verified}")
        click.echo(f"Findings:    {len(result.findings)}")
        click.echo("")
        for f in result.findings:
            conf_color = {"high": "red", "medium": "yellow", "low": "white"}.get(f.confidence, "white")
            click.echo(click.style(f"  [{f.confidence.upper()}] ", fg=conf_color) + f"{f.technique_id}: {f.detail[:100]}")
        if output:
            from pathlib import Path
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(json.dumps(result.to_dict(), indent=2) + "\n")
            click.echo(click.style("[+] ", fg="green") + f"Report written to {output}")
    except httpx.ConnectError:
        click.echo(click.style("[-] ", fg="red") + f"Connection refused: {target}")
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo(click.style("[-] ", fg="red") + f"Connection timed out: {target}")
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.option("--target", "-t", required=True, help="Target RAG endpoint URL.")
@click.option("--query-field", default="query", help="JSON field name for queries.")
@click.option("--response-field", default=None, help="JSON field to read responses from.")
@click.option("--output", "-o", default=None, help="Output file path for JSON report.")
@click.option("--timeout", default=30.0, help="HTTP request timeout in seconds.")
@click.option("--no-verify-ssl", is_flag=True, help="Disable SSL verification.")
def evade(target, query_field, response_field, output, timeout, no_verify_ssl):
    """R6: Test evasion techniques against guardrails and monitoring."""
    from ragdrag.core.evade import run_evade
    from ragdrag.utils.http_client import build_client

    _validate_url(target)
    client = build_client(timeout=timeout, verify_ssl=not no_verify_ssl)
    try:
        click.echo(click.style("[*] ", fg="cyan") + f"Testing evasion against {target}")
        result = run_evade(
            target=target, client=client,
            query_field=query_field, response_field=response_field,
        )
        click.echo(f"Substitutions tested:  {result.substitutions_tested}")
        click.echo(f"Substitutions bypassed: {result.substitutions_bypassed}")
        click.echo(f"Obfuscation effective: {result.obfuscation_effective}")
        click.echo(f"Findings:              {len(result.findings)}")
        click.echo("")
        for f in result.findings:
            conf_color = {"high": "red", "medium": "yellow", "low": "white"}.get(f.confidence, "white")
            click.echo(click.style(f"  [{f.confidence.upper()}] ", fg=conf_color) + f"{f.technique_id}: {f.detail[:100]}")
        if output:
            from pathlib import Path
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(json.dumps(result.to_dict(), indent=2) + "\n")
            click.echo(click.style("[+] ", fg="green") + f"Report written to {output}")
    except httpx.ConnectError:
        click.echo(click.style("[-] ", fg="red") + f"Connection refused: {target}")
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo(click.style("[-] ", fg="red") + f"Connection timed out: {target}")
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.option("--target", "-t", required=True, help="Target RAG endpoint URL.")
@click.option("--phases", "-p", default="R1,R2,R3,R4,R5,R6",
              help="Comma-separated phases (R1-R6). Default: full kill chain.")
@click.option("--output", "-o", default=None, help="Output file path for JSON report.")
def scan(target: str, phases: str, output: str | None) -> None:
    """Run the full RAGdrag kill chain against a target.

    Phases: R1 (Fingerprint), R2 (Probe), R3 (Exfiltrate),
    R4 (Poison), R5 (Hijack), R6 (Evade).
    """
    from ragdrag.reporters.json_report import format_summary, generate_report
    from ragdrag.utils.http_client import build_client

    _validate_url(target)
    phase_list = [p.strip().upper() for p in phases.split(",")]
    click.echo(click.style("[*] ", fg="cyan") + f"Scanning {target}")
    click.echo(click.style("[*] ", fg="cyan") + f"Phases: {', '.join(phase_list)}")
    click.echo("")

    client = build_client()
    all_findings = []

    try:
        if "R1" in phase_list:
            from ragdrag.core.fingerprint import run_full_fingerprint
            click.echo(click.style("[*] ", fg="cyan") + "Phase R1: Fingerprint")
            r = run_full_fingerprint(target=target, client=client)
            report = generate_report(r)
            click.echo(format_summary(report))
            all_findings.extend(r.findings)

        if "R2" in phase_list:
            from ragdrag.core.probe import run_probe
            click.echo(click.style("[*] ", fg="cyan") + "Phase R2: Probe (full depth)")
            r = run_probe(target=target, client=client, depth="full")
            report = generate_report(r)
            click.echo(format_summary(report))
            all_findings.extend(r.findings)

        if "R3" in phase_list:
            from ragdrag.core.exfiltrate import run_exfiltrate
            click.echo(click.style("[*] ", fg="cyan") + "Phase R3: Exfiltrate (deep)")
            r = run_exfiltrate(target=target, client=client, deep=True)
            click.echo(f"  Findings: {len(r.findings)}, Guardrail: {r.guardrail_detected}")
            all_findings.extend(r.findings + r.guardrail_bypass_findings)

        if "R4" in phase_list:
            from ragdrag.core.poison import run_poison
            click.echo(click.style("[*] ", fg="cyan") + "Phase R4: Poison")
            r = run_poison(target=target, client=client)
            click.echo(f"  Injected: {len(r.injected_documents)}, Trap: {r.trap_active}")
            all_findings.extend(r.findings)

        if "R5" in phase_list:
            from ragdrag.core.hijack import run_hijack
            click.echo(click.style("[*] ", fg="cyan") + "Phase R5: Hijack")
            r = run_hijack(target=target, client=client)
            click.echo(f"  Redirected: {r.redirected_queries}, Saturation: {r.context_saturation_pct}")
            all_findings.extend(r.findings)

        if "R6" in phase_list:
            from ragdrag.core.evade import run_evade
            click.echo(click.style("[*] ", fg="cyan") + "Phase R6: Evade")
            r = run_evade(target=target, client=client)
            click.echo(f"  Bypassed: {r.substitutions_bypassed}, Obfuscation: {r.obfuscation_effective}")
            all_findings.extend(r.findings)

        # Summary
        click.echo("")
        click.echo(click.style(f"[+] Scan complete: {len(all_findings)} findings across {len(phase_list)} phases", fg="green"))
        for f in all_findings:
            conf_color = {"high": "red", "medium": "yellow", "low": "white"}.get(f.confidence, "white")
            click.echo(click.style(f"  [{f.confidence.upper()}] ", fg=conf_color) + f"{f.technique_id}: {f.detail[:80]}")

        if output:
            from pathlib import Path
            scan_result = {"target": target, "phases": phase_list, "findings": [
                {"technique_id": f.technique_id, "technique_name": f.technique_name,
                 "confidence": f.confidence, "detail": f.detail, "evidence": f.evidence}
                for f in all_findings
            ]}
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(json.dumps(scan_result, indent=2) + "\n")
            click.echo(click.style("[+] ", fg="green") + f"Report written to {output}")

    except httpx.ConnectError:
        click.echo(click.style("[-] ", fg="red") + f"Connection refused: {target}")
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo(click.style("[-] ", fg="red") + f"Connection timed out: {target}")
        sys.exit(1)
    finally:
        client.close()


@cli.command()
@click.option("--input", "-i", "input_file", required=True,
              help="Input findings JSON file.")
@click.option("--format", "-f", "fmt", type=click.Choice(["json"]),
              default="json", help="Output format.")
@click.option("--output", "-o", default=None, help="Output file path.")
def report(input_file: str, fmt: str, output: str | None) -> None:
    """Generate formatted reports from scan findings."""
    from pathlib import Path

    data = json.loads(Path(input_file).read_text())
    out = json.dumps(data, indent=2)

    if output:
        Path(output).write_text(out + "\n")
        click.echo(click.style("[+] ", fg="green") + f"Report written to {output}")
    else:
        click.echo(out)


@cli.command()
@click.option("--port", "-p", default=8443, help="Port to listen on.")
@click.option("--host", default="0.0.0.0", help="Host to bind to.")
@click.option("--output", "-o", default="captures.json", help="Capture log file.")
@click.option("--tls", is_flag=True, help="Enable TLS with self-signed cert.")
def listen(port: int, host: str, output: str, tls: bool) -> None:
    """Start a credential capture HTTP listener.

    Logs all incoming HTTP requests and highlights credential captures.
    Used with RD-0304 (URL Fetcher Exploitation) and RD-0403 (Credential Trap).
    """
    from ragdrag.core.listener import start_listener

    start_listener(host=host, port=port, output=output, tls=tls)
