"""
SSRF-safe HTTP request runner.
Blocks loopback, private, link-local, and metadata service destinations.
"""
import ipaddress
import socket
import time
from typing import Optional
from urllib.parse import urlparse

import httpx
from django.conf import settings

ALLOWED_SCHEMES = {"http", "https"}

# AWS/GCP/Azure metadata service IPs
BLOCKED_PREFIXES = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),   # shared address space (RFC 6598)
]

SAFE_RESPONSE_HEADERS = {
    "content-type",
    "content-length",
    "date",
    "server",
    "x-request-id",
    "x-correlation-id",
    "cache-control",
    "etag",
    "last-modified",
    "location",
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
}


class RunnerError(Exception):
    def __init__(self, error_kind: str, message: str):
        self.error_kind = error_kind
        self.message = message
        super().__init__(message)


def _resolve_and_check(host: str) -> None:
    """Resolve hostname and block private/reserved addresses."""
    try:
        addrinfos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise RunnerError("dns_error", f"Could not resolve host: {host}") from exc

    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise RunnerError("invalid_address", f"Cannot parse resolved address: {ip_str}")

        if ip.is_loopback:
            raise RunnerError("ssrf_blocked", "Loopback addresses are not allowed.")
        if ip.is_private:
            raise RunnerError("ssrf_blocked", "Private network addresses are not allowed.")
        if ip.is_link_local:
            raise RunnerError("ssrf_blocked", "Link-local addresses are not allowed.")
        if ip.is_multicast:
            raise RunnerError("ssrf_blocked", "Multicast addresses are not allowed.")
        if ip.is_reserved:
            raise RunnerError("ssrf_blocked", "Reserved addresses are not allowed.")
        for blocked_net in BLOCKED_PREFIXES:
            if ip in blocked_net:
                raise RunnerError("ssrf_blocked", f"Address {ip_str} is in a blocked range.")


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise RunnerError("invalid_scheme", f"Scheme '{parsed.scheme}' is not allowed. Use http or https.")
    if not parsed.hostname:
        raise RunnerError("invalid_url", "URL must include a hostname.")
    _resolve_and_check(parsed.hostname)


def _filter_headers(headers: dict) -> dict:
    """Return only safe, non-sensitive response headers."""
    return {
        k: v
        for k, v in headers.items()
        if k.lower() in SAFE_RESPONSE_HEADERS
    }


def _redact_request_headers(headers: dict) -> dict:
    """Redact sensitive headers from request headers before storing/logging."""
    sensitive = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token"}
    return {k: "[REDACTED]" if k.lower() in sensitive else v for k, v in headers.items()}


def run_request(
    method: str,
    url: str,
    headers: Optional[dict] = None,
    bearer_token: Optional[str] = None,
    json_body: Optional[dict] = None,
) -> dict:
    """
    Execute a controlled HTTP request with SSRF protections.

    Returns a dict with:
        success, status_code, duration_ms, response_headers,
        response_body (truncated), error_kind, error_message
    """
    headers = headers or {}
    max_bytes = getattr(settings, "REQUEST_RUNNER_MAX_RESPONSE_BYTES", 512 * 1024)
    timeout = getattr(settings, "REQUEST_RUNNER_TIMEOUT", 10)

    # Add bearer token without persisting it
    request_headers = dict(headers)
    if bearer_token:
        token = str(bearer_token).strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        request_headers["Authorization"] = f"Bearer {token}"

    try:
        _validate_url(url)
    except RunnerError as exc:
        return {
            "success": False,
            "status_code": None,
            "duration_ms": None,
            "response_headers": {},
            "response_body": None,
            "error_kind": exc.error_kind,
            "error_message": exc.message,
        }

    start = time.monotonic()
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            max_redirects=3,
        ) as client:
            response = client.request(
                method=method.upper(),
                url=url,
                headers=request_headers,
                json=json_body if json_body else None,
            )
            # Validate redirect destinations
            for r in response.history:
                try:
                    _validate_url(str(r.url))
                except RunnerError as exc:
                    return {
                        "success": False,
                        "status_code": None,
                        "duration_ms": round((time.monotonic() - start) * 1000, 2),
                        "response_headers": {},
                        "response_body": None,
                        "error_kind": exc.error_kind,
                        "error_message": f"Redirect blocked: {exc.message}",
                    }

            duration_ms = round((time.monotonic() - start) * 1000, 2)
            body_bytes = response.content[:max_bytes]
            try:
                body = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body = "[binary content]"

            truncated = len(response.content) > max_bytes

            return {
                "success": 200 <= response.status_code < 300,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "response_headers": _filter_headers(dict(response.headers)),
                "response_body": body,
                "response_truncated": truncated,
                "error_kind": None,
                "error_message": None,
            }

    except httpx.TimeoutException:
        duration_ms = round((time.monotonic() - start) * 1000, 2)
        return {
            "success": False,
            "status_code": None,
            "duration_ms": duration_ms,
            "response_headers": {},
            "response_body": None,
            "error_kind": "timeout",
            "error_message": f"Request timed out after {timeout}s.",
        }
    except httpx.RequestError as exc:
        duration_ms = round((time.monotonic() - start) * 1000, 2)
        return {
            "success": False,
            "status_code": None,
            "duration_ms": duration_ms,
            "response_headers": {},
            "response_body": None,
            "error_kind": "network_error",
            "error_message": f"Network error: {type(exc).__name__}",
        }
