"""
Observability utilities: sensitive data redaction, route sanitization,
request correlation, and classification.
"""
import json
import re
import uuid
from typing import Any, Dict

SENSITIVE_PATTERNS = {
    "password",
    "password2",
    "token",
    "access",
    "refresh",
    "secret",
    "authorization",
    "cookie",
    "key",
    "api_key",
    "sessionid",
    "csrf",
    "credit_card",
    "cvv",
}

SAFE_HEADER_WHITELIST = {
    "content-type",
    "content-length",
    "accept",
    "user-agent",
    "host",
    "origin",
    "referer",
    "x-request-id",
    "x-correlation-id",
    "x-pocketops-secret",
    "authorization",
}


def is_sensitive_key(key: str) -> bool:
    normalized = str(key).lower().replace("-", "_").replace(" ", "_")
    return any(p in normalized for p in SENSITIVE_PATTERNS)


def redact_data(data: Any) -> Any:
    """Recursively redact sensitive keys in dictionaries and lists."""
    if isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            if is_sensitive_key(k):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_data(v)
        return redacted
    elif isinstance(data, list):
        return [redact_data(item) for item in data]
    return data


def sanitize_headers(meta: Dict[str, Any]) -> Dict[str, str]:
    """Extract and redact HTTP headers from request.META."""
    headers = {}
    for key, value in meta.items():
        if key.startswith("HTTP_"):
            header_name = key[5:].replace("_", "-").lower()
            if header_name in SAFE_HEADER_WHITELIST:
                if is_sensitive_key(header_name):
                    headers[header_name] = "[REDACTED]"
                else:
                    headers[header_name] = str(value)[:500]
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            header_name = key.replace("_", "-").lower()
            headers[header_name] = str(value)[:200]
    return headers


def sanitize_query_params(query_dict: Any) -> Dict[str, Any]:
    """Sanitize and redact query parameters."""
    sanitized = {}
    for key in query_dict:
        val_list = query_dict.getlist(key) if hasattr(query_dict, "getlist") else [query_dict[key]]
        if is_sensitive_key(key):
            sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = val_list[0] if len(val_list) == 1 else val_list
    return sanitized


def sanitize_body(body_bytes: bytes, max_bytes: int = 8192) -> str:
    """Safely decode, redact sensitive JSON keys, and truncate body."""
    if not body_bytes:
        return ""

    truncated = body_bytes[:max_bytes]
    try:
        decoded_text = truncated.decode("utf-8", errors="replace")
    except Exception:
        return "[binary]"

    # Attempt JSON parsing for field-level redaction
    try:
        parsed = json.loads(decoded_text)
        redacted = redact_data(parsed)
        result = json.dumps(redacted)
        return result[:max_bytes]
    except Exception:
        pass

    # Regex fallback for query-like or text bodies
    cleaned = decoded_text
    for pattern in SENSITIVE_PATTERNS:
        cleaned = re.sub(
            rf'(?i)("{pattern}"\s*:\s*")[^"]+(")',
            r'\1[REDACTED]\2',
            cleaned,
        )
    return cleaned[:max_bytes]


def classify_request(status_code: int, is_exception: bool = False) -> str:
    if status_code >= 500:
        return "exception" if is_exception else "server_error"
    if status_code >= 400:
        return "client_error"
    return "success"


def extract_client_ip(request: Any) -> str:
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
        return ip[:45]
    return str(request.META.get("REMOTE_ADDR", ""))[:45]


def extract_or_generate_request_ids(request: Any) -> tuple[str, str]:
    raw_req_id = request.META.get("HTTP_X_REQUEST_ID", "").strip()
    raw_corr_id = request.META.get("HTTP_X_CORRELATION_ID", "").strip()

    safe_regex = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

    request_id = raw_req_id if safe_regex.match(raw_req_id) else uuid.uuid4().hex
    correlation_id = raw_corr_id if safe_regex.match(raw_corr_id) else request_id

    return request_id, correlation_id
