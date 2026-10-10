"""
pocketops_integration.py

Drop this file into any Django/DRF project to send diagnostic events to PocketOps.
Configure POCKETOPS_PROJECT_ID and POCKETOPS_SECRET in your project's environment.

Usage in settings.py:
    REST_FRAMEWORK = {
        "EXCEPTION_HANDLER": "pocketops_integration.pocketops_exception_handler",
    }
"""
import os
import threading
import uuid
from datetime import timezone as dt_timezone
from datetime import datetime

import httpx

POCKETOPS_BASE_URL = os.environ.get("POCKETOPS_BASE_URL", "https://your-pocketops.railway.app")
POCKETOPS_PROJECT_ID = os.environ.get("POCKETOPS_PROJECT_ID", "")
POCKETOPS_SECRET = os.environ.get("POCKETOPS_SECRET", "")
POCKETOPS_ENABLED = bool(POCKETOPS_PROJECT_ID and POCKETOPS_SECRET)

_SAFE_CATEGORY_MAP = {
    "ValidationError": "serializer_validation",
    "AuthenticationFailed": "authentication",
    "NotAuthenticated": "authentication",
    "PermissionDenied": "permission_denied",
    "NotFound": "not_found",
    "Throttled": "throttled",
    # Map Django OperationalError, IntegrityError etc.
    "OperationalError": "database_error",
    "IntegrityError": "database_error",
    "ProgrammingError": "database_error",
}


def _classify_exception(exc) -> tuple[str, str, dict]:
    """
    Returns (category, safe_summary, safe_details).
    Never exposes stack traces, SQL, credentials, or raw exception text.
    """
    exc_type = type(exc).__name__
    category = _SAFE_CATEGORY_MAP.get(exc_type, "unknown")

    if category == "serializer_validation":
        try:
            fields = {}
            if hasattr(exc, "detail") and isinstance(exc.detail, dict):
                for field, messages in exc.detail.items():
                    fields[field] = [str(m) for m in (messages if isinstance(messages, list) else [messages])]
            safe_details = {"fields": fields}
            safe_summary = "Serializer validation failed."
        except Exception:
            safe_details = {}
            safe_summary = "Serializer validation failed."
    elif category == "authentication":
        safe_summary = "Authentication failed."
        safe_details = {"exception_type": exc_type}
    elif category == "permission_denied":
        safe_summary = "Permission denied."
        safe_details = {"exception_type": exc_type}
    elif category == "database_error":
        # NEVER include the actual exception message (may contain SQL/credentials)
        safe_summary = "A database error occurred."
        safe_details = {"error_type": exc_type}
    elif category == "not_found":
        safe_summary = "Resource not found."
        safe_details = {"exception_type": exc_type}
    elif category == "throttled":
        safe_summary = "Request was throttled."
        safe_details = {"exception_type": exc_type}
    else:
        safe_summary = "An unexpected error occurred."
        safe_details = {"exception_type": exc_type}

    return category, safe_summary, safe_details


def _send_event_async(payload: dict) -> None:
    """Fire-and-forget in a background thread. Never blocks the response."""
    if not POCKETOPS_ENABLED:
        return

    def _send():
        try:
            with httpx.Client(timeout=5) as client:
                client.post(
                    f"{POCKETOPS_BASE_URL}/api/v1/ingest/{POCKETOPS_PROJECT_ID}/",
                    json=payload,
                    headers={"X-PocketOps-Secret": POCKETOPS_SECRET},
                )
        except Exception:
            pass  # Never let PocketOps reporting break the target app

    t = threading.Thread(target=_send, daemon=True)
    t.start()


def pocketops_exception_handler(exc, context):
    """
    Drop-in DRF exception handler that also sends diagnostic events to PocketOps.
    """
    from rest_framework.views import exception_handler

    response = exception_handler(exc, context)

    if response is not None:
        category, safe_summary, safe_details = _classify_exception(exc)
        request = context.get("request")

        payload = {
            "schema_version": "1",
            "event_id": str(uuid.uuid4()),
            "category": category,
            "safe_summary": safe_summary,
            "safe_details": safe_details,
            "http_method": request.method if request else "",
            "http_path": request.path if request else "",
            "http_status": response.status_code,
            "timestamp": datetime.now(dt_timezone.utc).isoformat(),
        }

        _send_event_async(payload)

    return response


# ── Safe demo of database_error category (no real DB failure) ────────────────────
def simulate_database_error_event(project_id: str = None, secret: str = None) -> dict:
    """
    Sends a simulated database_error event to PocketOps for demo purposes.
    Does NOT perform any real destructive database operation.
    """
    _proj = project_id or POCKETOPS_PROJECT_ID
    _secret = secret or POCKETOPS_SECRET
    if not (_proj and _secret):
        return {"error": "POCKETOPS_PROJECT_ID and POCKETOPS_SECRET must be set."}

    payload = {
        "schema_version": "1",
        "event_id": str(uuid.uuid4()),
        "category": "database_error",
        "safe_summary": "Simulated database error for PocketOps demo.",
        "safe_details": {"error_type": "OperationalError", "simulated": True},
        "http_method": "GET",
        "http_path": "/demo/simulate-db-error/",
        "http_status": 500,
        "timestamp": datetime.now(dt_timezone.utc).isoformat(),
    }

    try:
        with httpx.Client(timeout=5) as client:
            r = client.post(
                f"{POCKETOPS_BASE_URL}/api/v1/ingest/{_proj}/",
                json=payload,
                headers={"X-PocketOps-Secret": _secret},
            )
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}
