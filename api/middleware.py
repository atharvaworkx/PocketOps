"""
Observability Middleware for PocketOps.
Captures incoming requests, records duration, response status,
sanitized headers/bodies, and persists events safely.
"""
import logging
import time
from typing import Optional

from django.utils import timezone

from .models import ObservedRequest
from .observability import (
    classify_request,
    extract_client_ip,
    extract_or_generate_request_ids,
    sanitize_body,
    sanitize_headers,
    sanitize_query_params,
)

logger = logging.getLogger(__name__)

EXCLUDED_PATH_PREFIXES = (
    "/api/v1/observability/",
    "/static/",
    "/favicon.ico",
)


class ObservabilityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path_info or request.path

        # Avoid recursion or noise for observability endpoints and static assets
        if any(path.startswith(prefix) for prefix in EXCLUDED_PATH_PREFIXES):
            return self.get_response(request)

        request_id, correlation_id = extract_or_generate_request_ids(request)
        request.request_id = request_id
        request.correlation_id = correlation_id

        # Safely buffer request body if present
        request_body_bytes = b""
        if request.body:
            request_body_bytes = request.body

        start_time = time.monotonic()
        exception_obj: Optional[Exception] = None
        response = None

        try:
            response = self.get_response(request)
        except Exception as exc:
            exception_obj = exc
            raise exc
        finally:
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            self._record_event(
                request=request,
                response=response,
                exception=exception_obj,
                duration_ms=duration_ms,
                request_body_bytes=request_body_bytes,
                request_id=request_id,
                correlation_id=correlation_id,
            )

        if response is not None and not response.has_header("X-Request-ID"):
            response["X-Request-ID"] = request_id

        return response

    def _record_event(
        self,
        request,
        response,
        exception: Optional[Exception],
        duration_ms: float,
        request_body_bytes: bytes,
        request_id: str,
        correlation_id: str,
    ):
        try:
            status_code = 500
            if response is not None:
                status_code = response.status_code

            if exception is None and status_code >= 500:
                exception = getattr(request, "_handled_exception", None)

            is_exception = (exception is not None) and (status_code >= 500)
            exception_type = type(exception).__name__ if is_exception else ""
            error_summary = ""

            if is_exception:
                error_summary = str(exception)[:500]
            elif status_code >= 400 and response is not None:
                if hasattr(response, "data") and isinstance(response.data, dict):
                    detail_val = response.data.get("detail", response.data)
                    error_summary = str(detail_val)[:500]
                elif hasattr(response, "content") and not getattr(response, "streaming", False):
                    error_summary = response.content[:500].decode("utf-8", errors="replace")

            classification = classify_request(status_code=status_code, is_exception=is_exception)

            # Resolve user (DRF authenticates within view processing)
            user = None
            user_identifier = "anonymous"
            req_user = getattr(request, "user", None)
            if req_user and req_user.is_authenticated:
                user = req_user
                user_identifier = req_user.username

            # Sanitize bodies and headers
            sanitized_req_body = sanitize_body(request_body_bytes, max_bytes=4096)

            sanitized_resp_body = ""
            if response is not None and not getattr(response, "streaming", False):
                try:
                    sanitized_resp_body = sanitize_body(response.content, max_bytes=4096)
                except Exception:
                    sanitized_resp_body = ""

            client_ip = extract_client_ip(request)
            user_agent = request.META.get("HTTP_USER_AGENT", "")[:500]
            sanitized_headers = sanitize_headers(request.META)
            sanitized_query = sanitize_query_params(request.GET)

            ObservedRequest.objects.create(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=timezone.now(),
                method=request.method[:10].upper(),
                path=request.path[:1000],
                query_params=sanitized_query,
                status_code=status_code,
                duration_ms=duration_ms,
                user=user,
                user_identifier=user_identifier,
                client_ip=client_ip,
                user_agent=user_agent,
                classification=classification,
                error_summary=error_summary,
                request_headers=sanitized_headers,
                request_body=sanitized_req_body,
                response_body=sanitized_resp_body,
                exception_type=exception_type,
                is_exception=is_exception,
            )
        except Exception as persist_err:
            # Observability persistence MUST never break user API requests
            logger.exception("Failed to persist observed request: %s", persist_err)
