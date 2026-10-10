"""
Rule-based diagnostic explanations. No external AI API. Pure deterministic Python.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class DiagnosticExplanation:
    title: str
    explanation: str
    suggested_action: str
    confidence: str  # "high" | "medium" | "low"
    evidence_notes: str


# Map categories to base explanations
_CATEGORY_BASE: dict[str, dict] = {
    "serializer_validation": {
        "title": "Validation Error",
        "base_explanation": "The request payload failed server-side validation.",
        "confidence": "high",
    },
    "authentication": {
        "title": "Authentication Failure",
        "base_explanation": "The request could not be authenticated.",
        "confidence": "high",
    },
    "permission_denied": {
        "title": "Permission Denied",
        "base_explanation": "The authenticated user does not have permission to perform this action.",
        "confidence": "high",
    },
    "database_error": {
        "title": "Database Error",
        "base_explanation": "A database operation failed.",
        "confidence": "medium",
    },
    "not_found": {
        "title": "Resource Not Found",
        "base_explanation": "The requested resource could not be found.",
        "confidence": "high",
    },
    "throttled": {
        "title": "Rate Limited",
        "base_explanation": "The request was rate-limited by the server.",
        "confidence": "high",
    },
    "unknown": {
        "title": "Unknown Cause",
        "base_explanation": "The cause could not be established from available evidence.",
        "confidence": "low",
    },
}

_CATEGORY_ACTIONS: dict[str, str] = {
    "serializer_validation": (
        "Review the request payload against the API schema. "
        "Check field names, types, and required fields."
    ),
    "authentication": (
        "Verify that the Authorization header is present and contains a valid, non-expired token. "
        "Re-authenticate if the token has expired."
    ),
    "permission_denied": (
        "Ensure the authenticated user has the required role or permissions for this resource. "
        "Contact an administrator if access is needed."
    ),
    "database_error": (
        "Check database connectivity and query constraints. "
        "Review recent schema migrations for potential conflicts."
    ),
    "not_found": (
        "Confirm the resource identifier is correct. "
        "Verify the resource exists and has not been deleted."
    ),
    "throttled": (
        "Reduce request frequency. "
        "Implement exponential back-off and check the Retry-After header if present."
    ),
    "unknown": (
        "Collect more context: check application logs, HTTP status code, and request/response details. "
        "Look for patterns across multiple events."
    ),
}


def explain_diagnostic(
    category: str,
    safe_summary: str,
    safe_details: Optional[dict] = None,
) -> DiagnosticExplanation:
    """
    Produce a rule-based explanation for a diagnostic event.
    Never invents causes beyond what evidence supports.
    """
    safe_details = safe_details or {}

    base = _CATEGORY_BASE.get(category, _CATEGORY_BASE["unknown"])
    action = _CATEGORY_ACTIONS.get(category, _CATEGORY_ACTIONS["unknown"])

    # Build explanation enriched with available evidence
    explanation_parts = [base["base_explanation"]]

    if category == "serializer_validation" and safe_details:
        fields = safe_details.get("fields", {})
        if fields:
            field_summary = "; ".join(
                f"{field}: {', '.join(msgs) if isinstance(msgs, list) else msgs}"
                for field, msgs in fields.items()
            )
            explanation_parts.append(f"Field errors: {field_summary}.")

    if category in ("authentication", "permission_denied") and safe_summary:
        explanation_parts.append(f"Detail: {safe_summary}.")

    if category == "database_error" and safe_details:
        db_type = safe_details.get("error_type", "")
        if db_type:
            explanation_parts.append(f"Error type: {db_type}.")

    # Evidence notes
    if category == "unknown":
        evidence_notes = (
            f"Available summary: '{safe_summary}'. "
            "Insufficient evidence to determine root cause. "
            "Treat as unconfirmed until more data is collected."
        )
    else:
        evidence_notes = f"Category confirmed from event data. Summary: '{safe_summary}'."

    return DiagnosticExplanation(
        title=base["title"],
        explanation=" ".join(explanation_parts),
        suggested_action=action,
        confidence=base["confidence"],
        evidence_notes=evidence_notes,
    )


VALID_CATEGORIES = set(_CATEGORY_BASE.keys())


def normalize_category(raw_category: str) -> str:
    """
    Validate and normalize a client-supplied category.
    Untrusted input is never accepted blindly.
    """
    if raw_category in VALID_CATEGORIES:
        return raw_category
    return "unknown"
