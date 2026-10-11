from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status


def custom_exception_handler(exc, context):
    req = context.get("request") if isinstance(context, dict) else None
    if req is not None:
        try:
            raw_req = getattr(req, "_request", req)
            raw_req._handled_exception = exc
        except Exception:
            pass

    response = exception_handler(exc, context)

    if response is not None:
        response.data = {
            "error": True,
            "status_code": response.status_code,
            "detail": response.data,
        }
        return response

    return Response(
        {
            "error": True,
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
            "detail": "An unexpected error occurred.",
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
