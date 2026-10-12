from typing import Optional, Tuple
from urllib.parse import urlparse
import secrets
from django.utils import timezone
from rest_framework import generics, permissions, status, views
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .diagnostics import explain_diagnostic, normalize_category
from .models import CheckResult, DiagnosticEvent, Endpoint, Incident, ObservedRequest, Project
from .permissions import IsOwner, IsProjectOwner
from .runner import run_request


def get_request_jwt(request) -> Optional[str]:
    """Extract Bearer JWT token from the incoming HTTP request."""
    if not request:
        return None
    auth = request.headers.get("Authorization") or request.META.get("HTTP_AUTHORIZATION", "")
    if auth and auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def resolve_request_auth(request, endpoint: Optional[Endpoint], full_url: str) -> Tuple[dict, Optional[str]]:
    """
    Resolves headers and bearer_token for an outbound probe.
    1. If endpoint has custom headers, start with them.
    2. If endpoint has an explicit bearer_token:
        - If 'auto', 'user_jwt', 'jwt', or 'current_user': use incoming user's JWT.
        - Otherwise, use the explicit token.
    3. If endpoint has no token and no Authorization header:
        - If target host matches the PocketOps host (or localhost/same domain),
          auto-forward the logged-in user's JWT!
    """
    headers = dict(endpoint.headers) if (endpoint and getattr(endpoint, "headers", None) and isinstance(endpoint.headers, dict)) else {}
    raw_token = (endpoint.bearer_token.strip() if endpoint and getattr(endpoint, "bearer_token", None) else "")
    bearer_token = raw_token or None

    user_jwt = get_request_jwt(request)

    # 1. Magic keyword to explicitly use the logged-in user's JWT
    if bearer_token and bearer_token.lower() in ("auto", "user_jwt", "jwt", "current_user"):
        bearer_token = user_jwt

    # 2. Auto-forward JWT if calling own backend / same host and no custom auth is specified
    has_auth_header = any(k.lower() == "authorization" for k in headers.keys())
    if not bearer_token and not has_auth_header and user_jwt and request:
        try:
            target_host = urlparse(full_url).hostname or ""
            target_host = target_host.lower()
            current_host = request.get_host().split(":")[0].lower()

            is_same_host = (target_host == current_host)
            is_local = target_host in ("localhost", "127.0.0.1") and current_host in ("localhost", "127.0.0.1")

            if is_same_host or is_local:
                bearer_token = user_jwt
        except Exception:
            pass

    return headers, bearer_token
from .serializers import (
    CheckResultSerializer,
    DiagnosticEventIngestSerializer,
    DiagnosticEventSerializer,
    EndpointSerializer,
    IncidentSerializer,
    ObservedRequestDetailSerializer,
    ObservedRequestSerializer,
    ProjectDetailSerializer,
    ProjectSerializer,
    RegisterSerializer,
    RunRequestSerializer,
    UserSerializer,
)
from rest_framework.pagination import PageNumberPagination


# ── Health ─────────────────────────────────────────────────────────────────────

class HealthView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response({"status": "ok", "version": "1"})


# ── Auth ────────────────────────────────────────────────────────────────────────

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)


class MeView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


# ── Project ──────────────────────────────────────────────────────────────────────

class ProjectListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        return ProjectSerializer

    def get_queryset(self):
        return Project.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        ingestion_secret = secrets.token_hex(32)
        serializer.save(owner=self.request.user, ingestion_secret=ingestion_secret)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ingestion_secret = secrets.token_hex(32)
        project = serializer.save(owner=request.user, ingestion_secret=ingestion_secret)
        # Return ingestion_secret ONCE on creation
        data = ProjectDetailSerializer(project, context={"request": request}).data
        return Response(data, status=status.HTTP_201_CREATED)


class ProjectRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwner]

    def get_queryset(self):
        return Project.objects.filter(owner=self.request.user)


# ── Endpoint ──────────────────────────────────────────────────────────────────────

class EndpointListCreateView(generics.ListCreateAPIView):
    serializer_class = EndpointSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        project_id = self.kwargs["project_id"]
        return Endpoint.objects.filter(
            project__id=project_id, project__owner=self.request.user
        )

    def perform_create(self, serializer):
        project_id = self.kwargs["project_id"]
        project = Project.objects.get(id=project_id, owner=self.request.user)
        serializer.save(project=project)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        endpoint = serializer.instance
        project = endpoint.project

        # Immediately probe the endpoint so Flutter gets instant feedback
        full_url = project.base_url.rstrip("/") + "/" + endpoint.path.lstrip("/")
        headers, bearer_token = resolve_request_auth(request, endpoint, full_url)
        res = run_request(
            method=endpoint.method,
            url=full_url,
            headers=headers,
            bearer_token=bearer_token,
        )
        success = res["success"]
        if endpoint.expected_status and res.get("status_code"):
            success = res["status_code"] == endpoint.expected_status

        check = CheckResult.objects.create(
            endpoint=endpoint,
            project=project,
            status_code=res.get("status_code"),
            duration_ms=res.get("duration_ms"),
            success=success,
            error_message=res.get("error_message") or "",
            response_summary=(res.get("response_body") or "")[:500],
        )

        if not success:
            explanation = explain_diagnostic(
                "unknown",
                res.get("error_message") or f"HTTP {res.get('status_code')}",
            )
            Incident.objects.create(
                project=project,
                endpoint=endpoint,
                http_status=res.get("status_code"),
                diagnostic_category="unknown",
                summary=res.get("error_message") or f"HTTP {res.get('status_code')}",
                safe_details={"error_kind": res.get("error_kind")},
                suggested_action=explanation.suggested_action,
            )

        data = EndpointSerializer(endpoint, context={"request": request}).data
        data["latest_check"] = CheckResultSerializer(check).data
        return Response(data, status=status.HTTP_201_CREATED)

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        return ctx


class EndpointRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = EndpointSerializer
    permission_classes = [permissions.IsAuthenticated, IsProjectOwner]

    def get_queryset(self):
        return Endpoint.objects.filter(project__owner=self.request.user)


# ── Endpoint Check ─────────────────────────────────────────────────────────────────

class EndpointCheckView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, project_id, endpoint_id):
        try:
            endpoint = Endpoint.objects.get(
                id=endpoint_id,
                project__id=project_id,
                project__owner=request.user,
            )
        except Endpoint.DoesNotExist:
            return Response(
                {"error": True, "detail": "Endpoint not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        project = endpoint.project
        full_url = project.base_url.rstrip("/") + "/" + endpoint.path.lstrip("/")
        headers, bearer_token = resolve_request_auth(request, endpoint, full_url)
        result = run_request(
            method=endpoint.method,
            url=full_url,
            headers=headers,
            bearer_token=bearer_token,
        )

        success = result["success"]
        if endpoint.expected_status and result.get("status_code"):
            success = result["status_code"] == endpoint.expected_status

        check = CheckResult.objects.create(
            endpoint=endpoint,
            project=project,
            status_code=result.get("status_code"),
            duration_ms=result.get("duration_ms"),
            success=success,
            error_message=result.get("error_message") or "",
            response_summary=(result.get("response_body") or "")[:500],
        )

        # Create incident if failed
        if not success:
            category = "unknown"
            summary = result.get("error_message") or f"HTTP {result.get('status_code')}"
            explanation = explain_diagnostic(category, summary)
            Incident.objects.create(
                project=project,
                endpoint=endpoint,
                http_status=result.get("status_code"),
                diagnostic_category=category,
                summary=summary,
                safe_details={"error_kind": result.get("error_kind")},
                suggested_action=explanation.suggested_action,
            )

        return Response(CheckResultSerializer(check).data, status=status.HTTP_200_OK)


class ProjectCheckView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, project_id):
        try:
            project = Project.objects.get(id=project_id, owner=request.user)
        except Project.DoesNotExist:
            return Response(
                {"error": True, "detail": "Project not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        endpoints = Endpoint.objects.filter(project=project, enabled=True)
        results = []

        if not endpoints.exists():
            headers, bearer_token = resolve_request_auth(request, None, project.base_url)
            res = run_request(
                method="GET",
                url=project.base_url,
                headers=headers,
                bearer_token=bearer_token,
            )
            check = CheckResult.objects.create(
                project=project,
                status_code=res.get("status_code"),
                duration_ms=res.get("duration_ms"),
                success=res.get("success", False),
                error_message=res.get("error_message") or "",
                response_summary=(res.get("response_body") or "")[:500],
            )
            if not res.get("success"):
                explanation = explain_diagnostic("unknown", res.get("error_message") or f"HTTP {res.get('status_code')}")
                Incident.objects.create(
                    project=project,
                    http_status=res.get("status_code"),
                    diagnostic_category="unknown",
                    summary=res.get("error_message") or f"HTTP {res.get('status_code')}",
                    safe_details={"error_kind": res.get("error_kind")},
                    suggested_action=explanation.suggested_action,
                )
            results.append(check)
        else:
            for endpoint in endpoints:
                full_url = project.base_url.rstrip("/") + "/" + endpoint.path.lstrip("/")
                headers, bearer_token = resolve_request_auth(request, endpoint, full_url)
                res = run_request(
                    method=endpoint.method,
                    url=full_url,
                    headers=headers,
                    bearer_token=bearer_token,
                )
                success = res["success"]
                if endpoint.expected_status and res.get("status_code"):
                    success = res["status_code"] == endpoint.expected_status

                check = CheckResult.objects.create(
                    endpoint=endpoint,
                    project=project,
                    status_code=res.get("status_code"),
                    duration_ms=res.get("duration_ms"),
                    success=success,
                    error_message=res.get("error_message") or "",
                    response_summary=(res.get("response_body") or "")[:500],
                )
                if not success:
                    explanation = explain_diagnostic("unknown", res.get("error_message") or f"HTTP {res.get('status_code')}")
                    Incident.objects.create(
                        project=project,
                        endpoint=endpoint,
                        http_status=res.get("status_code"),
                        diagnostic_category="unknown",
                        summary=res.get("error_message") or f"HTTP {res.get('status_code')}",
                        safe_details={"error_kind": res.get("error_kind")},
                        suggested_action=explanation.suggested_action,
                    )
                results.append(check)

        return Response(CheckResultSerializer(results[-1]).data if results else {}, status=status.HTTP_201_CREATED)



# ── Check History ─────────────────────────────────────────────────────────────────

class CheckResultListView(generics.ListAPIView):
    serializer_class = CheckResultSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        project_id = self.kwargs["project_id"]
        qs = CheckResult.objects.filter(
            project__id=project_id, project__owner=self.request.user
        )
        endpoint_id = self.request.query_params.get("endpoint_id")
        if endpoint_id:
            qs = qs.filter(endpoint__id=endpoint_id)
        return qs


# ── Incident ──────────────────────────────────────────────────────────────────────

class IncidentListView(generics.ListAPIView):
    serializer_class = IncidentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        project_id = self.kwargs["project_id"]
        return Incident.objects.filter(
            project__id=project_id, project__owner=self.request.user
        )


class IncidentRetrieveView(generics.RetrieveUpdateAPIView):
    serializer_class = IncidentSerializer
    permission_classes = [permissions.IsAuthenticated, IsProjectOwner]

    def get_queryset(self):
        return Incident.objects.filter(project__owner=self.request.user)


# ── Request Runner ─────────────────────────────────────────────────────────────────

class RunRequestView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = RunRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": True, "detail": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = serializer.validated_data
        headers = dict(data.get("headers", {}))
        bearer_token = data.get("bearer_token") or None
        if not bearer_token and not any(k.lower() == "authorization" for k in headers.keys()):
            _h, auto_token = resolve_request_auth(request, None, data["url"])
            if auto_token:
                bearer_token = auto_token

        result = run_request(
            method=data["method"],
            url=data["url"],
            headers=headers,
            bearer_token=bearer_token,
            json_body=data.get("json_body"),
        )
        return Response(result, status=status.HTTP_200_OK)


# ── Diagnostic Ingestion ───────────────────────────────────────────────────────────

class DiagnosticIngestView(views.APIView):
    permission_classes = [permissions.AllowAny]  # Auth via ingestion_secret header

    def post(self, request, project_id):
        # Authenticate via X-PocketOps-Secret header
        provided_secret = request.headers.get("X-PocketOps-Secret", "")
        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            # Constant-time-ish response to avoid project enumeration
            return Response(
                {"error": True, "detail": "Unauthorized."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not provided_secret or provided_secret != project.ingestion_secret:
            return Response(
                {"error": True, "detail": "Unauthorized."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        serializer = DiagnosticEventIngestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": True, "detail": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        d = serializer.validated_data
        # Validate and normalize category; never trust client blindly
        category = normalize_category(d["category"])
        explanation = explain_diagnostic(
            category=category,
            safe_summary=d["safe_summary"],
            safe_details=d.get("safe_details", {}),
        )

        event = DiagnosticEvent.objects.create(
            project=project,
            event_id=d.get("event_id", ""),
            correlation_id=d.get("correlation_id", ""),
            category=category,
            safe_summary=d["safe_summary"],
            safe_details=d.get("safe_details", {}),
            http_method=d.get("http_method", ""),
            http_path=d.get("http_path", ""),
            http_status=d.get("http_status"),
            timestamp=d["timestamp"],
        )

        # Auto-create incident for non-200 events
        incident = Incident.objects.create(
            project=project,
            http_status=d.get("http_status"),
            diagnostic_category=category,
            summary=d["safe_summary"],
            safe_details=d.get("safe_details", {}),
            suggested_action=explanation.suggested_action,
        )
        event.incident = incident
        event.save(update_fields=["incident"])

        return Response(
            {
                "received": True,
                "event_id": str(event.id),
                "incident_id": str(incident.id),
                "explanation": {
                    "title": explanation.title,
                    "explanation": explanation.explanation,
                    "suggested_action": explanation.suggested_action,
                    "confidence": explanation.confidence,
                },
            },
            status=status.HTTP_201_CREATED,
        )


class DiagnosticEventListView(generics.ListAPIView):
    serializer_class = DiagnosticEventSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        project_id = self.kwargs["project_id"]
        return DiagnosticEvent.objects.filter(
            project__id=project_id, project__owner=self.request.user
        )


# ── Observability ─────────────────────────────────────────────────────────────

class ObservabilityPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


class ObservedRequestListView(generics.ListAPIView):
    serializer_class = ObservedRequestSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = ObservabilityPagination

    def get_queryset(self):
        user = self.request.user
        if user.is_staff or user.is_superuser:
            qs = ObservedRequest.objects.all()
        else:
            qs = ObservedRequest.objects.filter(user=user)

        status_code = self.request.query_params.get("status_code")
        if status_code:
            try:
                qs = qs.filter(status_code=int(status_code))
            except ValueError:
                pass

        method = self.request.query_params.get("method")
        if method:
            qs = qs.filter(method__iexact=method.strip())

        path = self.request.query_params.get("path")
        if path:
            qs = qs.filter(path__icontains=path.strip())

        classification = self.request.query_params.get("classification")
        if classification:
            qs = qs.filter(classification__iexact=classification.strip())

        request_id = self.request.query_params.get("request_id")
        if request_id:
            qs = qs.filter(request_id__icontains=request_id.strip())

        start_time = self.request.query_params.get("start_time")
        if start_time:
            qs = qs.filter(timestamp__gte=start_time)

        end_time = self.request.query_params.get("end_time")
        if end_time:
            qs = qs.filter(timestamp__lte=end_time)

        min_duration_ms = self.request.query_params.get("min_duration_ms")
        if min_duration_ms:
            try:
                qs = qs.filter(duration_ms__gte=float(min_duration_ms))
            except ValueError:
                pass

        max_duration_ms = self.request.query_params.get("max_duration_ms")
        if max_duration_ms:
            try:
                qs = qs.filter(duration_ms__lte=float(max_duration_ms))
            except ValueError:
                pass

        return qs


class ObservedRequestDetailView(generics.RetrieveAPIView):
    serializer_class = ObservedRequestDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff or user.is_superuser:
            return ObservedRequest.objects.all()
        return ObservedRequest.objects.filter(user=user)
