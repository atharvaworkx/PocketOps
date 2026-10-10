from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenBlacklistView

from .views import (
    CheckResultListView,
    DiagnosticEventListView,
    DiagnosticIngestView,
    EndpointCheckView,
    EndpointListCreateView,
    EndpointRetrieveUpdateDestroyView,
    HealthView,
    IncidentListView,
    IncidentRetrieveView,
    MeView,
    ProjectListCreateView,
    ProjectRetrieveUpdateDestroyView,
    ProjectCheckView,
    RegisterView,

    RunRequestView,
)

urlpatterns = [
    # Health
    path("health/", HealthView.as_view(), name="health"),

    # Auth
    path("auth/register/", RegisterView.as_view(), name="auth-register"),
    path("auth/token/", TokenObtainPairView.as_view(), name="auth-token"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="auth-token-refresh"),
    path("auth/token/blacklist/", TokenBlacklistView.as_view(), name="auth-token-blacklist"),
    path("auth/me/", MeView.as_view(), name="auth-me"),

    # Projects
    path("projects/", ProjectListCreateView.as_view(), name="project-list"),
    path("projects/<uuid:pk>/", ProjectRetrieveUpdateDestroyView.as_view(), name="project-detail"),

    # Endpoints (nested under project)
    path(
        "projects/<uuid:project_id>/endpoints/",
        EndpointListCreateView.as_view(),
        name="endpoint-list",
    ),
    path(
        "projects/<uuid:project_id>/endpoints/<uuid:pk>/",
        EndpointRetrieveUpdateDestroyView.as_view(),
        name="endpoint-detail",
    ),

    # Endpoint check
    path(
        "projects/<uuid:project_id>/check/",
        ProjectCheckView.as_view(),
        name="project-check",
    ),
    path(
        "projects/<uuid:project_id>/endpoints/<uuid:endpoint_id>/check/",
        EndpointCheckView.as_view(),
        name="endpoint-check",
    ),

    # Check history
    path(
        "projects/<uuid:project_id>/checks/",
        CheckResultListView.as_view(),
        name="check-list",
    ),

    # Incidents
    path(
        "projects/<uuid:project_id>/incidents/",
        IncidentListView.as_view(),
        name="incident-list",
    ),
    path(
        "projects/<uuid:project_id>/incidents/<uuid:pk>/",
        IncidentRetrieveView.as_view(),
        name="incident-detail",
    ),

    # Request runner
    path("run/", RunRequestView.as_view(), name="run-request"),

    # Diagnostic ingestion (authenticated with X-PocketOps-Secret)
    path(
        "ingest/<uuid:project_id>/",
        DiagnosticIngestView.as_view(),
        name="diagnostic-ingest",
    ),

    # Diagnostic events list (for project owner)
    path(
        "projects/<uuid:project_id>/events/",
        DiagnosticEventListView.as_view(),
        name="diagnostic-event-list",
    ),
]
