from django.contrib import admin
from .models import CheckResult, DiagnosticEvent, Endpoint, Incident, Project


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "base_url", "created_at")
    list_filter = ("owner",)
    search_fields = ("name", "base_url")
    readonly_fields = ("id", "ingestion_secret", "created_at", "updated_at")


@admin.register(Endpoint)
class EndpointAdmin(admin.ModelAdmin):
    list_display = ("name", "project", "method", "path", "enabled")
    list_filter = ("method", "enabled", "project")
    search_fields = ("name", "path")


@admin.register(CheckResult)
class CheckResultAdmin(admin.ModelAdmin):
    list_display = ("endpoint", "status_code", "success", "duration_ms", "checked_at")
    list_filter = ("success",)
    readonly_fields = ("id", "checked_at")


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("project", "summary", "diagnostic_category", "resolution_status", "occurred_at")
    list_filter = ("resolution_status", "diagnostic_category")
    search_fields = ("summary",)
    readonly_fields = ("id", "occurred_at")


@admin.register(DiagnosticEvent)
class DiagnosticEventAdmin(admin.ModelAdmin):
    list_display = ("project", "category", "safe_summary", "http_status", "received_at")
    list_filter = ("category",)
    search_fields = ("safe_summary", "event_id")
    readonly_fields = ("id", "received_at")
