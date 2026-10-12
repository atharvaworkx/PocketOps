from django.contrib.auth.models import User
from rest_framework import serializers

from .models import CheckResult, DiagnosticEvent, Endpoint, Incident, ObservedRequest, Project


# ── Auth ──────────────────────────────────────────────────────────────────────

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "password", "password2")
        extra_kwargs = {"email": {"required": True}}

    def validate(self, data):
        if data["password"] != data["password2"]:
            raise serializers.ValidationError({"password2": "Passwords do not match."})
        return data

    def create(self, validated_data):
        validated_data.pop("password2")
        user = User.objects.create_user(**validated_data)
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "date_joined")
        read_only_fields = ("id", "date_joined")


# ── Project ───────────────────────────────────────────────────────────────────

class ProjectSerializer(serializers.ModelSerializer):
    owner = serializers.StringRelatedField(read_only=True)
    endpoint_count = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = (
            "id", "name", "base_url", "description", "owner",
            "endpoint_count", "created_at", "updated_at",
        )
        read_only_fields = ("id", "owner", "endpoint_count", "created_at", "updated_at")

    def get_endpoint_count(self, obj):
        return obj.endpoints.count()


class ProjectDetailSerializer(ProjectSerializer):
    """Includes ingestion_secret on create only."""

    class Meta(ProjectSerializer.Meta):
        fields = ProjectSerializer.Meta.fields + ("ingestion_secret",)
        read_only_fields = ProjectSerializer.Meta.read_only_fields + ("ingestion_secret",)


# ── Endpoint ──────────────────────────────────────────────────────────────────

class EndpointSerializer(serializers.ModelSerializer):
    bearer_token = serializers.CharField(
        max_length=2000, required=False, allow_blank=True, write_only=True, default=""
    )

    headers = serializers.JSONField(required=False, default=dict)
    project = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Endpoint
        fields = (
            "id", "project", "name", "path", "method",
            "expected_status", "enabled", "bearer_token", "headers", "created_at", "updated_at",
        )
        read_only_fields = ("id", "project", "created_at", "updated_at")

    def validate_headers(self, value):
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise serializers.ValidationError("Headers must be a JSON object (key-value pairs).")
        return value

    def validate_path(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Path must not be empty.")
        if not value.startswith("/"):
            value = "/" + value
        return value

    def validate_project(self, project):
        request = self.context.get("request")
        if request and project.owner != request.user:
            raise serializers.ValidationError("You do not own this project.")
        return project


# ── CheckResult ───────────────────────────────────────────────────────────────

class CheckResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = CheckResult
        fields = (
            "id", "endpoint", "project", "status_code",
            "duration_ms", "success", "error_message",
            "response_summary", "checked_at",
        )
        read_only_fields = fields


# ── Incident ──────────────────────────────────────────────────────────────────

class IncidentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Incident
        fields = (
            "id", "project", "endpoint", "occurred_at", "http_status",
            "diagnostic_category", "summary", "safe_details",
            "suggested_action", "resolution_status", "resolved_at",
        )
        read_only_fields = (
            "id", "occurred_at", "diagnostic_category", "safe_details", "suggested_action",
        )


# ── DiagnosticEvent ingestion ─────────────────────────────────────────────────

class DiagnosticEventIngestSerializer(serializers.Serializer):
    """Validates an incoming diagnostic event from an instrumented target app."""

    schema_version = serializers.CharField(default="1")
    event_id = serializers.CharField(max_length=128, required=False, default="", allow_blank=True)
    correlation_id = serializers.CharField(max_length=128, required=False, default="", allow_blank=True)
    category = serializers.CharField(max_length=50)
    safe_summary = serializers.CharField(max_length=500)
    safe_details = serializers.DictField(
        child=serializers.JSONField(),
        required=False,
        default=dict,
    )
    http_method = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    http_path = serializers.CharField(max_length=500, required=False, default="", allow_blank=True)
    http_status = serializers.IntegerField(required=False, allow_null=True, default=None)
    timestamp = serializers.DateTimeField()

    def validate_schema_version(self, value):
        if value not in ("1",):
            raise serializers.ValidationError(f"Unsupported schema version: {value}")
        return value


class DiagnosticEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = DiagnosticEvent
        fields = (
            "id", "project", "event_id", "correlation_id",
            "category", "safe_summary", "safe_details",
            "http_method", "http_path", "http_status",
            "timestamp", "received_at", "incident",
        )
        read_only_fields = fields


# ── Request Runner ────────────────────────────────────────────────────────────

class RunRequestSerializer(serializers.Serializer):
    method = serializers.ChoiceField(
        choices=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    )
    url = serializers.URLField(max_length=2000)
    headers = serializers.DictField(
        child=serializers.CharField(max_length=1000),
        required=False,
        default=dict,
    )
    bearer_token = serializers.CharField(
        max_length=2000, required=False, allow_blank=True, write_only=True
    )
    json_body = serializers.JSONField(required=False, allow_null=True, default=None)


# ── Observability ─────────────────────────────────────────────────────────────

class ObservedRequestSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(source="user.id", read_only=True, default=None)

    class Meta:
        model = ObservedRequest
        fields = (
            "id",
            "request_id",
            "correlation_id",
            "timestamp",
            "method",
            "path",
            "status_code",
            "duration_ms",
            "classification",
            "user_id",
            "user_identifier",
            "client_ip",
            "error_summary",
        )
        read_only_fields = fields


class ObservedRequestDetailSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(source="user.id", read_only=True, default=None)

    class Meta:
        model = ObservedRequest
        fields = (
            "id",
            "request_id",
            "correlation_id",
            "timestamp",
            "method",
            "path",
            "query_params",
            "status_code",
            "duration_ms",
            "classification",
            "user_id",
            "user_identifier",
            "client_ip",
            "user_agent",
            "error_summary",
            "request_headers",
            "request_body",
            "response_body",
            "exception_type",
            "is_exception",
        )
        read_only_fields = fields
