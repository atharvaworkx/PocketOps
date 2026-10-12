import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class Project(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="projects")
    name = models.CharField(max_length=255)
    base_url = models.URLField(max_length=500)
    description = models.TextField(blank=True, default="")
    ingestion_secret = models.CharField(max_length=128, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.owner.username})"


class Endpoint(models.Model):
    class HttpMethod(models.TextChoices):
        GET = "GET", "GET"
        POST = "POST", "POST"
        PUT = "PUT", "PUT"
        PATCH = "PATCH", "PATCH"
        DELETE = "DELETE", "DELETE"
        HEAD = "HEAD", "HEAD"
        OPTIONS = "OPTIONS", "OPTIONS"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="endpoints")
    name = models.CharField(max_length=255)
    path = models.CharField(max_length=1000)
    method = models.CharField(max_length=10, choices=HttpMethod.choices, default=HttpMethod.GET)
    expected_status = models.IntegerField(null=True, blank=True)
    enabled = models.BooleanField(default=True)
    bearer_token = models.CharField(max_length=2000, blank=True, default="")
    headers = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.method} {self.path}"


class CheckResult(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    endpoint = models.ForeignKey(Endpoint, on_delete=models.SET_NULL, null=True, blank=True, related_name="check_results")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="check_results")
    status_code = models.IntegerField(null=True, blank=True)
    duration_ms = models.FloatField(null=True, blank=True)
    success = models.BooleanField(default=False)
    error_message = models.CharField(max_length=500, blank=True, default="")
    response_summary = models.TextField(blank=True, default="")
    checked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-checked_at"]

    def __str__(self):
        return f"Check {self.endpoint} -> {self.status_code}"


class Incident(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        RESOLVED = "resolved", "Resolved"
        ACKNOWLEDGED = "acknowledged", "Acknowledged"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="incidents")
    endpoint = models.ForeignKey(
        Endpoint, on_delete=models.SET_NULL, null=True, blank=True, related_name="incidents"
    )
    occurred_at = models.DateTimeField(auto_now_add=True)
    http_status = models.IntegerField(null=True, blank=True)
    diagnostic_category = models.CharField(max_length=100, blank=True, default="unknown")
    summary = models.CharField(max_length=500)
    safe_details = models.JSONField(default=dict, blank=True)
    suggested_action = models.TextField(blank=True, default="")
    resolution_status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.OPEN
    )
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-occurred_at"]

    def __str__(self):
        return f"Incident({self.project.name}): {self.summary[:60]}"


class DiagnosticEvent(models.Model):
    """
    Separate from Incident: DiagnosticEvent is raw ingested data from the
    user's target app. Incidents are derived summaries shown to users.
    We keep them separate so raw ingested data is isolated from UI-facing data.
    """

    CATEGORY_CHOICES = [
        ("serializer_validation", "Serializer Validation"),
        ("authentication", "Authentication"),
        ("permission_denied", "Permission Denied"),
        ("database_error", "Database Error"),
        ("not_found", "Not Found"),
        ("throttled", "Throttled"),
        ("unknown", "Unknown"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="diagnostic_events")
    event_id = models.CharField(max_length=128, blank=True, default="")
    correlation_id = models.CharField(max_length=128, blank=True, default="")
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default="unknown")
    safe_summary = models.CharField(max_length=500)
    safe_details = models.JSONField(default=dict, blank=True)
    http_method = models.CharField(max_length=10, blank=True, default="")
    http_path = models.CharField(max_length=500, blank=True, default="")
    http_status = models.IntegerField(null=True, blank=True)
    timestamp = models.DateTimeField()
    received_at = models.DateTimeField(auto_now_add=True)
    incident = models.ForeignKey(
        Incident,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="diagnostic_events",
    )

    class Meta:
        ordering = ["-received_at"]

    def __str__(self):
        return f"DiagnosticEvent({self.category}): {self.safe_summary[:60]}"


class ObservedRequest(models.Model):
    class Classification(models.TextChoices):
        SUCCESS = "success", "Success"
        CLIENT_ERROR = "client_error", "Client Error"
        SERVER_ERROR = "server_error", "Server Error"
        EXCEPTION = "exception", "Exception"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request_id = models.CharField(max_length=64, db_index=True)
    correlation_id = models.CharField(max_length=64, blank=True, default="", db_index=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    method = models.CharField(max_length=10, db_index=True)
    path = models.CharField(max_length=1000, db_index=True)
    query_params = models.JSONField(default=dict, blank=True)
    status_code = models.IntegerField(db_index=True)
    duration_ms = models.FloatField()
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="observed_requests"
    )
    user_identifier = models.CharField(max_length=150, blank=True, default="")
    client_ip = models.CharField(max_length=45, blank=True, default="")
    user_agent = models.CharField(max_length=500, blank=True, default="")
    classification = models.CharField(
        max_length=25, choices=Classification.choices, default=Classification.SUCCESS, db_index=True
    )
    error_summary = models.CharField(max_length=500, blank=True, default="")
    request_headers = models.JSONField(default=dict, blank=True)
    request_body = models.TextField(blank=True, default="")
    response_body = models.TextField(blank=True, default="")
    exception_type = models.CharField(max_length=100, blank=True, default="")
    is_exception = models.BooleanField(default=False)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["-timestamp"]),
            models.Index(fields=["status_code", "-timestamp"]),
            models.Index(fields=["method", "-timestamp"]),
            models.Index(fields=["path", "-timestamp"]),
            models.Index(fields=["classification", "-timestamp"]),
            models.Index(fields=["request_id"]),
        ]

    def __str__(self):
        return f"{self.method} {self.path} -> {self.status_code} ({self.duration_ms}ms)"
