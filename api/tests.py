"""
Focused automated tests for PocketOps backend.
Run with: python manage.py test api
"""
from unittest.mock import MagicMock, patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from .diagnostics import explain_diagnostic, normalize_category
from .models import DiagnosticEvent, Endpoint, Incident, Project
from .runner import RunnerError, _validate_url


def make_user(username="testuser", password="testpass123"):
    return User.objects.create_user(username=username, password=password)


def auth_client(user):
    client = APIClient()
    refresh = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return client


def make_project(owner, name="TestProject", base_url="https://example.com"):
    return Project.objects.create(
        owner=owner,
        name=name,
        base_url=base_url,
        ingestion_secret="test-secret-abc123",
    )


# ── Diagnostics ───────────────────────────────────────────────────────────────────

class DiagnosticsTest(TestCase):
    def test_serializer_validation_explains_fields(self):
        exp = explain_diagnostic(
            "serializer_validation",
            "Validation failed",
            {"fields": {"email": ["Enter a valid email."]}},
        )
        self.assertEqual(exp.title, "Validation Error")
        self.assertIn("email", exp.explanation)
        self.assertEqual(exp.confidence, "high")

    def test_authentication_category(self):
        exp = explain_diagnostic("authentication", "Token is invalid or expired.")
        self.assertEqual(exp.title, "Authentication Failure")
        self.assertEqual(exp.confidence, "high")

    def test_permission_denied_category(self):
        exp = explain_diagnostic("permission_denied", "You do not have permission.")
        self.assertEqual(exp.title, "Permission Denied")

    def test_unknown_category_low_confidence(self):
        exp = explain_diagnostic("unknown", "Something went wrong.")
        self.assertEqual(exp.confidence, "low")
        self.assertEqual(exp.title, "Unknown Cause")
        self.assertIn("could not be established", exp.explanation)

    def test_normalize_category_rejects_arbitrary(self):
        self.assertEqual(normalize_category("rm -rf /"), "unknown")
        self.assertEqual(normalize_category("SQL_INJECTION"), "unknown")

    def test_normalize_category_accepts_valid(self):
        self.assertEqual(normalize_category("database_error"), "database_error")
        self.assertEqual(normalize_category("throttled"), "throttled")


# ── SSRF / Runner URL validation ──────────────────────────────────────────────────

class RunnerUrlValidationTest(TestCase):
    def test_blocks_loopback(self):
        with self.assertRaises(RunnerError) as ctx:
            _validate_url("http://127.0.0.1/anything")
        self.assertEqual(ctx.exception.error_kind, "ssrf_blocked")

    def test_blocks_localhost(self):
        with self.assertRaises(RunnerError) as ctx:
            _validate_url("http://localhost/anything")
        self.assertIn(ctx.exception.error_kind, ("ssrf_blocked", "dns_error"))

    def test_blocks_private_class_a(self):
        with self.assertRaises(RunnerError) as ctx:
            _validate_url("http://10.0.0.1/api")
        self.assertEqual(ctx.exception.error_kind, "ssrf_blocked")

    def test_blocks_private_class_c(self):
        with self.assertRaises(RunnerError) as ctx:
            _validate_url("http://192.168.1.100/api")
        self.assertEqual(ctx.exception.error_kind, "ssrf_blocked")

    def test_blocks_metadata_service(self):
        with self.assertRaises(RunnerError) as ctx:
            _validate_url("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(ctx.exception.error_kind, "ssrf_blocked")

    def test_blocks_ftp_scheme(self):
        with self.assertRaises(RunnerError) as ctx:
            _validate_url("ftp://example.com/file")
        self.assertEqual(ctx.exception.error_kind, "invalid_scheme")

    def test_allows_public_https(self):
        # This should not raise — public domain (DNS resolution needed)
        # We mock DNS to return a public IP
        with patch("api.runner.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(None, None, None, None, ("1.2.3.4", 443))]
            _validate_url("https://api.example.com/test")  # Should not raise


# ── Auth API ─────────────────────────────────────────────────────────────────────────

class AuthApiTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_register_success(self):
        res = self.client.post(
            "/api/v1/auth/register/",
            {"username": "newuser", "email": "newuser@example.com", "password": "Str0ngPass!", "password2": "Str0ngPass!"},
            format="json",
        )
        self.assertEqual(res.status_code, 201)
        self.assertIn("username", res.data)

    def test_register_password_mismatch(self):
        res = self.client.post(
            "/api/v1/auth/register/",
            {"username": "newuser", "email": "x@x.com", "password": "abc", "password2": "xyz"},
            format="json",
        )
        self.assertEqual(res.status_code, 400)

    def test_obtain_token(self):
        make_user("tokuser", "tokpass123")
        res = self.client.post(
            "/api/v1/auth/token/",
            {"username": "tokuser", "password": "tokpass123"},
            format="json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("access", res.data)

    def test_me_requires_auth(self):
        res = self.client.get("/api/v1/auth/me/")
        self.assertEqual(res.status_code, 401)


# ── Project ownership & permissions ──────────────────────────────────────────────────

class ProjectPermissionsTest(TestCase):
    def setUp(self):
        self.user1 = make_user("user1", "pass1234!")
        self.user2 = make_user("user2", "pass1234!")
        self.client1 = auth_client(self.user1)
        self.client2 = auth_client(self.user2)
        self.project = make_project(self.user1)

    def test_user_sees_own_projects(self):
        res = self.client1.get("/api/v1/projects/")
        self.assertEqual(res.status_code, 200)
        ids = [p["id"] for p in res.data["results"]]
        self.assertIn(str(self.project.id), ids)

    def test_user2_cannot_see_user1_project(self):
        res = self.client2.get(f"/api/v1/projects/{self.project.id}/")
        self.assertEqual(res.status_code, 404)

    def test_user2_cannot_delete_user1_project(self):
        res = self.client2.delete(f"/api/v1/projects/{self.project.id}/")
        self.assertEqual(res.status_code, 404)

    def test_create_project_returns_ingestion_secret_once(self):
        res = self.client1.post(
            "/api/v1/projects/",
            {"name": "NewProj", "base_url": "https://newproject.example.com"},
            format="json",
        )
        self.assertEqual(res.status_code, 201)
        self.assertIn("ingestion_secret", res.data)
        # Verify it's not returned on subsequent GET
        project_id = res.data["id"]
        res2 = self.client1.get(f"/api/v1/projects/{project_id}/")
        self.assertNotIn("ingestion_secret", res2.data)


# ── Error response format consistency ────────────────────────────────────────────────

class ErrorResponseFormatTest(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client = auth_client(self.user)

    def test_404_has_consistent_shape(self):
        res = self.client.get("/api/v1/projects/00000000-0000-0000-0000-000000000000/")
        self.assertIn(res.status_code, [404])
        self.assertIn("error", res.data)
        self.assertTrue(res.data["error"])

    def test_validation_error_has_consistent_shape(self):
        res = self.client.post("/api/v1/projects/", {"name": ""}, format="json")
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.data)


# ── Diagnostic ingestion authentication ──────────────────────────────────────────────

class DiagnosticIngestionAuthTest(TestCase):
    def setUp(self):
        self.user = make_user("diaguser", "diagpass!")
        self.project = make_project(self.user)
        self.client = APIClient()

    def _ingest_payload(self):
        return {
            "schema_version": "1",
            "category": "serializer_validation",
            "safe_summary": "Validation failed on email field.",
            "safe_details": {"fields": {"email": ["Enter a valid email."]}},
            "http_method": "POST",
            "http_path": "/api/users/",
            "http_status": 400,
            "timestamp": timezone.now().isoformat(),
        }

    def test_ingestion_rejected_without_secret(self):
        res = self.client.post(
            f"/api/v1/ingest/{self.project.id}/",
            self._ingest_payload(),
            format="json",
        )
        self.assertEqual(res.status_code, 401)

    def test_ingestion_rejected_with_wrong_secret(self):
        self.client.credentials(**{"HTTP_X_POCKETOPS_SECRET": "wrong-secret"})
        res = self.client.post(
            f"/api/v1/ingest/{self.project.id}/",
            self._ingest_payload(),
            format="json",
        )
        self.assertEqual(res.status_code, 401)

    def test_ingestion_accepted_with_correct_secret(self):
        self.client.credentials(**{"HTTP_X_POCKETOPS_SECRET": "test-secret-abc123"})
        res = self.client.post(
            f"/api/v1/ingest/{self.project.id}/",
            self._ingest_payload(),
            format="json",
        )
        self.assertEqual(res.status_code, 201)
        self.assertIn("event_id", res.data)
        self.assertIn("explanation", res.data)

    def test_ingestion_normalizes_invalid_category(self):
        self.client.credentials(**{"HTTP_X_POCKETOPS_SECRET": "test-secret-abc123"})
        payload = self._ingest_payload()
        payload["category"] = "malicious_injection"
        res = self.client.post(
            f"/api/v1/ingest/{self.project.id}/",
            payload,
            format="json",
        )
        self.assertEqual(res.status_code, 201)
        event = DiagnosticEvent.objects.get(id=res.data["event_id"])
        self.assertEqual(event.category, "unknown")


# ── Request runner integration (mocked) ───────────────────────────────────────────────

class RequestRunnerApiTest(TestCase):
    def setUp(self):
        self.user = make_user("runuser", "runpass123!")
        self.client = auth_client(self.user)

    @patch("api.runner.socket.getaddrinfo")
    @patch("api.runner.httpx.Client")
    def test_run_returns_result(self, mock_client_cls, mock_dns):
        mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"ok": true}'
        mock_response.headers = {"content-type": "application/json"}
        mock_response.history = []
        mock_client_inst = MagicMock()
        mock_client_inst.__enter__ = lambda s: mock_client_inst
        mock_client_inst.__exit__ = MagicMock(return_value=False)
        mock_client_inst.request.return_value = mock_response
        mock_client_cls.return_value = mock_client_inst

        res = self.client.post(
            "/api/v1/run/",
            {"method": "GET", "url": "https://example.com/api/test"},
            format="json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["status_code"], 200)
        self.assertIsNone(res.data["error_kind"])

    def test_run_blocks_loopback(self):
        res = self.client.post(
            "/api/v1/run/",
            {"method": "GET", "url": "http://127.0.0.1/secret"},
            format="json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.data["success"])
        self.assertEqual(res.data["error_kind"], "ssrf_blocked")

    def test_run_requires_auth(self):
        unauthd_client = APIClient()
        res = unauthd_client.post(
            "/api/v1/run/",
            {"method": "GET", "url": "https://example.com/"},
            format="json",
        )
        self.assertEqual(res.status_code, 401)

    def test_run_rejects_invalid_method(self):
        res = self.client.post(
            "/api/v1/run/",
            {"method": "INVALID", "url": "https://example.com/"},
            format="json",
        )
        self.assertEqual(res.status_code, 400)
