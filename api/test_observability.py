"""
Automated test suite for PocketOps Backend-Wide API Observability.
Covers:
1. Successful GET request recording
2. Successful POST request recording
3. Validation failure HTTP 400
4. Unauthorized request HTTP 401
5. Missing route HTTP 404
6. Server exception HTTP 500 and diagnostic capture
7. Monotonic duration recording
8. Request ID generation and correlation ID preservation
9. Redaction of sensitive headers and body fields
10. Large body limit truncation
11. Permission enforcement (user scoping and admin access)
12. Pagination and filtering
13. Timestamp ordering
14. Excluded observability endpoints (no recursion loops)
15. Persistence failure isolation (does not break API response)
16. Existing endpoints regression
"""
from unittest.mock import patch
from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from .models import ObservedRequest, Project


def make_user(username="obsuser", password="obspassword123", is_staff=False, is_superuser=False):
    return User.objects.create_user(
        username=username,
        password=password,
        is_staff=is_staff,
        is_superuser=is_superuser,
    )


def auth_client(user):
    client = APIClient()
    refresh = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return client


class ObservabilityAutomatedTests(TestCase):
    def setUp(self):
        self.user = make_user("normal_user", "pass123456")
        self.other_user = make_user("other_user", "pass123456")
        self.admin_user = make_user("admin_user", "pass123456", is_staff=True, is_superuser=True)
        self.client = auth_client(self.user)
        self.admin_client = auth_client(self.admin_user)
        self.anon_client = APIClient()

    def test_01_successful_get_request_recorded(self):
        """1. Successful GET request is recorded with correct status and user."""
        resp = self.client.get("/api/v1/health/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        record = ObservedRequest.objects.filter(path="/api/v1/health/").first()
        self.assertIsNotNone(record)
        self.assertEqual(record.method, "GET")
        self.assertEqual(record.status_code, 200)
        self.assertEqual(record.classification, "success")
        self.assertEqual(record.user, self.user)
        self.assertGreaterEqual(record.duration_ms, 0.0)

    def test_02_successful_post_request_recorded(self):
        """2. Successful POST request creates project and is recorded."""
        payload = {"name": "Test Project", "base_url": "https://api.example.com"}
        resp = self.client.post("/api/v1/projects/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        record = ObservedRequest.objects.filter(path="/api/v1/projects/", method="POST").first()
        self.assertIsNotNone(record)
        self.assertEqual(record.status_code, 201)
        self.assertEqual(record.classification, "success")
        self.assertIn("Test Project", record.request_body)

    def test_03_validation_failure_http_400(self):
        """3. Validation failure returning HTTP 400 is recorded as client_error."""
        resp = self.client.post("/api/v1/projects/", {"name": ""}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

        record = ObservedRequest.objects.filter(path="/api/v1/projects/", status_code=400).first()
        self.assertIsNotNone(record)
        self.assertEqual(record.classification, "client_error")
        self.assertTrue(len(record.error_summary) > 0)

    def test_04_unauthorized_request_http_401(self):
        """4. Unauthorized request returning HTTP 401 is recorded."""
        resp = self.anon_client.get("/api/v1/projects/")
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

        record = ObservedRequest.objects.filter(path="/api/v1/projects/", status_code=401).first()
        self.assertIsNotNone(record)
        self.assertEqual(record.classification, "client_error")
        self.assertEqual(record.user_identifier, "anonymous")
        self.assertIsNone(record.user)

    def test_05_missing_route_http_404(self):
        """5. Missing route returning HTTP 404 is recorded."""
        resp = self.anon_client.get("/api/v1/nonexistent-route-xyz/")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

        record = ObservedRequest.objects.filter(path="/api/v1/nonexistent-route-xyz/").first()
        self.assertIsNotNone(record)
        self.assertEqual(record.status_code, 404)
        self.assertEqual(record.classification, "client_error")

    def test_06_server_exception_http_500(self):
        """6. Server exception is captured safely with exception type and summary."""
        with patch("api.views.HealthView.get", side_effect=RuntimeError("Simulated server crash")):
            resp = self.client.get("/api/v1/health/")
            self.assertEqual(resp.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

        record = ObservedRequest.objects.filter(path="/api/v1/health/", is_exception=True).first()
        self.assertIsNotNone(record)
        self.assertEqual(record.classification, "exception")
        self.assertEqual(record.exception_type, "RuntimeError")
        self.assertIn("Simulated server crash", record.error_summary)

    def test_07_duration_recording(self):
        """7. Duration is recorded monotonically in milliseconds."""
        resp = self.client.get("/api/v1/health/")
        self.assertEqual(resp.status_code, 200)

        record = ObservedRequest.objects.filter(path="/api/v1/health/").first()
        self.assertIsNotNone(record)
        self.assertIsInstance(record.duration_ms, float)
        self.assertGreaterEqual(record.duration_ms, 0.0)

    def test_08_request_id_generation_and_correlation(self):
        """8. Request IDs are extracted or generated and returned in headers."""
        custom_req_id = "test-custom-req-id-12345"
        custom_corr_id = "test-custom-corr-id-67890"

        resp = self.client.get(
            "/api/v1/health/",
            HTTP_X_REQUEST_ID=custom_req_id,
            HTTP_X_CORRELATION_ID=custom_corr_id,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Request-ID"), custom_req_id)

        record = ObservedRequest.objects.filter(request_id=custom_req_id).first()
        self.assertIsNotNone(record)
        self.assertEqual(record.correlation_id, custom_corr_id)

    def test_09_redaction_of_sensitive_headers_and_body(self):
        """9. Passwords, authorization tokens, and secrets are strictly redacted."""
        payload = {
            "username": "secretuser",
            "email": "secret@example.com",
            "password": "SuperSecretPassword123!",
            "password2": "SuperSecretPassword123!",
        }
        # Body redaction test on register
        resp = self.anon_client.post(
            "/api/v1/auth/register/",
            payload,
            format="json",
            HTTP_X_POCKETOPS_SECRET="my_ingest_secret_key",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        record = ObservedRequest.objects.filter(path="/api/v1/auth/register/").first()
        self.assertIsNotNone(record)

        # Body must NOT contain plaintext password
        self.assertNotIn("SuperSecretPassword123!", record.request_body)
        self.assertIn('"password": "[REDACTED]"', record.request_body)
        self.assertEqual(record.request_headers.get("x-pocketops-secret"), "[REDACTED]")

        # Header redaction test on authenticated request
        resp_auth = self.client.get("/api/v1/health/")
        self.assertEqual(resp_auth.status_code, status.HTTP_200_OK)
        record_auth = ObservedRequest.objects.filter(path="/api/v1/health/", user=self.user).first()
        self.assertIsNotNone(record_auth)
        self.assertEqual(record_auth.request_headers.get("authorization"), "[REDACTED]")

    def test_10_large_body_limits(self):
        """10. Very large bodies are bounded and truncated without crashing."""
        large_string = "a" * 20000
        payload = {"name": "LargeProject", "description": large_string, "base_url": "https://example.com"}
        self.client.post("/api/v1/projects/", payload, format="json")

        record = ObservedRequest.objects.filter(path="/api/v1/projects/", method="POST").first()
        self.assertIsNotNone(record)
        self.assertLessEqual(len(record.request_body), 4096)

    def test_11_permission_enforcement(self):
        """11. Normal users only view their own logs; admins view all logs."""
        # User 1 makes a request
        self.client.get("/api/v1/health/")
        # User 2 makes a request
        other_client = auth_client(self.other_user)
        other_client.get("/api/v1/health/")

        # User 1 queries observability API
        resp1 = self.client.get("/api/v1/observability/requests/")
        self.assertEqual(resp1.status_code, status.HTTP_200_OK)
        for item in resp1.data["results"]:
            self.assertEqual(item["user_id"], self.user.id)

        # Admin user queries observability API
        admin_resp = self.admin_client.get("/api/v1/observability/requests/")
        self.assertEqual(admin_resp.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(admin_resp.data["count"], 2)

        # Unauthenticated user is denied
        anon_resp = self.anon_client.get("/api/v1/observability/requests/")
        self.assertEqual(anon_resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_12_pagination_and_filtering(self):
        """12. Supports filtering by status, method, and pagination."""
        self.client.get("/api/v1/health/")
        self.client.post("/api/v1/projects/", {"name": "Proj1", "base_url": "https://test.com"}, format="json")

        # Filter by method POST
        resp = self.admin_client.get("/api/v1/observability/requests/?method=POST")
        self.assertEqual(resp.status_code, 200)
        for res in resp.data["results"]:
            self.assertEqual(res["method"], "POST")

        # Filter by status_code 200
        resp_status = self.admin_client.get("/api/v1/observability/requests/?status_code=200")
        self.assertEqual(resp_status.status_code, 200)
        for res in resp_status.data["results"]:
            self.assertEqual(res["status_code"], 200)

        # Page size check
        resp_page = self.admin_client.get("/api/v1/observability/requests/?page_size=1")
        self.assertEqual(len(resp_page.data["results"]), 1)

    def test_13_timestamp_ordering(self):
        """13. Results are ordered newest first (descending timestamp)."""
        self.client.get("/api/v1/health/")
        self.client.get("/api/v1/projects/")

        resp = self.admin_client.get("/api/v1/observability/requests/")
        results = resp.data["results"]
        self.assertGreaterEqual(len(results), 2)
        # First result should have timestamp >= second result
        self.assertGreaterEqual(results[0]["timestamp"], results[1]["timestamp"])

    def test_14_excluded_observability_endpoints(self):
        """14. Observability queries do not recursively record themselves."""
        ObservedRequest.objects.all().delete()
        self.client.get("/api/v1/health/")
        count_before = ObservedRequest.objects.count()

        # Query observability API multiple times
        self.client.get("/api/v1/observability/requests/")
        self.client.get("/api/v1/observability/requests/")

        count_after = ObservedRequest.objects.count()
        # Count should remain unchanged because /observability/ is excluded
        self.assertEqual(count_before, count_after)

    def test_15_persistence_failure_does_not_break_api(self):
        """15. Database persistence failure does not break original HTTP response."""
        with patch("api.models.ObservedRequest.objects.create", side_effect=Exception("DB connection error")):
            resp = self.client.get("/api/v1/health/")
            # Response must still return 200 OK cleanly
            self.assertEqual(resp.status_code, status.HTTP_200_OK)
            self.assertEqual(resp.data, {"status": "ok", "version": "1"})

    def test_16_regression_existing_endpoints(self):
        """16. Existing project creation, listing, and health endpoints work intact."""
        # Create project
        create_resp = self.client.post(
            "/api/v1/projects/",
            {"name": "Regression Proj", "base_url": "https://example.com"},
            format="json",
        )
        self.assertEqual(create_resp.status_code, status.HTTP_201_CREATED)
        proj_id = create_resp.data["id"]

        # List projects
        list_resp = self.client.get("/api/v1/projects/")
        self.assertEqual(list_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(list_resp.data["count"], 1)

        # Health endpoint
        health_resp = self.client.get("/api/v1/health/")
        self.assertEqual(health_resp.status_code, status.HTTP_200_OK)
