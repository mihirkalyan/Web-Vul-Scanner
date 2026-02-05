"""
Tests for ScanRequest and ScanResponse Models
"""

import pytest
import json
from datetime import datetime
from src.models import (
    ScanRequest,
    ScanResponse,
    HTTPMethod,
    ContentType,
    Cookie,
)


class TestScanRequestBasic:
    """Test basic ScanRequest functionality."""

    def test_create_basic_request(self):
        """Test creating a basic GET request."""
        request = ScanRequest(url="https://example.com/api/users")
        assert request.url == "https://example.com/api/users"
        assert request.method == HTTPMethod.GET
        assert request.headers == {}
        assert request.cookies == {}
        assert request.params == {}
        assert request.body is None

    def test_create_post_request_with_body(self):
        """Test creating a POST request with body."""
        body = {"username": "admin", "password": "test123"}
        request = ScanRequest(
            url="https://example.com/login",
            method=HTTPMethod.POST,
            body=body,
        )
        assert request.method == HTTPMethod.POST
        assert request.body == body
        assert request.content_type == ContentType.JSON

    def test_method_case_insensitive(self):
        """Test that HTTP methods are case-insensitive."""
        request1 = ScanRequest(url="https://example.com", method="post")
        request2 = ScanRequest(url="https://example.com", method="POST")
        request3 = ScanRequest(url="https://example.com", method=HTTPMethod.POST)

        assert request1.method == request2.method == request3.method == HTTPMethod.POST

    def test_invalid_url_raises_error(self):
        """Test that invalid URLs raise validation error."""
        with pytest.raises(ValueError):
            ScanRequest(url="not-a-valid-url")

    def test_auto_detect_json_content_type(self):
        """Test automatic JSON content type detection."""
        request = ScanRequest(
            url="https://example.com",
            body={"key": "value"},
        )
        assert request.content_type == ContentType.JSON

    def test_auto_detect_form_content_type(self):
        """Test automatic form content type detection from header."""
        request = ScanRequest(
            url="https://example.com",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="username=admin&password=test",
        )
        assert request.content_type == ContentType.FORM


class TestScanRequestHeaders:
    """Test header manipulation methods."""

    @pytest.fixture
    def request(self):
        return ScanRequest(url="https://example.com")

    def test_set_get_header(self, request):
        """Test setting and getting headers."""
        request.set_header("Authorization", "Bearer token123")
        assert request.get_header("Authorization") == "Bearer token123"

    def test_case_insensitive_header_get(self, request):
        """Test case-insensitive header retrieval."""
        request.set_header("Content-Type", "application/json")
        assert request.get_header("content-type") == "application/json"
        assert request.get_header("CONTENT-TYPE") == "application/json"

    def test_delete_header(self, request):
        """Test deleting headers."""
        request.set_header("X-Custom", "value")
        assert "X-Custom" in request.headers
        request.delete_header("X-Custom")
        assert "X-Custom" not in request.headers

    def test_delete_header_case_insensitive(self, request):
        """Test case-insensitive header deletion."""
        request.set_header("X-Custom-Header", "value")
        request.delete_header("x-custom-header")
        assert request.get_header("X-Custom-Header") is None

    def test_header_chaining(self, request):
        """Test method chaining with headers."""
        result = (
            request.set_header("Authorization", "Bearer token")
            .set_header("Content-Type", "application/json")
            .set_header("X-Custom", "value")
        )
        assert result is request
        assert len(request.headers) == 3


class TestScanRequestCookies:
    """Test cookie manipulation methods."""

    @pytest.fixture
    def request(self):
        return ScanRequest(url="https://example.com")

    def test_set_get_cookie(self, request):
        """Test setting and getting cookies."""
        request.set_cookie("session_id", "abc123xyz")
        assert request.get_cookie("session_id") == "abc123xyz"

    def test_cookie_syncs_to_header(self, request):
        """Test that cookies sync to Cookie header."""
        request.set_cookie("session", "token123")
        request.set_cookie("user_id", "42")
        
        cookie_header = request.get_header("Cookie")
        assert "session=token123" in cookie_header
        assert "user_id=42" in cookie_header

    def test_delete_cookie(self, request):
        """Test deleting cookies."""
        request.set_cookie("temp", "value")
        assert request.get_cookie("temp") == "value"
        request.delete_cookie("temp")
        assert request.get_cookie("temp") is None

    def test_cookie_chaining(self, request):
        """Test method chaining with cookies."""
        result = (
            request.set_cookie("session", "token1")
            .set_cookie("user", "admin")
            .set_cookie("theme", "dark")
        )
        assert result is request
        assert len(request.cookies) == 3


class TestScanRequestParameters:
    """Test parameter manipulation methods."""

    @pytest.fixture
    def request(self):
        return ScanRequest(url="https://example.com")

    def test_set_get_param(self, request):
        """Test setting and getting parameters."""
        request.set_param("search", "vulnerability")
        assert request.get_param("search") == "vulnerability"

    def test_set_multiple_value_param(self, request):
        """Test setting parameters with multiple values."""
        request.set_param("tag", ["security", "scanner", "testing"])
        assert request.get_param("tag") == ["security", "scanner", "testing"]

    def test_delete_param(self, request):
        """Test deleting parameters."""
        request.set_param("filter", "active")
        assert "filter" in request.params
        request.delete_param("filter")
        assert "filter" not in request.params

    def test_param_chaining(self, request):
        """Test method chaining with parameters."""
        result = (
            request.set_param("page", "1")
            .set_param("limit", "50")
            .set_param("sort", "name")
        )
        assert result is request
        assert len(request.params) == 3

    def test_get_query_string(self, request):
        """Test query string generation."""
        request.set_param("user_id", "123")
        request.set_param("action", "delete")
        query = request.get_query_string()
        assert "user_id=123" in query
        assert "action=delete" in query
        assert "&" in query

    def test_get_query_string_with_list_params(self, request):
        """Test query string with list parameters."""
        request.set_param("id", ["1", "2", "3"])
        query = request.get_query_string()
        assert query.count("id=") == 3

    def test_get_full_url(self, request):
        """Test full URL with parameters."""
        request.set_param("search", "admin")
        request.set_param("page", "2")
        full_url = request.get_full_url()
        assert full_url.startswith("https://example.com?")
        assert "search=admin" in full_url
        assert "page=2" in full_url


class TestScanRequestBody:
    """Test body manipulation methods."""

    @pytest.fixture
    def request(self):
        return ScanRequest(url="https://example.com", method=HTTPMethod.POST)

    def test_set_dict_body(self, request):
        """Test setting dict body."""
        body = {"username": "admin", "password": "secret"}
        request.set_body(body, ContentType.JSON)
        assert request.body == body
        assert request.content_type == ContentType.JSON

    def test_set_string_body(self, request):
        """Test setting string body."""
        body = "username=admin&password=secret"
        request.set_body(body, ContentType.FORM)
        assert request.body == body

    def test_get_body_string_from_dict(self, request):
        """Test getting body as string from dict."""
        request.set_body({"key": "value"}, ContentType.JSON)
        body_str = request.get_body_string()
        assert isinstance(body_str, str)
        assert "key" in body_str
        assert "value" in body_str

    def test_get_body_dict_from_string(self, request):
        """Test getting body as dict from JSON string."""
        json_str = '{"name": "test", "value": 42}'
        request.set_body(json_str, ContentType.JSON)
        body_dict = request.get_body_dict()
        assert body_dict["name"] == "test"
        assert body_dict["value"] == 42

    def test_get_body_dict_invalid_json(self, request):
        """Test getting dict from invalid JSON returns None."""
        request.set_body("not valid json", ContentType.JSON)
        assert request.get_body_dict() is None


class TestScanRequestSerialization:
    """Test request serialization methods."""

    def test_to_dict(self):
        """Test converting request to dictionary."""
        request = ScanRequest(
            url="https://example.com/api",
            method=HTTPMethod.POST,
            headers={"Authorization": "Bearer token"},
            params={"page": "1"},
        )
        req_dict = request.to_dict()
        assert req_dict["url"] == "https://example.com/api"
        assert req_dict["method"] == "POST"
        assert req_dict["headers"]["Authorization"] == "Bearer token"
        assert req_dict["params"]["page"] == "1"

    def test_to_json(self):
        """Test converting request to JSON string."""
        request = ScanRequest(
            url="https://example.com",
            method=HTTPMethod.GET,
        )
        json_str = request.to_json()
        parsed = json.loads(json_str)
        assert parsed["url"] == "https://example.com"
        assert parsed["method"] == "GET"

    def test_from_dict(self):
        """Test creating request from dictionary."""
        data = {
            "url": "https://example.com/test",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": {"key": "value"},
        }
        request = ScanRequest.from_dict(data)
        assert request.url == "https://example.com/test"
        assert request.method == HTTPMethod.POST

    def test_from_json(self):
        """Test creating request from JSON string."""
        json_str = '{"url": "https://example.com", "method": "GET"}'
        request = ScanRequest.from_json(json_str)
        assert request.url == "https://example.com"
        assert request.method == HTTPMethod.GET

    def test_round_trip_serialization(self):
        """Test round-trip serialization."""
        original = ScanRequest(
            url="https://example.com/api/users",
            method=HTTPMethod.POST,
            headers={"Authorization": "Bearer token123"},
            cookies={"session": "xyz789"},
            params={"filter": "active"},
            body={"name": "John", "age": 30},
        )
        
        json_str = original.to_json()
        restored = ScanRequest.from_json(json_str)
        
        assert restored.url == original.url
        assert restored.method == original.method
        assert restored.headers == original.headers
        assert restored.params == original.params


class TestScanRequestCopy:
    """Test request copying methods."""

    def test_deep_copy(self):
        """Test deep copying a request."""
        original = ScanRequest(
            url="https://example.com",
            headers={"X-Custom": "value"},
            params={"id": "123"},
        )
        
        copied = original.copy(deep=True)
        
        # Verify it's a different object
        assert copied is not original
        assert copied.headers is not original.headers
        assert copied.params is not original.params
        
        # Verify contents are the same
        assert copied.url == original.url
        assert copied.headers == original.headers

    def test_shallow_copy(self):
        """Test shallow copying a request."""
        original = ScanRequest(
            url="https://example.com",
            headers={"X-Custom": "value"},
        )
        
        copied = original.copy(deep=False)
        
        # Shallow copy doesn't copy nested structures
        assert copied.headers is not original.headers

    def test_copy_independence(self):
        """Test that copied requests are independent."""
        original = ScanRequest(
            url="https://example.com",
            headers={"Authorization": "Bearer token"},
        )
        
        copied = original.copy()
        copied.set_header("X-Custom", "new-header")
        
        assert "X-Custom" not in original.headers
        assert "X-Custom" in copied.headers


class TestScanResponse:
    """Test ScanResponse model."""

    def test_create_response(self):
        """Test creating a response."""
        response = ScanResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"result": "success"}',
        )
        assert response.status_code == 200
        assert response.is_success()
        assert not response.is_error()

    def test_response_error_status(self):
        """Test response error detection."""
        response = ScanResponse(status_code=404, body="Not Found")
        assert response.is_error()
        assert not response.is_success()

    def test_response_get_body_dict(self):
        """Test parsing response body as dict."""
        response = ScanResponse(
            status_code=200,
            body='{"name": "John", "age": 30}',
        )
        body_dict = response.get_body_dict()
        assert body_dict["name"] == "John"
        assert body_dict["age"] == 30

    def test_response_get_header(self):
        """Test getting response headers."""
        response = ScanResponse(
            status_code=200,
            headers={"Content-Type": "application/json", "Set-Cookie": "token=abc"},
        )
        assert response.get_header("content-type") == "application/json"
        assert response.get_header("Set-Cookie") == "token=abc"


class TestCookieModel:
    """Test Cookie model."""

    def test_create_cookie(self):
        """Test creating a cookie."""
        cookie = Cookie(
            name="session",
            value="abc123",
            domain=".example.com",
            secure=True,
        )
        assert cookie.name == "session"
        assert cookie.value == "abc123"
        assert cookie.secure is True

    def test_cookie_to_header(self):
        """Test converting cookie to Set-Cookie header."""
        cookie = Cookie(
            name="session",
            value="token123",
            domain=".example.com",
            path="/api",
            secure=True,
            http_only=True,
        )
        header = cookie.to_header()
        assert "session=token123" in header
        assert "Domain=.example.com" in header
        assert "Path=/api" in header
        assert "Secure" in header
        assert "HttpOnly" in header

    def test_cookie_from_header(self):
        """Test parsing Set-Cookie header to Cookie."""
        header_value = "session=xyz789; Domain=.example.com; Path=/; Secure; HttpOnly"
        cookie = Cookie.from_header(header_value)
        assert cookie.name == "session"
        assert cookie.value == "xyz789"
        assert cookie.domain == ".example.com"
        assert cookie.secure is True
        assert cookie.http_only is True
