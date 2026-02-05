"""
Pydantic Models for Web Vulnerability Scanner Plugin System

Provides standardized data objects for HTTP request handling,
enabling plugins to easily manipulate headers, cookies, parameters, and body content.
"""

from typing import Dict, List, Optional, Any, Union
from enum import Enum
from pydantic import BaseModel, Field, field_validator, HttpUrl
from copy import deepcopy
import json
from datetime import datetime
from urllib.parse import urlencode, parse_qs, quote


class HTTPMethod(str, Enum):
    """HTTP request methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ContentType(str, Enum):
    """Common content types."""
    JSON = "application/json"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    XML = "application/xml"
    TEXT = "text/plain"
    HTML = "text/html"


class Cookie(BaseModel):
    """Represents a single cookie."""
    name: str = Field(..., description="Cookie name")
    value: str = Field(..., description="Cookie value")
    domain: Optional[str] = Field(None, description="Cookie domain")
    path: Optional[str] = Field("/", description="Cookie path")
    secure: bool = Field(False, description="Secure flag")
    http_only: bool = Field(False, description="HttpOnly flag")
    same_site: Optional[str] = Field(None, description="SameSite attribute")
    max_age: Optional[int] = Field(None, description="Max age in seconds")

    def to_header(self) -> str:
        """
        Convert cookie to Set-Cookie header format.

        Returns:
            Set-Cookie header value
        """
        parts = [f"{self.name}={self.value}"]

        if self.domain:
            parts.append(f"Domain={self.domain}")

        if self.path:
            parts.append(f"Path={self.path}")

        if self.secure:
            parts.append("Secure")

        if self.http_only:
            parts.append("HttpOnly")

        if self.same_site:
            parts.append(f"SameSite={self.same_site}")

        if self.max_age is not None:
            parts.append(f"Max-Age={self.max_age}")

        return "; ".join(parts)

    @staticmethod
    def from_header(header_value: str) -> "Cookie":
        """
        Parse Set-Cookie header to Cookie object.

        Args:
            header_value: Set-Cookie header value

        Returns:
            Cookie instance
        """
        parts = [p.strip() for p in header_value.split(";")]
        name, value = parts[0].split("=", 1)

        cookie_dict = {"name": name.strip(), "value": value.strip()}

        for part in parts[1:]:
            if "=" in part:
                key, val = part.split("=", 1)
                key = key.strip().lower()
                val = val.strip()

                if key == "domain":
                    cookie_dict["domain"] = val
                elif key == "path":
                    cookie_dict["path"] = val
                elif key == "max-age":
                    cookie_dict["max_age"] = int(val)
                elif key == "samesite":
                    cookie_dict["same_site"] = val
            else:
                key = part.lower()
                if key == "secure":
                    cookie_dict["secure"] = True
                elif key == "httponly":
                    cookie_dict["http_only"] = True

        return Cookie(**cookie_dict)


class ScanRequest(BaseModel):
    """
    Standardized HTTP request object for vulnerability scanning.
    Supports headers, cookies, parameters, and body manipulation.
    """

    url: str = Field(..., description="Target URL")
    method: HTTPMethod = Field(HTTPMethod.GET, description="HTTP method")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    cookies: Dict[str, str] = Field(default_factory=dict, description="Request cookies")
    params: Dict[str, Union[str, List[str]]] = Field(
        default_factory=dict, description="Query parameters"
    )
    body: Optional[Union[str, Dict[str, Any]]] = Field(
        None, description="Request body (string or dict)"
    )
    content_type: Optional[ContentType] = Field(
        None, description="Content-Type header (auto-detected if not set)"
    )
    timeout: float = Field(30.0, description="Request timeout in seconds")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Plugin metadata and custom fields"
    )
    created_at: datetime = Field(default_factory=datetime.now)
    modified_at: datetime = Field(default_factory=datetime.now)

    class Config:
        use_enum_values = False

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate URL format."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    @field_validator("method", mode="before")
    @classmethod
    def validate_method(cls, v: Union[str, HTTPMethod]) -> HTTPMethod:
        """Validate and normalize HTTP method."""
        if isinstance(v, str):
            return HTTPMethod(v.upper())
        return v

    def _sync_cookies_to_headers(self):
        """
        Sync cookies dict to Cookie header.
        This ensures headers and cookies stay in sync.
        """
        if self.cookies:
            cookie_header = "; ".join(
                f"{name}={value}" for name, value in self.cookies.items()
            )
            self.headers["Cookie"] = cookie_header
        elif "Cookie" in self.headers and not self.cookies:
            # Parse Cookie header into cookies dict
            cookie_header = self.headers.get("Cookie", "")
            self.cookies = {
                name.strip(): value.strip()
                for name, value in (
                    pair.split("=", 1) for pair in cookie_header.split(";") if "=" in pair
                )
            }

    def _detect_content_type(self) -> Optional[ContentType]:
        """
        Auto-detect content type based on body and existing headers.

        Returns:
            Detected ContentType or None
        """
        if isinstance(self.body, dict):
            return ContentType.JSON

        if "Content-Type" in self.headers:
            ct = self.headers["Content-Type"].lower()
            if "json" in ct:
                return ContentType.JSON
            elif "form-data" in ct:
                return ContentType.MULTIPART
            elif "x-www-form-urlencoded" in ct:
                return ContentType.FORM

        return None

    def model_post_init(self, __context):
        """Post-initialization hook for pydantic v2."""
        self._sync_cookies_to_headers()
        self.modified_at = datetime.now()

        if not self.content_type and self.body:
            self.content_type = self._detect_content_type()

    def set_header(self, name: str, value: str) -> "ScanRequest":
        """
        Set a header value.

        Args:
            name: Header name
            value: Header value

        Returns:
            Self for chaining
        """
        self.headers[name] = value
        self.modified_at = datetime.now()
        return self

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a header value (case-insensitive).

        Args:
            name: Header name
            default: Default value if not found

        Returns:
            Header value or default
        """
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def delete_header(self, name: str) -> "ScanRequest":
        """
        Delete a header by name (case-insensitive).

        Args:
            name: Header name

        Returns:
            Self for chaining
        """
        keys_to_delete = [k for k in self.headers if k.lower() == name.lower()]
        for key in keys_to_delete:
            del self.headers[key]
        self.modified_at = datetime.now()
        return self

    def set_cookie(self, name: str, value: str) -> "ScanRequest":
        """
        Set a cookie value.

        Args:
            name: Cookie name
            value: Cookie value

        Returns:
            Self for chaining
        """
        self.cookies[name] = value
        self._sync_cookies_to_headers()
        self.modified_at = datetime.now()
        return self

    def get_cookie(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a cookie value.

        Args:
            name: Cookie name
            default: Default value if not found

        Returns:
            Cookie value or default
        """
        return self.cookies.get(name, default)

    def delete_cookie(self, name: str) -> "ScanRequest":
        """
        Delete a cookie by name.

        Args:
            name: Cookie name

        Returns:
            Self for chaining
        """
        if name in self.cookies:
            del self.cookies[name]
            self._sync_cookies_to_headers()
            self.modified_at = datetime.now()
        return self

    def set_param(
        self, name: str, value: Union[str, List[str]]
    ) -> "ScanRequest":
        """
        Set a query parameter.

        Args:
            name: Parameter name
            value: Parameter value(s)

        Returns:
            Self for chaining
        """
        self.params[name] = value
        self.modified_at = datetime.now()
        return self

    def get_param(
        self, name: str, default: Optional[Union[str, List[str]]] = None
    ) -> Optional[Union[str, List[str]]]:
        """
        Get a parameter value.

        Args:
            name: Parameter name
            default: Default value if not found

        Returns:
            Parameter value or default
        """
        return self.params.get(name, default)

    def delete_param(self, name: str) -> "ScanRequest":
        """
        Delete a parameter by name.

        Args:
            name: Parameter name

        Returns:
            Self for chaining
        """
        if name in self.params:
            del self.params[name]
            self.modified_at = datetime.now()
        return self

    def set_body(
        self,
        body: Optional[Union[str, Dict[str, Any]]],
        content_type: Optional[ContentType] = None,
    ) -> "ScanRequest":
        """
        Set request body with optional content type.

        Args:
            body: Body content (string or dict)
            content_type: Optional content type

        Returns:
            Self for chaining
        """
        self.body = body
        if content_type:
            self.content_type = content_type
        else:
            self.content_type = self._detect_content_type()

        if self.content_type:
            self.headers["Content-Type"] = self.content_type.value

        self.modified_at = datetime.now()
        return self

    def get_body_string(self) -> str:
        """
        Get body as string, converting dict to JSON if needed.

        Returns:
            Body as string
        """
        if isinstance(self.body, dict):
            return json.dumps(self.body)
        return self.body or ""

    def get_body_dict(self) -> Optional[Dict[str, Any]]:
        """
        Get body as dict, parsing JSON string if needed.

        Returns:
            Body as dict or None
        """
        if isinstance(self.body, dict):
            return self.body

        if isinstance(self.body, str):
            try:
                return json.loads(self.body)
            except (json.JSONDecodeError, ValueError):
                return None

        return None

    def get_query_string(self) -> str:
        """
        Generate query string from params.

        Returns:
            URL-encoded query string (without ?)
        """
        if not self.params:
            return ""

        pairs = []
        for name, value in self.params.items():
            if isinstance(value, list):
                for v in value:
                    pairs.append((name, str(v)))
            else:
                pairs.append((name, str(value)))

        return urlencode(pairs)

    def get_full_url(self) -> str:
        """
        Get full URL with query parameters.

        Returns:
            Complete URL with query string
        """
        base_url = self.url
        query_string = self.get_query_string()

        if query_string:
            separator = "&" if "?" in base_url else "?"
            return f"{base_url}{separator}{query_string}"

        return base_url

    def copy(self, deep: bool = True) -> "ScanRequest":
        """
        Create a copy of this request.

        Args:
            deep: If True, perform deep copy (default)

        Returns:
            New ScanRequest instance
        """
        if deep:
            return ScanRequest(
                url=self.url,
                method=self.method,
                headers=deepcopy(self.headers),
                cookies=deepcopy(self.cookies),
                params=deepcopy(self.params),
                body=deepcopy(self.body) if self.body else None,
                content_type=self.content_type,
                timeout=self.timeout,
                metadata=deepcopy(self.metadata),
            )
        else:
            return ScanRequest(
                url=self.url,
                method=self.method,
                headers=self.headers.copy(),
                cookies=self.cookies.copy(),
                params=self.params.copy(),
                body=self.body,
                content_type=self.content_type,
                timeout=self.timeout,
                metadata=self.metadata.copy(),
            )

    def to_dict(self, include_metadata: bool = False) -> Dict[str, Any]:
        """
        Convert request to dictionary.

        Args:
            include_metadata: Include metadata field

        Returns:
            Dictionary representation
        """
        data = {
            "url": self.url,
            "method": self.method.value,
            "headers": self.headers,
            "cookies": self.cookies,
            "params": self.params,
            "body": self.body,
            "content_type": self.content_type.value if self.content_type else None,
            "timeout": self.timeout,
        }

        if include_metadata:
            data["metadata"] = self.metadata

        return data

    def to_json(self, include_metadata: bool = False) -> str:
        """
        Convert request to JSON string.

        Args:
            include_metadata: Include metadata field

        Returns:
            JSON representation
        """
        return json.dumps(self.to_dict(include_metadata=include_metadata))

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ScanRequest":
        """
        Create ScanRequest from dictionary.

        Args:
            data: Dictionary with request data

        Returns:
            ScanRequest instance
        """
        return ScanRequest(**data)

    @staticmethod
    def from_json(json_str: str) -> "ScanRequest":
        """
        Create ScanRequest from JSON string.

        Args:
            json_str: JSON string with request data

        Returns:
            ScanRequest instance
        """
        data = json.loads(json_str)
        return ScanRequest.from_dict(data)


class ScanResponse(BaseModel):
    """Response object for scan operations."""

    status_code: int = Field(..., description="HTTP status code")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    body: str = Field("", description="Response body")
    cookies: Dict[str, str] = Field(default_factory=dict, description="Response cookies")
    elapsed_time: float = Field(0.0, description="Request duration in seconds")
    error: Optional[str] = Field(None, description="Error message if any")
    timestamp: datetime = Field(default_factory=datetime.now)

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Get header value (case-insensitive)."""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def get_body_dict(self) -> Optional[Dict[str, Any]]:
        """Parse body as JSON if possible."""
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, ValueError):
            return None

    def is_success(self) -> bool:
        """Check if response is successful (2xx status code)."""
        return 200 <= self.status_code < 300

    def is_error(self) -> bool:
        """Check if response is error (4xx or 5xx)."""
        return self.status_code >= 400
