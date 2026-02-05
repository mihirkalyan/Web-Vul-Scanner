"""
Header Injection Plugin

Demonstrates request modification by injecting custom headers.
Useful for testing header-based vulnerabilities and bypasses.
"""

from typing import List, Optional, Dict, Any
from ..models import ScanRequest, ScanResponse
from ..plugin import ScanPlugin, PluginResult, PluginType, register


@register(plugin_type=PluginType.REQUEST_MODIFIER)
class HeaderInjectorPlugin(ScanPlugin):
    """
    Injects custom headers into requests.
    Useful for testing authentication bypasses, security headers, and XFF/XFB tricks.
    """

    name = "HeaderInjector"
    version = "1.0.0"
    description = "Injects custom headers into HTTP requests"
    plugin_type = PluginType.REQUEST_MODIFIER
    author = "Scanner Team"

    def __init__(
        self,
        headers_to_inject: Optional[Dict[str, str]] = None,
        remove_headers: Optional[List[str]] = None,
        **kwargs,
    ):
        """
        Initialize header injector plugin.

        Args:
            headers_to_inject: Dictionary of headers to inject
            remove_headers: List of header names to remove
            **kwargs: Additional config
        """
        super().__init__(**kwargs)
        self.headers_to_inject = headers_to_inject or {
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Proto": "https",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
        }
        self.remove_headers = remove_headers or []

    def validate_config(self) -> bool:
        """Validate configuration."""
        return isinstance(self.headers_to_inject, dict) and isinstance(
            self.remove_headers, list
        )

    async def execute(
        self,
        request: ScanRequest,
        response: Optional[ScanResponse] = None,
        **kwargs,
    ) -> PluginResult:
        """
        Execute header injection.

        Args:
            request: Request to modify
            response: Ignored
            **kwargs: Additional args

        Returns:
            PluginResult with modified request
        """
        try:
            # Create a copy to avoid modifying original
            modified_request = request.copy()

            # Remove specified headers
            for header_name in self.remove_headers:
                modified_request.delete_header(header_name)

            # Inject headers
            for header_name, header_value in self.headers_to_inject.items():
                modified_request.set_header(header_name, header_value)

            self.log(
                "debug",
                f"Injected {len(self.headers_to_inject)} headers, "
                f"removed {len(self.remove_headers)} headers",
            )

            return PluginResult(
                success=True,
                message=f"Injected {len(self.headers_to_inject)} headers",
                request=modified_request,
                data={
                    "injected_headers": self.headers_to_inject,
                    "removed_headers": self.remove_headers,
                },
            )

        except Exception as e:
            self.log("error", f"Failed to inject headers: {str(e)}")
            return PluginResult(success=False, message=f"Header injection failed: {str(e)}")


@register(plugin_type=PluginType.REQUEST_MODIFIER)
class CookieInjectorPlugin(ScanPlugin):
    """
    Injects custom cookies into requests.
    Useful for session manipulation, CSRF token testing, and cookie-based auth bypass.
    """

    name = "CookieInjector"
    version = "1.0.0"
    description = "Injects custom cookies into HTTP requests"
    plugin_type = PluginType.REQUEST_MODIFIER
    author = "Scanner Team"

    def __init__(
        self,
        cookies_to_inject: Optional[Dict[str, str]] = None,
        remove_cookies: Optional[List[str]] = None,
        **kwargs,
    ):
        """
        Initialize cookie injector plugin.

        Args:
            cookies_to_inject: Dictionary of cookies to inject
            remove_cookies: List of cookie names to remove
            **kwargs: Additional config
        """
        super().__init__(**kwargs)
        self.cookies_to_inject = cookies_to_inject or {
            "admin": "true",
            "role": "administrator",
            "user_id": "1",
        }
        self.remove_cookies = remove_cookies or []

    def validate_config(self) -> bool:
        """Validate configuration."""
        return isinstance(self.cookies_to_inject, dict) and isinstance(
            self.remove_cookies, list
        )

    async def execute(
        self,
        request: ScanRequest,
        response: Optional[ScanResponse] = None,
        **kwargs,
    ) -> PluginResult:
        """
        Execute cookie injection.

        Args:
            request: Request to modify
            response: Ignored
            **kwargs: Additional args

        Returns:
            PluginResult with modified request
        """
        try:
            modified_request = request.copy()

            # Remove specified cookies
            for cookie_name in self.remove_cookies:
                modified_request.delete_cookie(cookie_name)

            # Inject cookies
            for cookie_name, cookie_value in self.cookies_to_inject.items():
                modified_request.set_cookie(cookie_name, cookie_value)

            self.log(
                "debug",
                f"Injected {len(self.cookies_to_inject)} cookies, "
                f"removed {len(self.remove_cookies)} cookies",
            )

            return PluginResult(
                success=True,
                message=f"Injected {len(self.cookies_to_inject)} cookies",
                request=modified_request,
                data={
                    "injected_cookies": self.cookies_to_inject,
                    "removed_cookies": self.remove_cookies,
                },
            )

        except Exception as e:
            self.log("error", f"Failed to inject cookies: {str(e)}")
            return PluginResult(success=False, message=f"Cookie injection failed: {str(e)}")
