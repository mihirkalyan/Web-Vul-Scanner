"""
Plugin System Examples

Demonstrates how to use the plugin system for request manipulation,
response analysis, and custom vulnerability detection.
"""

import asyncio
from src.models import ScanRequest, ScanResponse, HTTPMethod, ContentType
from src.plugin import (
    ScanPlugin,
    PluginResult,
    PluginType,
    get_registry,
    register,
)


# =============================================================================
# Example 1: Using Built-in Plugins
# =============================================================================

async def example_header_injection():
    """Demonstrate header injection plugin."""
    print("\n" + "=" * 60)
    print("Example 1: Header Injection Plugin")
    print("=" * 60)

    from src.plugins.header_injector import HeaderInjectorPlugin

    # Create plugin
    plugin = HeaderInjectorPlugin(
        headers_to_inject={
            "X-Forwarded-For": "192.168.1.1",
            "X-Original-URL": "/admin",
            "Authorization": "Bearer fake-token",
        }
    )

    # Create request
    request = ScanRequest(
        url="https://example.com/api/users",
        method=HTTPMethod.GET,
    )

    print(f"\nOriginal request headers: {request.headers}")

    # Execute plugin
    result = await plugin.execute(request)

    print(f"Modified request headers: {result.request.headers}")
    print(f"Plugin result: {result.message}")


# =============================================================================
# Example 2: Cookie Injection and Modification
# =============================================================================

async def example_cookie_injection():
    """Demonstrate cookie injection plugin."""
    print("\n" + "=" * 60)
    print("Example 2: Cookie Injection Plugin")
    print("=" * 60)

    from src.plugins.header_injector import CookieInjectorPlugin

    # Create plugin
    plugin = CookieInjectorPlugin(
        cookies_to_inject={
            "session_id": "admin-session-12345",
            "user_role": "admin",
            "is_authenticated": "true",
        }
    )

    # Create request
    request = ScanRequest(
        url="https://example.com/dashboard",
        method=HTTPMethod.GET,
    )

    print(f"\nOriginal cookies: {request.cookies}")

    # Execute plugin
    result = await plugin.execute(request)

    print(f"Modified cookies: {result.request.cookies}")
    print(f"Cookie header: {result.request.get_header('Cookie')}")


# =============================================================================
# Example 3: Parameter Fuzzing
# =============================================================================

async def example_parameter_fuzzing():
    """Demonstrate parameter fuzzing plugin."""
    print("\n" + "=" * 60)
    print("Example 3: Parameter Fuzzing Plugin")
    print("=" * 60)

    from src.plugins.param_fuzzer import ParamFuzzerPlugin

    # Create plugin
    plugin = ParamFuzzerPlugin(
        target_params=["user_id", "action"],
        payloads=["' OR '1'='1", "../../etc/passwd", "${7*7}"],
    )

    # Create request with parameters
    request = ScanRequest(
        url="https://example.com/api/user",
        method=HTTPMethod.POST,
    )
    request.set_param("user_id", "123")
    request.set_param("action", "delete")
    request.set_param("confirm", "false")

    print(f"\nOriginal params: {request.params}")

    # Execute plugin with first payload
    result = await plugin.execute(request, payload_index=0)

    print(f"Generated {len(result.data['fuzzed_requests'])} fuzzing variants")
    print(f"Payload used: {result.data['payload_used']}")

    # Show first variant
    if result.data["fuzzed_requests"]:
        variant = result.data["fuzzed_requests"][0]
        print(f"Fuzzed param: {variant['fuzzed_param']} = {variant['payload'][:30]}...")


# =============================================================================
# Example 4: User Agent Spoofing
# =============================================================================

async def example_user_agent_spoofing():
    """Demonstrate user agent spoofing plugin."""
    print("\n" + "=" * 60)
    print("Example 4: User Agent Spoofing Plugin")
    print("=" * 60)

    from src.plugins.param_fuzzer import UserAgentSpoofingPlugin

    # Create plugin
    plugin = UserAgentSpoofingPlugin()

    # Create request
    request = ScanRequest(
        url="https://example.com/",
        method=HTTPMethod.GET,
    )

    print(f"\nOriginal User-Agent: {request.get_header('User-Agent')}")

    # Execute plugin
    result = await plugin.execute(request)

    print(f"Generated {len(result.data['spoofed_requests'])} user agent variants:")
    for variant in result.data["spoofed_requests"]:
        print(f"  - {variant['user_agent_type']}: {variant['user_agent_value'][:50]}...")


# =============================================================================
# Example 5: Creating Custom Plugin
# =============================================================================

@register(plugin_type=PluginType.REQUEST_MODIFIER)
class SQLInjectionPayloadPlugin(ScanPlugin):
    """Custom plugin that injects SQL injection payloads."""

    name = "SQLInjectionPayload"
    version = "1.0.0"
    description = "Injects SQL injection test payloads"
    plugin_type = PluginType.REQUEST_MODIFIER
    author = "Scanner Team"

    # SQL injection test payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "1' UNION SELECT NULL--",
        "' AND SLEEP(5)--",
        "'; DROP TABLE users;--",
    ]

    def __init__(self, target_param: str = "id", **kwargs):
        super().__init__(**kwargs)
        self.target_param = target_param

    def validate_config(self) -> bool:
        return isinstance(self.target_param, str)

    async def execute(self, request, response=None, payload_index=0, **kwargs):
        """Execute SQL injection payload injection."""
        if payload_index >= len(self.SQL_PAYLOADS):
            return PluginResult(success=False, message="Invalid payload index")

        payload = self.SQL_PAYLOADS[payload_index]
        modified_request = request.copy()

        # Inject into query parameter
        if self.target_param in modified_request.params:
            modified_request.set_param(self.target_param, payload)

        # Also inject into body if present
        if modified_request.body:
            body_dict = modified_request.get_body_dict()
            if body_dict and self.target_param in body_dict:
                body_dict[self.target_param] = payload
                modified_request.set_body(body_dict)

        return PluginResult(
            success=True,
            message=f"Injected SQL payload: {payload[:40]}...",
            request=modified_request,
            data={"payload": payload, "target_param": self.target_param},
        )


async def example_custom_plugin():
    """Demonstrate custom SQL injection plugin."""
    print("\n" + "=" * 60)
    print("Example 5: Custom SQL Injection Plugin")
    print("=" * 60)

    # Create plugin
    plugin = SQLInjectionPayloadPlugin(target_param="user_id")

    # Create request
    request = ScanRequest(
        url="https://example.com/profile",
        method=HTTPMethod.GET,
    )
    request.set_param("user_id", "42")

    print(f"\nOriginal request: {request.get_full_url()}")

    # Execute plugin
    result = await plugin.execute(request, payload_index=0)

    print(f"Modified request: {result.request.get_full_url()}")
    print(f"Payload: {result.data['payload']}")


# =============================================================================
# Example 6: Plugin Registry and Management
# =============================================================================

async def example_plugin_registry():
    """Demonstrate plugin registry management."""
    print("\n" + "=" * 60)
    print("Example 6: Plugin Registry Management")
    print("=" * 60)

    registry = get_registry()

    # List all available plugins
    available = registry.list_available_plugins()
    print(f"\nAvailable plugin classes: {available}")

    # Register some plugins
    from src.plugins.header_injector import HeaderInjectorPlugin, CookieInjectorPlugin

    registry.register_instance(HeaderInjectorPlugin(), "header_injector")
    registry.register_instance(CookieInjectorPlugin(), "cookie_injector")
    registry.register_instance(SQLInjectionPayloadPlugin(), "sql_injection")

    # List registered instances
    registered = registry.list_plugins()
    print(f"Registered plugin instances: {registered}")

    # Get info about plugins
    print("\nPlugin information:")
    for name in registered:
        info = registry.get_info(name)
        print(f"  {info['name']} v{info['version']}: {info['description']}")


# =============================================================================
# Example 7: Chaining Multiple Plugins
# =============================================================================

async def example_plugin_chaining():
    """Demonstrate chaining multiple plugins."""
    print("\n" + "=" * 60)
    print("Example 7: Plugin Chaining")
    print("=" * 60)

    from src.plugins.header_injector import (
        HeaderInjectorPlugin,
        CookieInjectorPlugin,
    )

    # Create plugins
    header_plugin = HeaderInjectorPlugin(
        headers_to_inject={"X-Admin": "true"}
    )
    cookie_plugin = CookieInjectorPlugin(
        cookies_to_inject={"role": "admin"}
    )
    sql_plugin = SQLInjectionPayloadPlugin(target_param="id")

    # Create initial request
    request = ScanRequest(
        url="https://example.com/api/user",
        method=HTTPMethod.GET,
    )
    request.set_param("id", "1")

    print(f"\nInitial request: {request.get_full_url()}")
    print(f"Initial headers: {request.headers}")
    print(f"Initial cookies: {request.cookies}")

    # Chain plugins
    print("\n--- Applying Header Injector ---")
    result1 = await header_plugin.execute(request)
    request = result1.request

    print("\n--- Applying Cookie Injector ---")
    result2 = await cookie_plugin.execute(request)
    request = result2.request

    print("\n--- Applying SQL Injection Payload ---")
    result3 = await sql_plugin.execute(request)
    request = result3.request

    # Show final request
    print(f"\nFinal request: {request.get_full_url()}")
    print(f"Final headers: {request.headers}")
    print(f"Final cookies: {request.cookies}")
    print(f"SQL injection payload in param: {request.get_param('id')}")


# =============================================================================
# Example 8: Response Analysis Plugin
# =============================================================================

@register(plugin_type=PluginType.RESPONSE_ANALYZER)
class SecurityHeaderAnalyzer(ScanPlugin):
    """Analyzes response for security headers."""

    name = "SecurityHeaderAnalyzer"
    version = "1.0.0"
    description = "Analyzes security headers in responses"
    plugin_type = PluginType.RESPONSE_ANALYZER
    author = "Scanner Team"

    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
    ]

    def validate_config(self) -> bool:
        return True

    async def execute(self, request, response=None, **kwargs):
        """Analyze security headers."""
        if not response:
            return PluginResult(success=False, message="No response to analyze")

        missing_headers = []
        present_headers = {}

        for header_name in self.SECURITY_HEADERS:
            value = response.get_header(header_name)
            if value:
                present_headers[header_name] = value
            else:
                missing_headers.append(header_name)

        return PluginResult(
            success=True,
            message=f"Found {len(present_headers)} security headers",
            data={
                "present_headers": present_headers,
                "missing_headers": missing_headers,
                "security_score": (len(present_headers) / len(self.SECURITY_HEADERS)) * 100,
            },
        )


async def example_response_analysis():
    """Demonstrate response analysis plugin."""
    print("\n" + "=" * 60)
    print("Example 8: Response Analysis Plugin")
    print("=" * 60)

    # Create plugin
    plugin = SecurityHeaderAnalyzer()

    # Create response with some security headers
    response = ScanResponse(
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Server": "Apache/2.4.1",
        },
        body="<html>...</html>",
    )

    print("\nResponse headers:", response.headers)

    # Analyze response
    result = await plugin.execute(None, response)

    print(f"\nAnalysis result: {result.message}")
    print(f"Present headers: {list(result.data['present_headers'].keys())}")
    print(f"Missing headers: {result.data['missing_headers']}")
    print(f"Security score: {result.data['security_score']:.1f}%")


# Import ScanResponse for example
from src.models import ScanResponse


async def main():
    """Run all examples."""
    print("\n" + "█" * 60)
    print("█" + " " * 58 + "█")
    print("█" + "  Plugin System Examples".center(58) + "█")
    print("█" + " " * 58 + "█")
    print("█" * 60)

    try:
        await example_header_injection()
        await example_cookie_injection()
        await example_parameter_fuzzing()
        await example_user_agent_spoofing()
        await example_custom_plugin()
        await example_plugin_registry()
        await example_plugin_chaining()
        await example_response_analysis()

        print("\n" + "=" * 60)
        print("All examples completed successfully! ✓")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"\n✗ Error during examples: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(main())
