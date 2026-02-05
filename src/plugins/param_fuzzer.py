"""
Parameter Fuzzing Plugin

Demonstrates request modification by fuzzing query parameters and body parameters.
Useful for testing parameter tampering vulnerabilities and logic flaws.
"""

from typing import List, Optional, Dict, Any
from ..models import ScanRequest, ScanResponse, ContentType
from ..plugin import ScanPlugin, PluginResult, PluginType, register
import json


@register(plugin_type=PluginType.REQUEST_MODIFIER)
class ParamFuzzerPlugin(ScanPlugin):
    """
    Fuzzes request parameters with test payloads.
    Useful for discovering parameter-based vulnerabilities like injection and tampering.
    """

    name = "ParamFuzzer"
    version = "1.0.0"
    description = "Fuzzes request parameters with test payloads"
    plugin_type = PluginType.REQUEST_MODIFIER
    author = "Scanner Team"

    # Common fuzzing payloads
    FUZZING_PAYLOADS = [
        "' OR '1'='1",  # SQL Injection
        "<script>alert('XSS')</script>",  # XSS
        "../../../../../../etc/passwd",  # Path Traversal
        "${7*7}",  # Template Injection
        "{{7*7}}",  # Template Injection
        "%00",  # Null Byte
        "1' UNION SELECT NULL--",  # UNION-based SQLi
    ]

    def __init__(
        self,
        target_params: Optional[List[str]] = None,
        payloads: Optional[List[str]] = None,
        append_mode: bool = False,
        **kwargs,
    ):
        """
        Initialize parameter fuzzer plugin.

        Args:
            target_params: List of parameter names to fuzz (None = all)
            payloads: List of payloads to use (uses defaults if None)
            append_mode: If True, append payloads; if False, replace values
            **kwargs: Additional config
        """
        super().__init__(**kwargs)
        self.target_params = target_params
        self.payloads = payloads or self.FUZZING_PAYLOADS
        self.append_mode = append_mode

    def validate_config(self) -> bool:
        """Validate configuration."""
        return isinstance(self.payloads, list) and len(self.payloads) > 0

    def _should_fuzz_param(self, param_name: str) -> bool:
        """
        Check if a parameter should be fuzzed.

        Args:
            param_name: Parameter name

        Returns:
            True if should fuzz
        """
        if self.target_params is None:
            return True
        return param_name in self.target_params

    async def execute(
        self,
        request: ScanRequest,
        response: Optional[ScanResponse] = None,
        payload_index: int = 0,
        **kwargs,
    ) -> PluginResult:
        """
        Execute parameter fuzzing.

        Args:
            request: Request to modify
            response: Ignored
            payload_index: Index of payload to use
            **kwargs: Additional args

        Returns:
            PluginResult with fuzzing variants
        """
        try:
            if payload_index >= len(self.payloads):
                return PluginResult(
                    success=False,
                    message=f"Payload index {payload_index} out of range",
                )

            payload = self.payloads[payload_index]
            fuzzed_requests = []

            # Fuzz query parameters
            for param_name in list(request.params.keys()):
                if self._should_fuzz_param(param_name):
                    fuzzed_request = request.copy()

                    if self.append_mode:
                        original = fuzzed_request.get_param(param_name)
                        new_value = f"{original}{payload}" if original else payload
                    else:
                        new_value = payload

                    fuzzed_request.set_param(param_name, new_value)
                    fuzzed_requests.append(
                        {
                            "request": fuzzed_request,
                            "fuzzed_param": param_name,
                            "payload": payload,
                        }
                    )

            # Fuzz body parameters if present
            if request.body:
                body_dict = request.get_body_dict()
                if body_dict:
                    for body_param_name in list(body_dict.keys()):
                        if self._should_fuzz_param(body_param_name):
                            fuzzed_request = request.copy()
                            fuzzed_body = request.get_body_dict() or {}
                            fuzzed_body = fuzzed_body.copy()

                            if self.append_mode:
                                original = fuzzed_body.get(body_param_name, "")
                                new_value = f"{original}{payload}"
                            else:
                                new_value = payload

                            fuzzed_body[body_param_name] = new_value
                            fuzzed_request.set_body(fuzzed_body)
                            fuzzed_requests.append(
                                {
                                    "request": fuzzed_request,
                                    "fuzzed_param": body_param_name,
                                    "payload": payload,
                                    "location": "body",
                                }
                            )

            self.log(
                "debug",
                f"Generated {len(fuzzed_requests)} fuzzing variants "
                f"with payload: {payload[:50]}...",
            )

            return PluginResult(
                success=True,
                message=f"Generated {len(fuzzed_requests)} fuzzing variants",
                data={
                    "fuzzed_requests": fuzzed_requests,
                    "payload_used": payload,
                    "total_payloads": len(self.payloads),
                    "current_payload_index": payload_index,
                },
            )

        except Exception as e:
            self.log("error", f"Failed to fuzz parameters: {str(e)}")
            return PluginResult(success=False, message=f"Parameter fuzzing failed: {str(e)}")


@register(plugin_type=PluginType.REQUEST_MODIFIER)
class UserAgentSpoofingPlugin(ScanPlugin):
    """
    Spoofs User-Agent headers to test client detection bypasses.
    Useful for testing user-agent based filtering and mobile/bot detection.
    """

    name = "UserAgentSpoofing"
    version = "1.0.0"
    description = "Spoofs User-Agent headers with various user agents"
    plugin_type = PluginType.REQUEST_MODIFIER
    author = "Scanner Team"

    # Common user agents to test
    USER_AGENTS = {
        "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "mobile": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
        "bot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "curl": "curl/7.64.1",
        "python": "python-requests/2.28.0",
    }

    def __init__(
        self,
        user_agents: Optional[Dict[str, str]] = None,
        **kwargs,
    ):
        """
        Initialize user agent spoofing plugin.

        Args:
            user_agents: Dictionary of user agents to use
            **kwargs: Additional config
        """
        super().__init__(**kwargs)
        self.user_agents = user_agents or self.USER_AGENTS

    def validate_config(self) -> bool:
        """Validate configuration."""
        return isinstance(self.user_agents, dict) and len(self.user_agents) > 0

    async def execute(
        self,
        request: ScanRequest,
        response: Optional[ScanResponse] = None,
        user_agent_key: Optional[str] = None,
        **kwargs,
    ) -> PluginResult:
        """
        Execute user agent spoofing.

        Args:
            request: Request to modify
            response: Ignored
            user_agent_key: Key of user agent to use (uses first if not specified)
            **kwargs: Additional args

        Returns:
            PluginResult with spoofed requests
        """
        try:
            spoofed_requests = []

            user_agent_keys = (
                [user_agent_key] if user_agent_key else list(self.user_agents.keys())
            )

            for ua_key in user_agent_keys:
                if ua_key not in self.user_agents:
                    continue

                ua_value = self.user_agents[ua_key]
                spoofed_request = request.copy()
                spoofed_request.set_header("User-Agent", ua_value)

                spoofed_requests.append(
                    {
                        "request": spoofed_request,
                        "user_agent_type": ua_key,
                        "user_agent_value": ua_value,
                    }
                )

            self.log(
                "debug",
                f"Generated {len(spoofed_requests)} user agent variants",
            )

            return PluginResult(
                success=True,
                message=f"Generated {len(spoofed_requests)} user agent variants",
                data={
                    "spoofed_requests": spoofed_requests,
                    "total_user_agents": len(self.user_agents),
                },
            )

        except Exception as e:
            self.log("error", f"Failed to spoof user agent: {str(e)}")
            return PluginResult(
                success=False, message=f"User agent spoofing failed: {str(e)}"
            )
