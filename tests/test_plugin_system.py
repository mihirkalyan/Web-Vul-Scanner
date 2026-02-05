"""
Tests for Plugin System
"""

import pytest
import asyncio
from src.models import ScanRequest, ScanResponse, HTTPMethod
from src.plugin import (
    ScanPlugin,
    PluginResult,
    PluginType,
    PluginRegistry,
    register,
    get_registry,
)


class MockPlugin(ScanPlugin):
    """Mock plugin for testing."""

    name = "MockPlugin"
    version = "1.0.0"
    plugin_type = PluginType.CUSTOM

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.execution_log = []

    def validate_config(self) -> bool:
        return True

    async def execute(self, request, response=None, **kwargs):
        self.execution_log.append(request.url)
        modified_request = request.copy()
        modified_request.set_header("X-Mocked", "true")
        return PluginResult(
            success=True,
            message="Mock execution successful",
            request=modified_request,
        )


class TestScanPlugin:
    """Test ScanPlugin base class."""

    def test_plugin_creation(self):
        """Test creating a plugin instance."""
        plugin = MockPlugin(config_key="config_value")
        assert plugin.name == "MockPlugin"
        assert plugin.version == "1.0.0"
        assert plugin.enabled is True
        assert plugin.config == {"config_key": "config_value"}

    def test_plugin_metadata(self):
        """Test getting plugin metadata."""
        plugin = MockPlugin()
        metadata = plugin.get_metadata()
        assert metadata["name"] == "MockPlugin"
        assert metadata["version"] == "1.0.0"
        assert metadata["enabled"] is True
        assert metadata["execution_count"] == 0
        assert metadata["error_count"] == 0

    def test_plugin_enable_disable(self):
        """Test enabling and disabling plugins."""
        plugin = MockPlugin()
        assert plugin.enabled is True
        plugin.disable()
        assert plugin.enabled is False
        plugin.enable()
        assert plugin.enabled is True

    @pytest.mark.asyncio
    async def test_plugin_execution(self):
        """Test executing a plugin."""
        plugin = MockPlugin()
        request = ScanRequest(url="https://example.com")
        result = await plugin._execute_wrapper(request)
        
        assert result.success is True
        assert result.request is not None
        assert result.request.get_header("X-Mocked") == "true"
        assert plugin._execution_count == 1

    @pytest.mark.asyncio
    async def test_disabled_plugin_not_executed(self):
        """Test that disabled plugins don't execute."""
        plugin = MockPlugin()
        plugin.disable()
        
        request = ScanRequest(url="https://example.com")
        result = await plugin._execute_wrapper(request)
        
        assert result.success is False
        assert plugin._execution_count == 0

    @pytest.mark.asyncio
    async def test_plugin_error_handling(self):
        """Test plugin error handling."""
        
        class FailingPlugin(ScanPlugin):
            name = "FailingPlugin"
            plugin_type = PluginType.CUSTOM

            def validate_config(self):
                return True

            async def execute(self, request, response=None, **kwargs):
                raise ValueError("Test error")

        plugin = FailingPlugin()
        request = ScanRequest(url="https://example.com")
        result = await plugin._execute_wrapper(request)
        
        assert result.success is False
        assert plugin._error_count == 1

    def test_plugin_stats_reset(self):
        """Test resetting plugin statistics."""
        plugin = MockPlugin()
        plugin._execution_count = 10
        plugin._error_count = 5
        
        plugin.reset_stats()
        
        assert plugin._execution_count == 0
        assert plugin._error_count == 0


class TestPluginResult:
    """Test PluginResult class."""

    def test_result_creation(self):
        """Test creating a plugin result."""
        request = ScanRequest(url="https://example.com")
        result = PluginResult(
            success=True,
            message="Success",
            request=request,
        )
        assert result.success is True
        assert result.message == "Success"
        assert result.request is request

    def test_result_with_data(self):
        """Test result with data."""
        data = {"vulnerabilities": ["XSS", "CSRF"]}
        result = PluginResult(
            success=True,
            message="Vulnerabilities found",
            data=data,
        )
        assert result.data == data
        assert "vulnerabilities" in result.data


class TestPluginRegistry:
    """Test PluginRegistry functionality."""

    @pytest.fixture
    def registry(self):
        return PluginRegistry()

    def test_register_plugin_class(self, registry):
        """Test registering a plugin class."""
        
        @registry.register()
        class TestPlugin(ScanPlugin):
            name = "TestPlugin"
            plugin_type = PluginType.CUSTOM
            
            def validate_config(self):
                return True
            
            async def execute(self, request, response=None, **kwargs):
                return PluginResult(success=True)

        assert "TestPlugin" in registry.list_available_plugins()

    def test_register_with_custom_name(self, registry):
        """Test registering with custom name."""
        
        @registry.register(name="CustomName")
        class TestPlugin(ScanPlugin):
            name = "TestPlugin"
            plugin_type = PluginType.CUSTOM
            
            def validate_config(self):
                return True
            
            async def execute(self, request, response=None, **kwargs):
                return PluginResult(success=True)

        assert "CustomName" in registry.list_available_plugins()

    def test_register_instance(self, registry):
        """Test registering a plugin instance."""
        plugin = MockPlugin()
        registry.register_instance(plugin)
        
        assert "MockPlugin" in registry.list_plugins()
        assert registry.get_plugin("MockPlugin") is plugin

    def test_create_instance(self, registry):
        """Test creating a plugin instance from class."""
        
        @registry.register()
        class TestPlugin(ScanPlugin):
            name = "TestPlugin"
            plugin_type = PluginType.CUSTOM
            
            def validate_config(self):
                return True
            
            async def execute(self, request, response=None, **kwargs):
                return PluginResult(success=True)

        instance = registry.create_instance("TestPlugin", custom_param="value")
        assert instance is not None
        assert instance.config["custom_param"] == "value"

    def test_get_plugin(self, registry):
        """Test getting a plugin."""
        plugin = MockPlugin()
        registry.register_instance(plugin, "test_plugin")
        
        retrieved = registry.get_plugin("test_plugin")
        assert retrieved is plugin

    def test_get_plugins_by_type(self, registry):
        """Test getting plugins by type."""
        
        @registry.register(plugin_type=PluginType.REQUEST_MODIFIER)
        class ModifierPlugin(ScanPlugin):
            name = "ModifierPlugin"
            plugin_type = PluginType.REQUEST_MODIFIER
            
            def validate_config(self):
                return True
            
            async def execute(self, request, response=None, **kwargs):
                return PluginResult(success=True)

        @registry.register(plugin_type=PluginType.RESPONSE_ANALYZER)
        class AnalyzerPlugin(ScanPlugin):
            name = "AnalyzerPlugin"
            plugin_type = PluginType.RESPONSE_ANALYZER
            
            def validate_config(self):
                return True
            
            async def execute(self, request, response=None, **kwargs):
                return PluginResult(success=True)

        registry.create_instance("ModifierPlugin")
        registry.create_instance("AnalyzerPlugin")
        
        modifiers = registry.get_plugins_by_type(PluginType.REQUEST_MODIFIER)
        assert len(modifiers) == 1
        assert modifiers[0].get_name() == "ModifierPlugin"

    def test_list_plugins(self, registry):
        """Test listing plugins."""
        registry.register_instance(MockPlugin())
        registry.register_instance(MockPlugin(), "second")
        
        plugins = registry.list_plugins()
        assert len(plugins) == 2

    def test_remove_plugin(self, registry):
        """Test removing a plugin."""
        registry.register_instance(MockPlugin())
        assert "MockPlugin" in registry.list_plugins()
        
        removed = registry.remove_plugin("MockPlugin")
        assert removed is True
        assert "MockPlugin" not in registry.list_plugins()

    def test_get_info(self, registry):
        """Test getting plugin info."""
        plugin = MockPlugin()
        registry.register_instance(plugin)
        
        info = registry.get_info("MockPlugin")
        assert info is not None
        assert info["name"] == "MockPlugin"
        assert info["enabled"] is True

    def test_get_all_info(self, registry):
        """Test getting all plugin info."""
        registry.register_instance(MockPlugin())
        registry.register_instance(MockPlugin(), "second")
        
        all_info = registry.get_all_info()
        assert len(all_info) == 2


class TestPluginIntegration:
    """Integration tests for plugin system."""

    @pytest.mark.asyncio
    async def test_plugin_request_modification(self):
        """Test plugin modifying a request."""
        
        class HeaderInjectorPlugin(ScanPlugin):
            name = "HeaderInjector"
            plugin_type = PluginType.REQUEST_MODIFIER
            
            def validate_config(self):
                return True
            
            async def execute(self, request, response=None, **kwargs):
                modified = request.copy()
                modified.set_header("X-Injected", "true")
                return PluginResult(success=True, request=modified)

        plugin = HeaderInjectorPlugin()
        request = ScanRequest(
            url="https://example.com",
            method=HTTPMethod.GET,
        )
        
        result = await plugin.execute(request)
        
        assert result.request.get_header("X-Injected") == "true"
        assert request.get_header("X-Injected") is None  # Original unchanged

    @pytest.mark.asyncio
    async def test_chained_plugin_execution(self):
        """Test executing multiple plugins in sequence."""
        
        class Plugin1(ScanPlugin):
            name = "Plugin1"
            plugin_type = PluginType.REQUEST_MODIFIER
            
            def validate_config(self):
                return True
            
            async def execute(self, request, response=None, **kwargs):
                modified = request.copy()
                modified.set_header("X-Plugin", "1")
                return PluginResult(success=True, request=modified)

        class Plugin2(ScanPlugin):
            name = "Plugin2"
            plugin_type = PluginType.REQUEST_MODIFIER
            
            def validate_config(self):
                return True
            
            async def execute(self, request, response=None, **kwargs):
                modified = request.copy()
                modified.set_header("X-Plugin", "2")
                return PluginResult(success=True, request=modified)

        request = ScanRequest(url="https://example.com")
        
        # Chain execution
        result1 = await Plugin1().execute(request)
        request = result1.request
        result2 = await Plugin2().execute(request)
        
        assert result2.request.get_header("X-Plugin") == "2"

    @pytest.mark.asyncio
    async def test_plugin_response_analysis(self):
        """Test plugin analyzing a response."""
        
        class StatusCodeAnalyzer(ScanPlugin):
            name = "StatusCodeAnalyzer"
            plugin_type = PluginType.RESPONSE_ANALYZER
            
            def validate_config(self):
                return True
            
            async def execute(self, request, response=None, **kwargs):
                if response and response.status_code >= 400:
                    return PluginResult(
                        success=True,
                        message="Error detected",
                        data={"is_error": True},
                    )
                return PluginResult(success=True, message="OK")

        plugin = StatusCodeAnalyzer()
        response = ScanResponse(status_code=404, body="Not Found")
        
        result = await plugin.execute(None, response)
        assert result.data["is_error"] is True
