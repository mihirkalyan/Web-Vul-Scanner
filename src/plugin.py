"""
Plugin System for Web Vulnerability Scanner

Provides base classes and registry for creating and managing scanner plugins.
Plugins can manipulate requests, analyze responses, and extend scanner capabilities.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Callable, Type
from enum import Enum
from datetime import datetime
import inspect

from .models import ScanRequest, ScanResponse


class PluginType(str, Enum):
    """Types of plugins."""
    REQUEST_MODIFIER = "request_modifier"  # Modifies requests before sending
    RESPONSE_ANALYZER = "response_analyzer"  # Analyzes responses
    DETECTOR = "detector"  # Detects vulnerabilities
    PAYLOAD_GENERATOR = "payload_generator"  # Generates payloads
    CUSTOM = "custom"  # Custom plugin type


class PluginResult:
    """Result from plugin execution."""

    def __init__(
        self,
        success: bool,
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
        request: Optional[ScanRequest] = None,
        response: Optional[ScanResponse] = None,
    ):
        """
        Initialize plugin result.

        Args:
            success: Whether execution succeeded
            message: Result message
            data: Optional result data
            request: Modified request (if applicable)
            response: Response to analyze (if applicable)
        """
        self.success = success
        self.message = message
        self.data = data or {}
        self.request = request
        self.response = response
        self.timestamp = datetime.now()

    def __repr__(self) -> str:
        return (
            f"PluginResult(success={self.success}, message='{self.message}', "
            f"data_keys={list(self.data.keys())})"
        )


class ScanPlugin(ABC):
    """
    Base class for all plugins.
    Plugins extend scanner capabilities by modifying requests,
    analyzing responses, or detecting vulnerabilities.
    """

    # Plugin metadata - override in subclasses
    name: str = "BasePlugin"
    version: str = "1.0.0"
    description: str = "Base plugin class"
    plugin_type: PluginType = PluginType.CUSTOM
    author: str = "Unknown"
    dependencies: List[str] = []

    def __init__(self, **kwargs):
        """
        Initialize plugin.

        Args:
            **kwargs: Plugin-specific configuration
        """
        self.config = kwargs
        self.enabled = True
        self.logger = None
        self._execution_count = 0
        self._error_count = 0

    @abstractmethod
    async def execute(
        self,
        request: ScanRequest,
        response: Optional[ScanResponse] = None,
        **kwargs,
    ) -> PluginResult:
        """
        Execute plugin logic.

        Args:
            request: ScanRequest to process
            response: Optional ScanResponse to analyze
            **kwargs: Additional arguments

        Returns:
            PluginResult with execution outcome
        """
        pass

    @abstractmethod
    def validate_config(self) -> bool:
        """
        Validate plugin configuration.

        Returns:
            True if config is valid
        """
        pass

    def get_name(self) -> str:
        """Get plugin name."""
        return self.name

    def get_version(self) -> str:
        """Get plugin version."""
        return self.version

    def get_type(self) -> PluginType:
        """Get plugin type."""
        return self.plugin_type

    def get_metadata(self) -> Dict[str, Any]:
        """
        Get plugin metadata.

        Returns:
            Dictionary with plugin info
        """
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "type": self.plugin_type.value,
            "author": self.author,
            "dependencies": self.dependencies,
            "enabled": self.enabled,
            "execution_count": self._execution_count,
            "error_count": self._error_count,
        }

    def set_logger(self, logger) -> None:
        """Set logger instance."""
        self.logger = logger

    def log(self, level: str, message: str) -> None:
        """Log a message."""
        if self.logger:
            getattr(self.logger, level)(f"[{self.name}] {message}")

    async def _execute_wrapper(
        self,
        request: ScanRequest,
        response: Optional[ScanResponse] = None,
        **kwargs,
    ) -> PluginResult:
        """
        Wrapper for execute method with tracking.

        Args:
            request: ScanRequest to process
            response: Optional ScanResponse to analyze
            **kwargs: Additional arguments

        Returns:
            PluginResult with execution outcome
        """
        if not self.enabled:
            return PluginResult(
                success=False, message="Plugin is disabled"
            )

        try:
            self._execution_count += 1
            result = await self.execute(request, response, **kwargs)
            return result
        except Exception as e:
            self._error_count += 1
            self.log("error", f"Execution failed: {str(e)}")
            return PluginResult(
                success=False, message=f"Plugin execution failed: {str(e)}"
            )

    def enable(self) -> None:
        """Enable the plugin."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the plugin."""
        self.enabled = False

    def reset_stats(self) -> None:
        """Reset execution statistics."""
        self._execution_count = 0
        self._error_count = 0


class PluginRegistry:
    """
    Registry for managing plugins.
    Handles plugin registration, loading, and discovery.
    """

    def __init__(self):
        """Initialize plugin registry."""
        self._plugins: Dict[str, Type[ScanPlugin]] = {}
        self._instances: Dict[str, ScanPlugin] = {}
        self._decorators: Dict[str, Callable] = {}

    def register(
        self,
        name: Optional[str] = None,
        plugin_type: Optional[PluginType] = None,
    ) -> Callable:
        """
        Decorator to register a plugin class.

        Args:
            name: Plugin name (uses class name if not provided)
            plugin_type: Plugin type

        Returns:
            Decorator function
        """
        def decorator(cls: Type[ScanPlugin]) -> Type[ScanPlugin]:
            plugin_name = name or cls.__name__
            self._plugins[plugin_name] = cls

            if plugin_type:
                cls.plugin_type = plugin_type

            return cls

        return decorator

    def register_instance(
        self, plugin: ScanPlugin, name: Optional[str] = None
    ) -> None:
        """
        Register a plugin instance directly.

        Args:
            plugin: Plugin instance
            name: Plugin name (uses plugin.name if not provided)
        """
        plugin_name = name or plugin.get_name()
        self._instances[plugin_name] = plugin

    def create_instance(
        self, plugin_name: str, **config
    ) -> Optional[ScanPlugin]:
        """
        Create a plugin instance from registered class.

        Args:
            plugin_name: Name of registered plugin
            **config: Configuration for plugin

        Returns:
            Plugin instance or None if not found
        """
        if plugin_name not in self._plugins:
            return None

        plugin_class = self._plugins[plugin_name]
        instance = plugin_class(**config)

        if instance.validate_config():
            self._instances[plugin_name] = instance
            return instance

        return None

    def get_plugin(self, name: str) -> Optional[ScanPlugin]:
        """
        Get a plugin instance by name.

        Args:
            name: Plugin name

        Returns:
            Plugin instance or None
        """
        return self._instances.get(name)

    def get_plugins_by_type(self, plugin_type: PluginType) -> List[ScanPlugin]:
        """
        Get all plugins of a specific type.

        Args:
            plugin_type: PluginType to filter by

        Returns:
            List of plugin instances
        """
        return [
            plugin
            for plugin in self._instances.values()
            if plugin.get_type() == plugin_type
        ]

    def list_plugins(self) -> List[str]:
        """
        List all registered plugin names.

        Returns:
            List of plugin names
        """
        return list(self._instances.keys())

    def list_available_plugins(self) -> List[str]:
        """
        List all available (not instantiated) plugin classes.

        Returns:
            List of plugin class names
        """
        return list(self._plugins.keys())

    def remove_plugin(self, name: str) -> bool:
        """
        Remove a plugin instance.

        Args:
            name: Plugin name

        Returns:
            True if removed, False if not found
        """
        if name in self._instances:
            del self._instances[name]
            return True
        return False

    def get_info(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get plugin metadata.

        Args:
            name: Plugin name

        Returns:
            Plugin metadata or None
        """
        plugin = self.get_plugin(name)
        if plugin:
            return plugin.get_metadata()
        return None

    def get_all_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get metadata for all plugins.

        Returns:
            Dictionary mapping plugin names to metadata
        """
        return {name: plugin.get_metadata() for name, plugin in self._instances.items()}


# Global plugin registry
_global_registry = PluginRegistry()


def register(
    name: Optional[str] = None,
    plugin_type: Optional[PluginType] = None,
) -> Callable:
    """
    Global decorator to register a plugin.

    Args:
        name: Plugin name
        plugin_type: Plugin type

    Returns:
        Decorator function
    """
    return _global_registry.register(name, plugin_type)


def get_plugin(name: str) -> Optional[ScanPlugin]:
    """
    Get a plugin from global registry.

    Args:
        name: Plugin name

    Returns:
        Plugin instance or None
    """
    return _global_registry.get_plugin(name)


def get_registry() -> PluginRegistry:
    """
    Get the global plugin registry.

    Returns:
        PluginRegistry instance
    """
    return _global_registry
