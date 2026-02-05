"""
Plugin Loader - Dynamic plugin loading and discovery

Provides utilities for loading plugins from files and directories.
"""

import importlib
import inspect
import sys
from pathlib import Path
from typing import List, Optional, Dict, Type

from .plugin import ScanPlugin, PluginRegistry, get_registry


class PluginLoader:
    """Loads and discovers plugins from Python modules."""

    def __init__(self, registry: Optional[PluginRegistry] = None):
        """
        Initialize plugin loader.

        Args:
            registry: Optional custom registry (uses global if not provided)
        """
        self.registry = registry or get_registry()
        self.loaded_modules: List[str] = []

    def load_from_module(self, module_name: str) -> int:
        """
        Load plugins from a Python module.

        Args:
            module_name: Fully qualified module name (e.g., 'src.plugins.header_injector')

        Returns:
            Number of plugins loaded
        """
        try:
            if module_name in self.loaded_modules:
                return 0

            module = importlib.import_module(module_name)
            self.loaded_modules.append(module_name)

            # Find all plugin classes in module
            count = 0
            for name, obj in inspect.getmembers(module):
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, ScanPlugin)
                    and obj is not ScanPlugin
                ):
                    count += 1

            return count
        except ImportError as e:
            raise ImportError(f"Failed to load module {module_name}: {str(e)}")

    def load_from_directory(self, directory_path: str, recursive: bool = True) -> int:
        """
        Load plugins from a directory.

        Args:
            directory_path: Path to plugin directory
            recursive: If True, recursively load from subdirectories

        Returns:
            Number of plugins loaded
        """
        path = Path(directory_path)
        if not path.exists():
            raise ValueError(f"Directory does not exist: {directory_path}")

        if not path.is_dir():
            raise ValueError(f"Path is not a directory: {directory_path}")

        total_loaded = 0

        # Find all Python files
        if recursive:
            py_files = list(path.rglob("*.py"))
        else:
            py_files = list(path.glob("*.py"))

        for py_file in py_files:
            if py_file.name.startswith("_"):
                continue

            # Convert file path to module name
            module_name = self._path_to_module_name(py_file)

            try:
                loaded = self.load_from_module(module_name)
                total_loaded += loaded
            except (ImportError, ValueError):
                # Skip files that can't be loaded
                continue

        return total_loaded

    def _path_to_module_name(self, file_path: Path) -> str:
        """
        Convert file path to module name.

        Args:
            file_path: Path to Python file

        Returns:
            Module name (e.g., 'src.plugins.header_injector')
        """
        # Remove .py extension
        module_path = file_path.with_suffix("")

        # Find the project root (containing src directory)
        current = file_path.parent
        parts = []

        while current != current.parent:
            parts.insert(0, current.name)
            current = current.parent

            # Stop if we reach src directory
            if current.name == "src" or (current / "src").exists():
                break

        # Add the file name
        parts.append(file_path.stem)

        return ".".join(parts)

    def load_built_in_plugins(self) -> int:
        """
        Load all built-in plugins from src/plugins directory.

        Returns:
            Number of plugins loaded
        """
        # Get the plugins directory relative to this file
        current_dir = Path(__file__).parent
        plugins_dir = current_dir / "plugins"

        if not plugins_dir.exists():
            return 0

        return self.load_from_directory(str(plugins_dir), recursive=True)

    def get_loaded_modules(self) -> List[str]:
        """
        Get list of loaded module names.

        Returns:
            List of module names
        """
        return self.loaded_modules.copy()

    def list_available_plugins(self) -> Dict[str, Type[ScanPlugin]]:
        """
        List all available plugin classes.

        Returns:
            Dictionary mapping plugin names to classes
        """
        plugins = {}

        for name, obj in sys.modules.items():
            if not hasattr(obj, "__dict__"):
                continue

            for attr_name, attr_obj in obj.__dict__.items():
                if (
                    inspect.isclass(attr_obj)
                    and issubclass(attr_obj, ScanPlugin)
                    and attr_obj is not ScanPlugin
                ):
                    plugins[attr_obj.__name__] = attr_obj

        return plugins


# Global plugin loader instance
_global_loader = None


def get_loader(registry: Optional[PluginRegistry] = None) -> PluginLoader:
    """
    Get the global plugin loader instance.

    Args:
        registry: Optional custom registry

    Returns:
        PluginLoader instance
    """
    global _global_loader
    if _global_loader is None:
        _global_loader = PluginLoader(registry)
    return _global_loader


def load_built_in_plugins() -> int:
    """
    Load all built-in plugins.

    Returns:
        Number of plugins loaded
    """
    loader = get_loader()
    return loader.load_built_in_plugins()
