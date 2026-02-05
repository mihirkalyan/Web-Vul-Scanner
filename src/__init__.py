"""
Web Vulnerability Scanner - Orchestrator Engine with Plugin System and Crawler
"""

from .orchestrator import OrchestratorEngine, ScanPriority, ScanTask, ScanResult
from .scope_checker import ScopeChecker
from .crawler import (
    WebCrawler,
    MemoryURLTracker,
    SQLiteURLTracker,
    FormData,
    CrawlStatistics,
    CrawlState,
)
from .models import (
    ScanRequest,
    ScanResponse,
    HTTPMethod,
    ContentType,
    Cookie,
)
from .plugin import (
    ScanPlugin,
    PluginResult,
    PluginType,
    PluginRegistry,
    register,
    get_plugin,
    get_registry,
)

__version__ = "3.0.0"
__all__ = [
    # Orchestrator
    "OrchestratorEngine",
    "ScanPriority",
    "ScanTask",
    "ScanResult",
    "ScopeChecker",
    # Crawler
    "WebCrawler",
    "MemoryURLTracker",
    "SQLiteURLTracker",
    "FormData",
    "CrawlStatistics",
    "CrawlState",
    # Models
    "ScanRequest",
    "ScanResponse",
    "HTTPMethod",
    "ContentType",
    "Cookie",
    # Plugin System
    "ScanPlugin",
    "PluginResult",
    "PluginType",
    "PluginRegistry",
    "register",
    "get_plugin",
    "get_registry",
]

