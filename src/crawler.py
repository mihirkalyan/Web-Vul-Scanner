"""
Web Vulnerability Scanner - Crawler Module

Implements async web crawler for discovering URLs and forms from HTML responses.
Supports multiple state management strategies (async set, SQLite) and configurable
crawl depth/limits.

Features:
- Async HTML parsing with BeautifulSoup
- Link extraction from <a> tags
- Form discovery and extraction from <form> elements
- Relative URL resolution
- Visited URL deduplication
- Scope-aware crawling with domain filtering
- Configurable crawl depth and URL limits
- Per-domain rate limiting support
- Crawl statistics tracking
"""

import asyncio
import sqlite3
import re
from urllib.parse import urljoin, urlparse
from datetime import datetime
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional, Callable, Any
from enum import Enum
from pathlib import Path
from abc import ABC, abstractmethod

from bs4 import BeautifulSoup

from .models import ScanRequest, HTTPMethod
from .scope_checker import ScopeChecker


class CrawlState(Enum):
    """Crawler state machine."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class FormData:
    """Represents HTML form extraction."""
    url: str
    method: str = "GET"
    action: str = ""
    inputs: List[Dict[str, str]] = field(default_factory=list)
    
    def get_full_action_url(self) -> str:
        """Resolve form action to full URL."""
        if not self.action:
            return self.url
        return urljoin(self.url, self.action)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "method": self.method.upper(),
            "action": self.action,
            "full_action": self.get_full_action_url(),
            "inputs": self.inputs,
            "input_count": len(self.inputs)
        }


@dataclass
class CrawlStatistics:
    """Crawl session statistics."""
    total_urls_discovered: int = 0
    total_urls_queued: int = 0
    total_urls_skipped: int = 0
    total_urls_visited: int = 0
    total_forms_discovered: int = 0
    max_depth_reached: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)
    
    @property
    def elapsed_seconds(self) -> float:
        """Get elapsed time in seconds."""
        if not self.start_time:
            return 0.0
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_urls_discovered": self.total_urls_discovered,
            "total_urls_queued": self.total_urls_queued,
            "total_urls_skipped": self.total_urls_skipped,
            "total_urls_visited": self.total_urls_visited,
            "total_forms_discovered": self.total_forms_discovered,
            "max_depth_reached": self.max_depth_reached,
            "elapsed_seconds": self.elapsed_seconds,
            "error_count": len(self.errors),
            "errors": self.errors[-10:]  # Last 10 errors
        }


class VisitedURLTracker(ABC):
    """Abstract base class for visited URL tracking."""
    
    @abstractmethod
    async def add(self, url: str) -> None:
        """Add URL to visited set."""
        pass
    
    @abstractmethod
    async def contains(self, url: str) -> bool:
        """Check if URL has been visited."""
        pass
    
    @abstractmethod
    async def get_all(self) -> Set[str]:
        """Get all visited URLs."""
        pass
    
    @abstractmethod
    async def clear(self) -> None:
        """Clear all visited URLs."""
        pass
    
    @abstractmethod
    async def count(self) -> int:
        """Get count of visited URLs."""
        pass


class MemoryURLTracker(VisitedURLTracker):
    """In-memory visited URL tracking using async set."""
    
    def __init__(self):
        """Initialize memory-based tracker."""
        self.visited: Set[str] = set()
        self._lock = asyncio.Lock()
    
    async def add(self, url: str) -> None:
        """Add URL to visited set."""
        async with self._lock:
            self.visited.add(self._normalize_url(url))
    
    async def contains(self, url: str) -> bool:
        """Check if URL has been visited."""
        async with self._lock:
            return self._normalize_url(url) in self.visited
    
    async def get_all(self) -> Set[str]:
        """Get all visited URLs."""
        async with self._lock:
            return self.visited.copy()
    
    async def clear(self) -> None:
        """Clear all visited URLs."""
        async with self._lock:
            self.visited.clear()
    
    async def count(self) -> int:
        """Get count of visited URLs."""
        async with self._lock:
            return len(self.visited)
    
    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for comparison."""
        # Remove fragment and trailing slash
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized.rstrip("/")


class SQLiteURLTracker(VisitedURLTracker):
    """SQLite-backed persistent visited URL tracking."""
    
    def __init__(self, db_path: str = ":memory:"):
        """Initialize SQLite-based tracker."""
        self.db_path = db_path
        self._lock = asyncio.Lock()
        self._initialized = False
        self._init_sync()
    
    def _init_sync(self) -> None:
        """Initialize database schema (synchronous)."""
        if self._initialized:
            return
        
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS visited_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    normalized_url TEXT NOT NULL,
                    visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_normalized_url 
                ON visited_urls(normalized_url)
            """)
            conn.commit()
            self._initialized = True
        finally:
            conn.close()
    
    async def add(self, url: str) -> None:
        """Add URL to visited set."""
        async with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                normalized = self._normalize_url(url)
                cursor.execute(
                    "INSERT OR IGNORE INTO visited_urls (url, normalized_url) VALUES (?, ?)",
                    (url, normalized)
                )
                conn.commit()
            finally:
                conn.close()
    
    async def contains(self, url: str) -> bool:
        """Check if URL has been visited."""
        async with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                normalized = self._normalize_url(url)
                cursor.execute(
                    "SELECT 1 FROM visited_urls WHERE normalized_url = ?",
                    (normalized,)
                )
                return cursor.fetchone() is not None
            finally:
                conn.close()
    
    async def get_all(self) -> Set[str]:
        """Get all visited URLs."""
        async with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT url FROM visited_urls")
                return {row[0] for row in cursor.fetchall()}
            finally:
                conn.close()
    
    async def clear(self) -> None:
        """Clear all visited URLs."""
        async with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM visited_urls")
                conn.commit()
            finally:
                conn.close()
    
    async def count(self) -> int:
        """Get count of visited URLs."""
        async with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM visited_urls")
                return cursor.fetchone()[0]
            finally:
                conn.close()
    
    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for comparison."""
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized.rstrip("/")


class WebCrawler:
    """
    Async web crawler for discovering URLs and forms from HTML responses.
    
    Features:
    - Configurable state tracking (memory or SQLite)
    - BeautifulSoup-based HTML parsing
    - Link and form extraction
    - Relative URL resolution
    - Scope-aware filtering
    - Crawl depth and URL limits
    - Rate limiting support
    - Comprehensive statistics
    """
    
    def __init__(
        self,
        scope_checker: ScopeChecker,
        start_urls: Optional[List[str]] = None,
        max_depth: int = 3,
        max_urls: int = 1000,
        max_urls_per_domain: Optional[int] = None,
        crawl_delay_ms: int = 100,
        state_backend: str = "memory",
        db_path: Optional[str] = None,
        logger: Optional[Callable] = None,
    ):
        """
        Initialize web crawler.
        
        Args:
            scope_checker: ScopeChecker instance for URL validation
            start_urls: Initial URLs to crawl
            max_depth: Maximum crawl depth (0-based)
            max_urls: Maximum total URLs to discover
            max_urls_per_domain: Max URLs per domain (None = unlimited)
            crawl_delay_ms: Delay between requests in milliseconds
            state_backend: "memory" or "sqlite" for visited URL tracking
            db_path: SQLite database path (default: in-memory)
            logger: Optional logging callback function
        """
        self.scope_checker = scope_checker
        self.start_urls = start_urls or []
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.max_urls_per_domain = max_urls_per_domain
        self.crawl_delay_ms = crawl_delay_ms
        self.logger_fn = logger
        
        # State management
        if state_backend == "sqlite":
            self.visited_tracker: VisitedURLTracker = SQLiteURLTracker(
                db_path or ":memory:"
            )
        else:
            self.visited_tracker = MemoryURLTracker()
        
        # Crawl state
        self.state = CrawlState.IDLE
        self.statistics = CrawlStatistics()
        self.url_queue: asyncio.Queue = asyncio.Queue()
        self.urls_by_domain: Dict[str, Set[str]] = {}
        self.discovered_forms: List[FormData] = []
        self._current_depth = 0
    
    def log(self, level: str, message: str) -> None:
        """Log message."""
        if self.logger_fn:
            self.logger_fn(f"[CRAWLER] {level.upper()}: {message}")
    
    async def start_crawl(
        self,
        request_handler: Callable[[str], Any],
        html_parser: Optional[Callable[[str, str], tuple]] = None
    ) -> Dict[str, Any]:
        """
        Start crawling from initial URLs.
        
        Args:
            request_handler: Async callable that fetches and returns HTML
                            signature: async def handler(url) -> (status, body)
            html_parser: Optional async callable to parse HTML
                        signature: async def parser(html, base_url) -> (links, forms)
        
        Returns:
            Dictionary containing discovered URLs, forms, and statistics
        """
        self.state = CrawlState.RUNNING
        self.statistics.start_time = datetime.now()
        self.log("info", f"Starting crawl with {len(self.start_urls)} initial URLs")
        
        try:
            # Queue initial URLs
            for url in self.start_urls:
                await self.url_queue.put((url, 0))  # (url, depth)
            
            # Process queue
            while not self.url_queue.empty():
                if self.state != CrawlState.RUNNING:
                    break
                
                url, depth = await self.url_queue.get()
                
                # Check limits
                if self.statistics.total_urls_visited >= self.max_urls:
                    self.log("info", f"Reached max URLs limit ({self.max_urls})")
                    break
                
                if depth > self.max_depth:
                    self.statistics.max_depth_reached = max(
                        self.statistics.max_depth_reached, depth
                    )
                    self.statistics.total_urls_skipped += 1
                    continue
                
                # Check if already visited
                if await self.visited_tracker.contains(url):
                    self.statistics.total_urls_skipped += 1
                    continue
                
                # Check per-domain limits
                domain = urlparse(url).netloc
                domain_urls = self.urls_by_domain.setdefault(domain, set())
                
                if (self.max_urls_per_domain and 
                    len(domain_urls) >= self.max_urls_per_domain):
                    self.statistics.total_urls_skipped += 1
                    continue
                
                # Mark as visited
                await self.visited_tracker.add(url)
                domain_urls.add(url)
                self.statistics.total_urls_visited += 1
                
                # Crawl URL
                try:
                    # Crawl delay
                    await asyncio.sleep(self.crawl_delay_ms / 1000.0)
                    
                    # Fetch content
                    status, html = await request_handler(url)
                    
                    if status not in [200, 201, 202, 203, 204, 206]:
                        self.log("debug", f"Non-2xx response from {url}: {status}")
                        continue
                    
                    # Parse HTML
                    if html_parser:
                        links, forms = await html_parser(html, url)
                    else:
                        links, forms = self._parse_html(html, url)
                    
                    # Queue new links
                    for link in links:
                        if not await self.visited_tracker.contains(link):
                            self.statistics.total_urls_discovered += 1
                            if self.scope_checker.is_in_scope(link):
                                await self.url_queue.put((link, depth + 1))
                                self.statistics.total_urls_queued += 1
                            else:
                                self.statistics.total_urls_skipped += 1
                    
                    # Store forms
                    self.statistics.total_forms_discovered += len(forms)
                    self.discovered_forms.extend(forms)
                    
                    self.log("info", f"Crawled {url} (depth={depth}, "
                            f"links={len(links)}, forms={len(forms)})")
                    
                except Exception as e:
                    error_msg = f"Error crawling {url}: {str(e)}"
                    self.log("error", error_msg)
                    self.statistics.errors.append(error_msg)
            
            self.state = CrawlState.COMPLETED
            self.log("info", "Crawl completed")
            
        except Exception as e:
            self.state = CrawlState.FAILED
            error_msg = f"Crawl failed: {str(e)}"
            self.log("error", error_msg)
            self.statistics.errors.append(error_msg)
            raise
        
        finally:
            self.statistics.end_time = datetime.now()
        
        # Get results with discovered URLs
        results = self._get_results()
        results["discovered_urls"] = await self.get_discovered_urls()
        return results
    
    def _parse_html(self, html: str, base_url: str) -> tuple:
        """
        Parse HTML to extract links and forms.
        
        Args:
            html: HTML content
            base_url: Base URL for resolving relative links
        
        Returns:
            Tuple of (links list, forms list)
        """
        try:
            soup = BeautifulSoup(html, "html.parser")
            links = set()
            forms = []
            
            # Extract links from <a> tags
            for tag in soup.find_all("a", href=True):
                href = tag.get("href", "").strip()
                if href and not href.startswith("#"):
                    try:
                        absolute_url = urljoin(base_url, href)
                        # Filter javascript: and mailto: links
                        if not absolute_url.startswith(("javascript:", "mailto:")):
                            links.add(absolute_url)
                    except Exception:
                        pass
            
            # Extract forms from <form> tags
            for form_tag in soup.find_all("form"):
                form_data = FormData(
                    url=base_url,
                    method=(form_tag.get("method", "GET")).upper(),
                    action=form_tag.get("action", ""),
                )
                
                # Extract form inputs
                for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                    input_name = input_tag.get("name", "")
                    input_type = input_tag.get("type", "text").lower()
                    
                    if input_name:
                        form_data.inputs.append({
                            "name": input_name,
                            "type": input_type,
                            "value": input_tag.get("value", "")
                        })
                
                forms.append(form_data)
            
            return list(links), forms
        
        except Exception as e:
            self.log("error", f"HTML parsing error: {str(e)}")
            return [], []
    
    async def get_discovered_urls(self) -> Set[str]:
        """Get all discovered URLs."""
        return await self.visited_tracker.get_all()
    
    async def get_discovered_forms(self) -> List[FormData]:
        """Get all discovered forms."""
        return self.discovered_forms.copy()
    
    def get_statistics(self) -> CrawlStatistics:
        """Get crawl statistics."""
        return self.statistics
    
    async def pause(self) -> None:
        """Pause crawling."""
        self.state = CrawlState.PAUSED
        self.log("info", "Crawl paused")
    
    async def resume(self) -> None:
        """Resume crawling."""
        if self.state == CrawlState.PAUSED:
            self.state = CrawlState.RUNNING
            self.log("info", "Crawl resumed")
    
    async def stop(self) -> None:
        """Stop crawling."""
        self.state = CrawlState.IDLE
        self.log("info", "Crawl stopped")
    
    async def clear_state(self) -> None:
        """Clear visited URLs and state."""
        await self.visited_tracker.clear()
        self.discovered_forms.clear()
        self.urls_by_domain.clear()
        self.statistics = CrawlStatistics()
        self.state = CrawlState.IDLE
        self.log("info", "Crawler state cleared")
    
    def _get_results(self) -> Dict[str, Any]:
        """Get crawl results."""
        # Don't use asyncio.run() since we're already in async context
        # Return data that can be awaited by caller
        return {
            "discovered_urls": [],  # Will be populated by caller
            "discovered_forms": [f.to_dict() for f in self.discovered_forms],
            "statistics": self.statistics.to_dict(),
            "state": self.state.value
        }
