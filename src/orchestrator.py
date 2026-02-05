"""
Orchestrator Engine - Manages scan speed, scope, and concurrent tasks
"""

import asyncio
import logging
from typing import Callable, List, Dict, Any, Optional, Set
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

from .scope_checker import ScopeChecker
from .crawler import WebCrawler


class ScanPriority(Enum):
    """Priority levels for scan tasks."""
    LOW = 3
    MEDIUM = 2
    HIGH = 1


@dataclass
class ScanTask:
    """Represents a single scan task."""
    url: str
    priority: ScanPriority = ScanPriority.MEDIUM
    task_id: str = None
    created_at: datetime = None
    max_retries: int = 3
    timeout: float = 30.0

    def __post_init__(self):
        if self.task_id is None:
            self.task_id = f"{hash(self.url)}_{datetime.now().timestamp()}"
        if self.created_at is None:
            self.created_at = datetime.now()


@dataclass
class ScanResult:
    """Result of a completed scan task."""
    task_id: str
    url: str
    status: str  # 'success', 'failed', 'skipped'
    result_data: Any = None
    error: Optional[str] = None
    elapsed_time: float = 0.0


class OrchestratorEngine:
    """
    Orchestrates the vulnerability scan workflow.
    Manages concurrent tasks, enforces scope boundaries, and controls scan speed.
    """

    def __init__(
        self,
        base_url: str,
        max_concurrent_tasks: int = 10,
        max_retries: int = 3,
        request_timeout: float = 30.0,
        additional_domains: List[str] = None,
        logger: logging.Logger = None,
    ):
        """
        Initialize the OrchestratorEngine.

        Args:
            base_url: Target URL for scanning
            max_concurrent_tasks: Maximum number of concurrent tasks (default: 10)
            max_retries: Maximum retries for failed tasks
            request_timeout: Timeout for individual requests in seconds
            additional_domains: Optional list of additional allowed domains
            logger: Optional logger instance
        """
        self.base_url = base_url
        self.max_concurrent_tasks = max_concurrent_tasks
        self.max_retries = max_retries
        self.request_timeout = request_timeout

        # Scope management
        self.scope_checker = ScopeChecker(base_url, additional_domains)

        # Concurrency control
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)

        # Task tracking
        self.pending_tasks: Dict[str, ScanTask] = {}
        self.running_tasks: Set[str] = set()
        self.completed_tasks: Dict[str, ScanResult] = {}
        self.failed_tasks: Dict[str, ScanResult] = {}

        # Logging
        self.logger = logger or self._setup_default_logger()

    def _setup_default_logger(self) -> logging.Logger:
        """Setup default logger for the engine."""
        logger = logging.getLogger("OrchestratorEngine")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    async def submit_task(self, url: str, priority: ScanPriority = ScanPriority.MEDIUM) -> str:
        """
        Submit a URL for scanning if it's within scope.

        Args:
            url: URL to scan
            priority: Task priority level

        Returns:
            Task ID if accepted, None if out of scope
        """
        # Validate scope
        if not self.scope_checker.is_in_scope(url):
            self.logger.warning(f"URL out of scope: {url}")
            return None

        # Create task
        task = ScanTask(url=url, priority=priority, timeout=self.request_timeout)
        self.pending_tasks[task.task_id] = task

        self.logger.info(f"Task submitted: {task.task_id} - {url}")
        return task.task_id

    async def submit_urls(self, urls: List[str], priority: ScanPriority = ScanPriority.MEDIUM) -> List[str]:
        """
        Submit multiple URLs for scanning.

        Args:
            urls: List of URLs to scan
            priority: Task priority level

        Returns:
            List of accepted task IDs
        """
        task_ids = []
        for url in urls:
            task_id = await self.submit_task(url, priority)
            if task_id:
                task_ids.append(task_id)
        return task_ids

    async def execute_task(
        self,
        task: ScanTask,
        task_handler: Callable,
    ) -> ScanResult:
        """
        Execute a single scan task with semaphore control and retry logic.

        Args:
            task: ScanTask to execute
            task_handler: Async callable that performs the actual scan

        Returns:
            ScanResult with execution details
        """
        start_time = datetime.now()

        async with self.semaphore:
            self.running_tasks.add(task.task_id)
            self.logger.info(
                f"Executing task: {task.task_id} (Concurrent: {len(self.running_tasks)}/{self.max_concurrent_tasks})"
            )

            retry_count = 0
            last_error = None

            while retry_count < task.max_retries:
                try:
                    # Execute task handler with timeout
                    result_data = await asyncio.wait_for(
                        task_handler(task.url),
                        timeout=task.timeout,
                    )

                    elapsed_time = (datetime.now() - start_time).total_seconds()

                    result = ScanResult(
                        task_id=task.task_id,
                        url=task.url,
                        status="success",
                        result_data=result_data,
                        elapsed_time=elapsed_time,
                    )

                    self.completed_tasks[task.task_id] = result
                    self.logger.info(f"Task completed: {task.task_id} ({elapsed_time:.2f}s)")
                    return result

                except asyncio.TimeoutError as e:
                    last_error = f"Timeout after {task.timeout}s"
                    self.logger.warning(f"Task timeout: {task.task_id} (Attempt {retry_count + 1}/{task.max_retries})")

                except Exception as e:
                    last_error = str(e)
                    self.logger.warning(
                        f"Task failed: {task.task_id} - {last_error} (Attempt {retry_count + 1}/{task.max_retries})"
                    )

                retry_count += 1
                if retry_count < task.max_retries:
                    # Exponential backoff before retry
                    await asyncio.sleep(2 ** retry_count)

            # Task exhausted retries
            elapsed_time = (datetime.now() - start_time).total_seconds()
            result = ScanResult(
                task_id=task.task_id,
                url=task.url,
                status="failed",
                error=last_error,
                elapsed_time=elapsed_time,
            )

            self.failed_tasks[task.task_id] = result
            self.logger.error(f"Task failed permanently: {task.task_id} - {last_error}")
            return result

        self.running_tasks.discard(task.task_id)

    async def run_scan(self, task_handler: Callable) -> Dict[str, ScanResult]:
        """
        Execute all pending tasks with controlled concurrency.

        Args:
            task_handler: Async callable that performs the actual scan

        Returns:
            Dictionary of all completed task results
        """
        self.logger.info(
            f"Starting scan with {len(self.pending_tasks)} tasks "
            f"(max concurrent: {self.max_concurrent_tasks})"
        )

        # Sort tasks by priority (lower enum value = higher priority)
        sorted_tasks = sorted(
            self.pending_tasks.values(),
            key=lambda t: t.priority.value,
        )

        # Create tasks for all scans
        scan_tasks = [
            self.execute_task(task, task_handler)
            for task in sorted_tasks
        ]

        # Execute all tasks with controlled concurrency
        results = await asyncio.gather(*scan_tasks, return_exceptions=False)

        self.logger.info(
            f"Scan completed. Success: {len(self.completed_tasks)}, "
            f"Failed: {len(self.failed_tasks)}"
        )

        return {**self.completed_tasks, **self.failed_tasks}

    def get_stats(self) -> Dict[str, Any]:
        """
        Get current scan statistics.

        Returns:
            Dictionary with scan statistics
        """
        total_tasks = len(self.pending_tasks) + len(self.completed_tasks) + len(self.failed_tasks)
        return {
            "total_tasks": total_tasks,
            "pending": len(self.pending_tasks),
            "running": len(self.running_tasks),
            "completed": len(self.completed_tasks),
            "failed": len(self.failed_tasks),
            "max_concurrent": self.max_concurrent_tasks,
            "allowed_domains": list(self.scope_checker.get_allowed_domains()),
        }

    def add_allowed_domain(self, domain: str):
        """
        Add an additional allowed domain to the scope.

        Args:
            domain: Domain to add
        """
        self.scope_checker.add_allowed_domain(domain)
        self.logger.info(f"Added allowed domain: {domain}")

    def get_scan_results(self) -> Dict[str, ScanResult]:
        """
        Get all completed scan results.

        Returns:
            Dictionary of completed task results
        """
        return self.completed_tasks.copy()

    def get_failed_results(self) -> Dict[str, ScanResult]:
        """
        Get all failed scan results.

        Returns:
            Dictionary of failed task results
        """
        return self.failed_tasks.copy()

    async def start_crawl(
        self,
        start_urls: List[str],
        request_handler: Callable,
        max_depth: int = 3,
        max_urls: int = 1000,
        max_urls_per_domain: Optional[int] = None,
        crawl_delay_ms: int = 100,
        auto_submit_urls: bool = True,
    ) -> Dict[str, Any]:
        """
        Start web crawling from initial URLs and optionally submit discovered URLs.

        Args:
            start_urls: Initial URLs to crawl
            request_handler: Async callable for HTTP requests (url -> (status, html))
            max_depth: Maximum crawl depth
            max_urls: Maximum total URLs to discover
            max_urls_per_domain: Max URLs per domain (None = unlimited)
            crawl_delay_ms: Delay between requests in milliseconds
            auto_submit_urls: Automatically submit discovered URLs to scanner queue

        Returns:
            Dictionary with crawl results (urls, forms, stats)
        """
        self.logger.info(f"Starting crawl from {len(start_urls)} initial URLs")

        # Initialize crawler
        crawler = WebCrawler(
            scope_checker=self.scope_checker,
            start_urls=start_urls,
            max_depth=max_depth,
            max_urls=max_urls,
            max_urls_per_domain=max_urls_per_domain,
            crawl_delay_ms=crawl_delay_ms,
            logger=lambda msg: self.logger.info(msg) if "INFO" in msg else self.logger.debug(msg),
        )

        # Run crawler
        try:
            results = await crawler.start_crawl(request_handler)

            # Auto-submit discovered URLs if enabled
            if auto_submit_urls:
                discovered_urls = results.get("discovered_urls", [])
                self.logger.info(f"Auto-submitting {len(discovered_urls)} discovered URLs")
                await self.submit_urls(list(discovered_urls))

            self.logger.info(f"Crawl completed: {crawler.statistics.to_dict()}")
            return results

        except Exception as e:
            self.logger.error(f"Crawl failed: {str(e)}")
            raise

    def reset(self):
        """Reset the engine for a new scan."""
        self.pending_tasks.clear()
        self.running_tasks.clear()
        self.completed_tasks.clear()
        self.failed_tasks.clear()
        self.logger.info("Engine reset for new scan")
