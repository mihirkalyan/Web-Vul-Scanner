"""
Tests for OrchestratorEngine
"""

import pytest
import asyncio
import logging
from src.orchestrator import OrchestratorEngine, ScanPriority, ScanTask, ScanResult


class TestOrchestratorBasic:
    """Test basic orchestrator functionality."""

    @pytest.fixture
    def engine(self):
        return OrchestratorEngine("https://example.com", max_concurrent_tasks=10)

    @pytest.mark.asyncio
    async def test_submit_task_in_scope(self, engine):
        """Test submitting a task with in-scope URL."""
        task_id = await engine.submit_task("https://example.com/page")
        assert task_id is not None
        assert task_id in engine.pending_tasks

    @pytest.mark.asyncio
    async def test_submit_task_out_of_scope(self, engine):
        """Test submitting a task with out-of-scope URL."""
        task_id = await engine.submit_task("https://evil.com/attack")
        assert task_id is None
        assert len(engine.pending_tasks) == 0

    @pytest.mark.asyncio
    async def test_submit_multiple_urls(self, engine):
        """Test submitting multiple URLs."""
        urls = [
            "https://example.com/page1",
            "https://api.example.com/endpoint",
            "https://evil.com",  # Out of scope
        ]

        task_ids = await engine.submit_urls(urls)
        assert len(task_ids) == 2
        assert len(engine.pending_tasks) == 2

    def test_get_stats(self, engine):
        """Test statistics gathering."""
        stats = engine.get_stats()

        assert stats["total_tasks"] == 0
        assert stats["pending"] == 0
        assert stats["max_concurrent"] == 10
        assert "example.com" in stats["allowed_domains"]


class TestOrchestratorConcurrency:
    """Test concurrency and semaphore control."""

    @pytest.fixture
    def engine(self):
        return OrchestratorEngine("https://example.com", max_concurrent_tasks=3)

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(self, engine):
        """Test that semaphore limits concurrent tasks."""
        max_concurrent = 0
        lock = asyncio.Lock()

        async def mock_handler(url: str):
            nonlocal max_concurrent
            current_concurrent = len(engine.running_tasks)

            async with lock:
                max_concurrent = max(max_concurrent, current_concurrent)

            # Simulate work
            await asyncio.sleep(0.1)
            return {"status": "scanned", "url": url}

        # Submit tasks
        urls = [f"https://example.com/page{i}" for i in range(10)]
        await engine.submit_urls(urls)

        # Run scan
        results = await engine.run_scan(mock_handler)

        assert len(results) == 10
        assert max_concurrent <= engine.max_concurrent_tasks

    @pytest.mark.asyncio
    async def test_priority_execution_order(self, engine):
        """Test that high-priority tasks execute first."""
        execution_order = []

        async def tracking_handler(url: str):
            execution_order.append(url)
            await asyncio.sleep(0.05)
            return {"url": url}

        # Submit tasks with different priorities
        high_task = await engine.submit_task(
            "https://example.com/high",
            ScanPriority.HIGH
        )
        low_task = await engine.submit_task(
            "https://example.com/low",
            ScanPriority.LOW
        )
        medium_task = await engine.submit_task(
            "https://example.com/medium",
            ScanPriority.MEDIUM
        )

        await engine.run_scan(tracking_handler)

        # High should execute before medium, medium before low
        high_idx = execution_order.index("https://example.com/high")
        medium_idx = execution_order.index("https://example.com/medium")
        low_idx = execution_order.index("https://example.com/low")

        assert high_idx < medium_idx < low_idx


class TestOrchestratorErrorHandling:
    """Test error handling and retry logic."""

    @pytest.fixture
    def engine(self):
        return OrchestratorEngine(
            "https://example.com",
            max_concurrent_tasks=5,
            max_retries=3
        )

    @pytest.mark.asyncio
    async def test_task_retry_on_failure(self, engine):
        """Test that failed tasks are retried."""
        attempt_count = {}

        async def failing_handler(url: str):
            attempt_count[url] = attempt_count.get(url, 0) + 1
            if attempt_count[url] < 3:
                raise Exception("Temporary failure")
            return {"status": "success"}

        task_id = await engine.submit_task("https://example.com/test")
        results = await engine.run_scan(failing_handler)

        # Should have retried 3 times before success
        assert attempt_count["https://example.com/test"] >= 3
        assert results[task_id].status == "success"

    @pytest.mark.asyncio
    async def test_task_timeout(self, engine):
        """Test task timeout handling."""
        engine.request_timeout = 0.1

        async def slow_handler(url: str):
            await asyncio.sleep(1.0)
            return {"status": "success"}

        task_id = await engine.submit_task("https://example.com/slow")
        results = await engine.run_scan(slow_handler)

        assert results[task_id].status == "failed"
        assert "Timeout" in results[task_id].error

    @pytest.mark.asyncio
    async def test_task_permanent_failure(self, engine):
        """Test handling of permanently failed tasks."""
        async def always_failing_handler(url: str):
            raise Exception("Permanent failure")

        task_id = await engine.submit_task("https://example.com/fail")
        results = await engine.run_scan(always_failing_handler)

        # After all retries, should be in failed tasks
        assert task_id in engine.failed_tasks
        assert results[task_id].status == "failed"

    @pytest.mark.asyncio
    async def test_get_failed_results(self, engine):
        """Test retrieving failed task results."""
        async def failing_handler(url: str):
            raise Exception("Test failure")

        await engine.submit_task("https://example.com/fail")
        await engine.run_scan(failing_handler)

        failed = engine.get_failed_results()
        assert len(failed) == 1
        assert "Test failure" in list(failed.values())[0].error


class TestOrchestratorScoping:
    """Test scope management features."""

    @pytest.mark.asyncio
    async def test_additional_domains(self):
        """Test orchestrator with additional allowed domains."""
        engine = OrchestratorEngine(
            "https://example.com",
            additional_domains=["partner.io"]
        )

        task1 = await engine.submit_task("https://example.com/page")
        task2 = await engine.submit_task("https://partner.io/api")
        task3 = await engine.submit_task("https://evil.com")

        assert task1 is not None
        assert task2 is not None
        assert task3 is None

    @pytest.mark.asyncio
    async def test_add_allowed_domain_dynamically(self, ):
        """Test adding allowed domains after engine creation."""
        engine = OrchestratorEngine("https://example.com")

        # Initially not allowed
        task1 = await engine.submit_task("https://trusted.io/page")
        assert task1 is None

        # Add domain
        engine.add_allowed_domain("trusted.io")

        # Now should be allowed
        task2 = await engine.submit_task("https://trusted.io/page")
        assert task2 is not None

    @pytest.mark.asyncio
    async def test_subdomain_scanning(self, ):
        """Test scanning across subdomains."""
        engine = OrchestratorEngine("https://example.com")

        urls = [
            "https://example.com/main",
            "https://api.example.com/endpoint",
            "https://admin.example.com/dashboard",
            "https://app.api.example.com/data",
        ]

        task_ids = await engine.submit_urls(urls)
        assert len(task_ids) == 4


class TestOrchestratorLifecycle:
    """Test engine lifecycle and state management."""

    @pytest.mark.asyncio
    async def test_reset_engine(self, ):
        """Test resetting engine for new scan."""
        engine = OrchestratorEngine("https://example.com")

        async def dummy_handler(url: str):
            return {"status": "scanned"}

        # Run a scan
        await engine.submit_task("https://example.com/page")
        await engine.run_scan(dummy_handler)

        assert len(engine.completed_tasks) > 0

        # Reset
        engine.reset()

        assert len(engine.pending_tasks) == 0
        assert len(engine.completed_tasks) == 0
        assert len(engine.failed_tasks) == 0

    @pytest.mark.asyncio
    async def test_get_results(self, ):
        """Test retrieving scan results."""
        engine = OrchestratorEngine("https://example.com")

        async def dummy_handler(url: str):
            return {"data": "test_result"}

        await engine.submit_task("https://example.com/page")
        await engine.run_scan(dummy_handler)

        results = engine.get_scan_results()
        assert len(results) == 1

        result = list(results.values())[0]
        assert result.status == "success"
        assert result.result_data["data"] == "test_result"

    def test_logging(self, ):
        """Test logging functionality."""
        logger = logging.getLogger("test_logger")
        engine = OrchestratorEngine("https://example.com", logger=logger)

        assert engine.logger == logger
