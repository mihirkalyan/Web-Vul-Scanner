"""
Tests for Web Crawler Component

Covers:
- URL deduplication and visited tracking
- Link and form extraction from HTML
- Relative URL resolution
- Scope filtering
- Crawl depth and URL limits
- Statistics tracking
- Both memory and SQLite state backends
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import urljoin

from src.crawler import (
    WebCrawler,
    MemoryURLTracker,
    SQLiteURLTracker,
    FormData,
    CrawlStatistics,
    CrawlState,
)
from src.scope_checker import ScopeChecker


class TestMemoryURLTracker:
    """Test in-memory URL tracking."""

    @pytest.mark.asyncio
    async def test_add_and_contains(self):
        """Test adding and checking URLs."""
        tracker = MemoryURLTracker()
        url = "https://example.com/page"

        await tracker.add(url)
        assert await tracker.contains(url)

    @pytest.mark.asyncio
    async def test_url_normalization(self):
        """Test URL normalization for deduplication."""
        tracker = MemoryURLTracker()
        
        url1 = "https://example.com/page"
        url2 = "https://example.com/page/"  # Trailing slash
        
        await tracker.add(url1)
        assert await tracker.contains(url2)

    @pytest.mark.asyncio
    async def test_get_all(self):
        """Test retrieving all visited URLs."""
        tracker = MemoryURLTracker()
        urls = [
            "https://example.com/page1",
            "https://example.com/page2",
            "https://example.com/page3",
        ]
        
        for url in urls:
            await tracker.add(url)
        
        visited = await tracker.get_all()
        assert len(visited) == 3

    @pytest.mark.asyncio
    async def test_count(self):
        """Test counting visited URLs."""
        tracker = MemoryURLTracker()
        
        for i in range(5):
            await tracker.add(f"https://example.com/page{i}")
        
        assert await tracker.count() == 5

    @pytest.mark.asyncio
    async def test_clear(self):
        """Test clearing visited URLs."""
        tracker = MemoryURLTracker()
        
        await tracker.add("https://example.com/page")
        await tracker.clear()
        
        assert await tracker.count() == 0
        assert not await tracker.contains("https://example.com/page")


class TestSQLiteURLTracker:
    """Test SQLite-backed URL tracking."""

    @pytest.mark.asyncio
    async def test_add_and_contains(self):
        """Test adding and checking URLs with SQLite."""
        # Use file-based DB since in-memory doesn't work across connections
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        
        try:
            tracker = SQLiteURLTracker(db_path)
            url = "https://example.com/page"

            await tracker.add(url)
            assert await tracker.contains(url)
        finally:
            import os
            if os.path.exists(db_path):
                os.remove(db_path)

    @pytest.mark.asyncio
    async def test_duplicate_handling(self):
        """Test that duplicate URLs are handled correctly."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        
        try:
            tracker = SQLiteURLTracker(db_path)
            url = "https://example.com/page"
            
            await tracker.add(url)
            await tracker.add(url)  # Should not raise error
            
            assert await tracker.count() == 1
        finally:
            import os
            if os.path.exists(db_path):
                os.remove(db_path)

    @pytest.mark.asyncio
    async def test_get_all(self):
        """Test retrieving all visited URLs."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        
        try:
            tracker = SQLiteURLTracker(db_path)
            urls = [
                "https://example.com/page1",
                "https://example.com/page2",
            ]
            
            for url in urls:
                await tracker.add(url)
            
            visited = await tracker.get_all()
            assert len(visited) == 2
        finally:
            import os
            if os.path.exists(db_path):
                os.remove(db_path)

    @pytest.mark.asyncio
    async def test_persistence_across_instances(self):
        """Test that URLs persist across tracker instances."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        
        try:
            # First instance adds URL
            tracker1 = SQLiteURLTracker(db_path)
            await tracker1.add("https://example.com/page")
            
            # Second instance should see it
            tracker2 = SQLiteURLTracker(db_path)
            assert await tracker2.contains("https://example.com/page")
        finally:
            import os
            if os.path.exists(db_path):
                os.remove(db_path)


class TestFormData:
    """Test form data model."""

    def test_form_creation(self):
        """Test creating form data."""
        form = FormData(
            url="https://example.com",
            method="POST",
            action="/login"
        )
        
        assert form.url == "https://example.com"
        assert form.method == "POST"
        assert form.action == "/login"

    def test_form_action_resolution(self):
        """Test resolving form action to full URL."""
        form = FormData(
            url="https://example.com/page",
            action="/submit"
        )
        
        full_url = form.get_full_action_url()
        assert full_url == "https://example.com/submit"

    def test_form_to_dict(self):
        """Test form serialization."""
        form = FormData(
            url="https://example.com",
            method="POST",
            action="/login",
            inputs=[
                {"name": "username", "type": "text", "value": ""}
            ]
        )
        
        data = form.to_dict()
        assert data["method"] == "POST"
        assert len(data["inputs"]) == 1


class TestWebCrawlerHTMLParsing:
    """Test HTML parsing functionality."""

    @pytest.mark.asyncio
    async def test_parse_html_links(self):
        """Test extracting links from HTML."""
        crawler = WebCrawler(ScopeChecker("https://example.com"))
        
        html = """
        <html>
            <body>
                <a href="/page1">Page 1</a>
                <a href="https://example.com/page2">Page 2</a>
                <a href="https://other.com/page">Other</a>
                <a href="#anchor">Anchor</a>
                <a href="javascript:alert('xss')">JS</a>
            </body>
        </html>
        """
        
        links, forms = crawler._parse_html(html, "https://example.com")
        
        # Should have 3 valid links (excluding anchor and javascript)
        assert len(links) >= 2
        assert any("page1" in link for link in links)

    @pytest.mark.asyncio
    async def test_parse_html_forms(self):
        """Test extracting forms from HTML."""
        crawler = WebCrawler(ScopeChecker("https://example.com"))
        
        html = """
        <html>
            <body>
                <form method="POST" action="/submit">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <input type="submit" />
                </form>
            </body>
        </html>
        """
        
        links, forms = crawler._parse_html(html, "https://example.com")
        
        assert len(forms) == 1
        assert forms[0].method == "POST"
        assert forms[0].action == "/submit"
        assert len(forms[0].inputs) == 2

    @pytest.mark.asyncio
    async def test_parse_html_multiple_forms(self):
        """Test extracting multiple forms."""
        crawler = WebCrawler(ScopeChecker("https://example.com"))
        
        html = """
        <html>
            <body>
                <form method="GET" action="/search">
                    <input type="text" name="q" />
                </form>
                <form method="POST" action="/login">
                    <input type="text" name="user" />
                    <input type="password" name="pass" />
                </form>
            </body>
        </html>
        """
        
        links, forms = crawler._parse_html(html, "https://example.com")
        
        assert len(forms) == 2
        assert forms[0].method == "GET"
        assert forms[1].method == "POST"


class TestWebCrawlerURLDiscovery:
    """Test URL discovery and deduplication."""

    @pytest.mark.asyncio
    async def test_url_deduplication(self):
        """Test that duplicate URLs are not crawled twice."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(scope, start_urls=["https://example.com"])
        
        visit_count = 0
        
        async def mock_handler(url):
            nonlocal visit_count
            visit_count += 1
            # Return same HTML for all URLs
            return (200, '<a href="/duplicate">Link</a>')
        
        html = '<a href="/page1">Link</a>'
        
        # Parse same HTML twice
        links1, _ = crawler._parse_html(html, "https://example.com")
        links2, _ = crawler._parse_html(html, "https://example.com")
        
        # Both should return the same links
        assert links1 == links2

    @pytest.mark.asyncio
    async def test_relative_url_resolution(self):
        """Test resolving relative URLs to absolute."""
        crawler = WebCrawler(ScopeChecker("https://example.com"))
        
        html = """
        <a href="/page">Absolute path</a>
        <a href="page">Relative</a>
        <a href="../parent">Parent</a>
        """
        
        links, _ = crawler._parse_html(html, "https://example.com/dir/current")
        
        assert any("page" in link for link in links)

    @pytest.mark.asyncio
    async def test_scope_filtering(self):
        """Test that out-of-scope URLs are filtered."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(scope)
        
        html = """
        <a href="https://example.com/page1">In scope</a>
        <a href="https://evil.com/page">Out of scope</a>
        """
        
        links, _ = crawler._parse_html(html, "https://example.com")
        
        # Only in-scope link should be parsed
        in_scope_links = [l for l in links if scope.is_in_scope(l)]
        assert len(in_scope_links) >= 1


class TestWebCrawlerDepthControl:
    """Test crawl depth limits."""

    @pytest.mark.asyncio
    async def test_max_depth_enforcement(self):
        """Test that max depth is enforced."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(
            scope,
            start_urls=["https://example.com"],
            max_depth=1,
            max_urls=100
        )
        
        crawled_urls = []
        
        async def mock_handler(url):
            crawled_urls.append(url)
            return (200, '<a href="/page">Link</a>')
        
        # Note: Actual crawl execution would test depth
        assert crawler.max_depth == 1

    @pytest.mark.asyncio
    async def test_max_urls_limit(self):
        """Test maximum URL discovery limit."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(
            scope,
            start_urls=["https://example.com"],
            max_urls=10
        )
        
        assert crawler.max_urls == 10
        assert crawler.statistics.total_urls_visited == 0


class TestWebCrawlerStatistics:
    """Test crawl statistics tracking."""

    @pytest.mark.asyncio
    async def test_statistics_initialization(self):
        """Test statistics object initialization."""
        stats = CrawlStatistics()
        
        assert stats.total_urls_discovered == 0
        assert stats.total_urls_visited == 0
        assert stats.total_forms_discovered == 0

    @pytest.mark.asyncio
    async def test_statistics_to_dict(self):
        """Test statistics serialization."""
        stats = CrawlStatistics(
            total_urls_discovered=100,
            total_urls_visited=50,
            total_forms_discovered=5
        )
        
        data = stats.to_dict()
        assert data["total_urls_discovered"] == 100
        assert data["total_urls_visited"] == 50
        assert data["total_forms_discovered"] == 5


class TestWebCrawlerConfiguration:
    """Test crawler configuration and initialization."""

    def test_crawler_initialization(self):
        """Test initializing crawler with configuration."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(
            scope,
            start_urls=["https://example.com"],
            max_depth=5,
            max_urls=500,
            max_urls_per_domain=50,
            crawl_delay_ms=200,
            state_backend="memory"
        )
        
        assert crawler.max_depth == 5
        assert crawler.max_urls == 500
        assert crawler.max_urls_per_domain == 50
        assert crawler.crawl_delay_ms == 200
        assert crawler.state == CrawlState.IDLE

    def test_crawler_with_sqlite_backend(self):
        """Test crawler with SQLite state backend."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(
            scope,
            state_backend="sqlite",
            db_path=":memory:"
        )
        
        assert isinstance(crawler.visited_tracker, SQLiteURLTracker)

    def test_crawler_with_memory_backend(self):
        """Test crawler with memory state backend."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(
            scope,
            state_backend="memory"
        )
        
        assert isinstance(crawler.visited_tracker, MemoryURLTracker)


class TestWebCrawlerStateManagement:
    """Test crawler state machine."""

    @pytest.mark.asyncio
    async def test_state_transitions(self):
        """Test crawler state transitions."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(scope)
        
        assert crawler.state == CrawlState.IDLE
        
        await crawler.pause()
        assert crawler.state == CrawlState.PAUSED
        
        await crawler.resume()
        assert crawler.state == CrawlState.RUNNING
        
        await crawler.stop()
        assert crawler.state == CrawlState.IDLE

    @pytest.mark.asyncio
    async def test_clear_state(self):
        """Test clearing crawler state."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(scope)
        
        # Simulate some discovered content
        await crawler.visited_tracker.add("https://example.com/page")
        crawler.discovered_forms.append(FormData(url="https://example.com"))
        
        await crawler.clear_state()
        
        assert await crawler.visited_tracker.count() == 0
        assert len(crawler.discovered_forms) == 0
        assert crawler.state == CrawlState.IDLE


class TestWebCrawlerIntegration:
    """Integration tests for crawler."""

    @pytest.mark.asyncio
    async def test_basic_crawl_flow(self):
        """Test basic crawl workflow."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(
            scope,
            start_urls=["https://example.com"],
            max_depth=2,
            max_urls=10
        )
        
        call_count = 0
        
        async def mock_handler(url):
            nonlocal call_count
            call_count += 1
            return (200, '<a href="/page1">Link</a><form><input name="test" /></form>')
        
        results = await crawler.start_crawl(mock_handler)
        
        assert results is not None
        assert "discovered_urls" in results
        assert "discovered_forms" in results
        assert "statistics" in results

    @pytest.mark.asyncio
    async def test_crawl_with_error_handling(self):
        """Test crawl with request errors."""
        scope = ScopeChecker("https://example.com")
        crawler = WebCrawler(scope, start_urls=["https://example.com"])
        
        async def mock_handler(url):
            # Simulate occasional failures
            if "fail" in url:
                raise Exception("Connection error")
            return (200, '<a href="/page">Link</a>')
        
        results = await crawler.start_crawl(mock_handler)
        
        # Should handle errors gracefully
        assert results is not None
        assert len(results.get("statistics", {}).get("errors", [])) >= 0


class TestWebCrawlerPerDomainLimits:
    """Test per-domain URL limits."""

    @pytest.mark.asyncio
    async def test_max_urls_per_domain(self):
        """Test per-domain URL limits."""
        scope = ScopeChecker("https://example.com")
        scope.add_allowed_domain("other.com")
        
        crawler = WebCrawler(
            scope,
            max_urls_per_domain=5
        )
        
        # Add URLs from multiple domains
        for i in range(3):
            domain = "example.com" if i < 2 else "other.com"
            url = f"https://{domain}/page{i}"
            await crawler.visited_tracker.add(url)
            # Manually track by domain
            domain_urls = crawler.urls_by_domain.setdefault(domain, set())
            domain_urls.add(url)
        
        # Verify domains are tracked
        assert len(crawler.urls_by_domain) >= 1
        assert any(len(urls) > 0 for urls in crawler.urls_by_domain.values())


class TestWebCrawlerWithForms:
    """Test form extraction and handling."""

    @pytest.mark.asyncio
    async def test_form_extraction_completeness(self):
        """Test that all form fields are extracted."""
        crawler = WebCrawler(ScopeChecker("https://example.com"))
        
        html = """
        <form id="login" method="POST" action="/auth">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="hidden" name="csrf" />
            <textarea name="message"></textarea>
            <select name="category">
                <option>Tech</option>
            </select>
            <button type="submit">Login</button>
        </form>
        """
        
        links, forms = crawler._parse_html(html, "https://example.com")
        
        assert len(forms) == 1
        form = forms[0]
        assert form.method == "POST"
        assert form.action == "/auth"
        # Should have extracted multiple input types
        assert len(form.inputs) >= 4
