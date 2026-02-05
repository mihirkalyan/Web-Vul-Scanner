"""
Tests for ScopeChecker
"""

import pytest
from src.scope_checker import ScopeChecker


class TestScopeCheckerBasic:
    """Test basic scope checking functionality."""

    @pytest.fixture
    def checker(self):
        return ScopeChecker("https://example.com")

    def test_exact_domain_match(self, checker):
        """Test that exact domain matches are accepted."""
        assert checker.is_in_scope("https://example.com/page")
        assert checker.is_in_scope("https://example.com")

    def test_subdomain_allowed(self, checker):
        """Test that subdomains are allowed."""
        assert checker.is_in_scope("https://api.example.com/endpoint")
        assert checker.is_in_scope("https://app.example.com")
        assert checker.is_in_scope("https://admin.api.example.com/test")

    def test_www_prefix_handling(self, checker):
        """Test www prefix handling."""
        assert checker.is_in_scope("https://www.example.com")
        assert checker.is_in_scope("https://www.api.example.com")

    def test_external_domain_blocked(self, checker):
        """Test that external domains are blocked."""
        assert not checker.is_in_scope("https://evil.com")
        assert not checker.is_in_scope("https://example.com.evil.com")
        assert not checker.is_in_scope("https://another.org")

    def test_invalid_protocols_blocked(self, checker):
        """Test that non-HTTP(S) protocols are blocked."""
        assert not checker.is_in_scope("ftp://example.com")
        assert not checker.is_in_scope("file:///etc/passwd")
        assert not checker.is_in_scope("javascript:alert('xss')")

    def test_case_insensitive(self, checker):
        """Test case-insensitive domain matching."""
        assert checker.is_in_scope("https://EXAMPLE.COM")
        assert checker.is_in_scope("https://API.EXAMPLE.COM")
        assert checker.is_in_scope("https://Example.Com/Page")


class TestScopeCheckerAdvanced:
    """Test advanced scope checking functionality."""

    def test_multiple_allowed_domains(self):
        """Test scope checker with multiple allowed domains."""
        checker = ScopeChecker(
            "https://example.com",
            additional_domains=["partner.io", "api.service.org"]
        )

        assert checker.is_in_scope("https://example.com")
        assert checker.is_in_scope("https://partner.io")
        assert checker.is_in_scope("https://api.service.org")
        assert not checker.is_in_scope("https://evil.com")

    def test_add_allowed_domain(self):
        """Test adding domains dynamically."""
        checker = ScopeChecker("https://example.com")
        assert not checker.is_in_scope("https://trusted.io")

        checker.add_allowed_domain("trusted.io")
        assert checker.is_in_scope("https://trusted.io")

    def test_get_allowed_domains(self):
        """Test retrieving allowed domains."""
        checker = ScopeChecker(
            "https://example.com",
            additional_domains=["partner.io"]
        )
        domains = checker.get_allowed_domains()
        assert "example.com" in domains
        assert "partner.io" in domains

    def test_filter_urls(self):
        """Test filtering multiple URLs."""
        checker = ScopeChecker("https://example.com")

        urls = [
            "https://example.com/page1",
            "https://api.example.com/endpoint",
            "https://evil.com/attack",
            "ftp://example.com/file",
            "https://www.example.com",
        ]

        filtered = checker.filter_urls(urls)
        assert len(filtered) == 3
        assert all("example.com" in url for url in filtered)


class TestURLResolution:
    """Test URL resolution functionality."""

    @pytest.fixture
    def checker(self):
        return ScopeChecker("https://example.com/app")

    def test_absolute_url_unchanged(self, checker):
        """Test that absolute URLs are returned unchanged."""
        url = "https://example.com/page"
        assert checker.resolve_url(url) == url

    def test_relative_url_resolution(self, checker):
        """Test relative URL resolution."""
        relative = "/api/users"
        resolved = checker.resolve_url(relative)
        assert resolved == "https://example.com/api/users"

    def test_protocol_relative_url(self, checker):
        """Test protocol-relative URL resolution."""
        url = "//example.com/page"
        resolved = checker.resolve_url(url)
        assert resolved == "https://example.com/page"

    def test_relative_with_parent_path(self, checker):
        """Test relative URL with parent directory navigation."""
        relative = "../other/page"
        current = "https://example.com/app/section/page"
        resolved = checker.resolve_url(relative, current)
        assert "/other/page" in resolved

    def test_filter_urls_with_relative_paths(self):
        """Test filtering URLs with relative paths."""
        checker = ScopeChecker("https://example.com")

        urls = [
            "/page1",
            "/api/endpoint",
            "../../../../../../etc/passwd",
            "https://evil.com",
            "/admin",
        ]

        filtered = checker.filter_urls(urls, "https://example.com/current/page")
        assert len(filtered) == 3
        assert all("example.com" in url for url in filtered)


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def checker(self):
        return ScopeChecker("https://example.com")

    def test_empty_url(self, checker):
        """Test handling of empty URLs."""
        assert not checker.is_in_scope("")

    def test_malformed_url(self, checker):
        """Test handling of malformed URLs."""
        assert not checker.is_in_scope("not a url")
        assert not checker.is_in_scope("http://")

    def test_international_domain(self):
        """Test international domain names."""
        checker = ScopeChecker("https://münchen.de")
        # The behavior depends on URL parsing library
        result = checker.is_in_scope("https://münchen.de/page")
        # Just ensure no exception is raised
        assert isinstance(result, bool)

    def test_port_numbers(self, checker):
        """Test URLs with port numbers."""
        assert checker.is_in_scope("https://example.com:8080/page")
        assert checker.is_in_scope("https://api.example.com:443")

    def test_query_strings_and_fragments(self, checker):
        """Test URLs with query strings and fragments."""
        assert checker.is_in_scope("https://example.com/page?id=123&name=test")
        assert checker.is_in_scope("https://example.com/page#section")
        assert checker.is_in_scope("https://example.com/page?q=1#hash")
