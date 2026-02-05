"""
Scope Checker - Validates URLs against allowed domain scope
"""

import re
from typing import List, Set
from urllib.parse import urlparse, urljoin


class ScopeChecker:
    """
    Validates discovered URLs to ensure they match the target scope.
    Prevents scanning of external domains and non-whitelisted resources.
    """

    def __init__(self, base_url: str, additional_domains: List[str] = None):
        """
        Initialize ScopeChecker with base URL and optional additional allowed domains.

        Args:
            base_url: The primary target URL (e.g., https://example.com)
            additional_domains: Optional list of additional allowed domains
        """
        self.base_url = base_url
        self.base_domain = self._extract_domain(base_url)
        self.allowed_domains: Set[str] = {self.base_domain}

        if additional_domains:
            self.allowed_domains.update(additional_domains)

        # Compile regex for efficient domain matching
        self._compile_domain_patterns()

    def _extract_domain(self, url: str) -> str:
        """
        Extract domain from URL.

        Args:
            url: Full URL string

        Returns:
            Domain without protocol (e.g., example.com)
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove www. prefix for consistent comparison
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    def _compile_domain_patterns(self):
        """Compile regex patterns for each allowed domain for efficient matching."""
        self.domain_patterns = []
        for domain in self.allowed_domains:
            # Pattern allows subdomains while preventing parent domain hijacking
            # e.g., example.com matches *.example.com but not evil.com
            pattern = re.compile(
                rf"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)*{re.escape(domain)}$",
                re.IGNORECASE,
            )
            self.domain_patterns.append((domain, pattern))

    def is_in_scope(self, url: str) -> bool:
        """
        Check if a URL is within the allowed scope.

        Args:
            url: URL to validate

        Returns:
            True if URL is in scope, False otherwise
        """
        try:
            parsed = urlparse(url)

            # Skip non-http(s) protocols
            if parsed.scheme not in ("http", "https"):
                return False

            # Extract domain and remove www. prefix
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]

            # Check against compiled patterns
            for allowed_domain, pattern in self.domain_patterns:
                if pattern.match(domain):
                    return True

            return False

        except Exception:
            return False

    def resolve_url(self, relative_url: str, current_page_url: str = None) -> str:
        """
        Resolve a relative URL to an absolute URL.

        Args:
            relative_url: Relative or absolute URL
            current_page_url: Current page URL for resolving relative links

        Returns:
            Absolute URL string
        """
        if not current_page_url:
            current_page_url = self.base_url

        # Handle absolute URLs
        if relative_url.startswith(("http://", "https://")):
            return relative_url

        # Handle protocol-relative URLs
        if relative_url.startswith("//"):
            parsed = urlparse(current_page_url)
            return f"{parsed.scheme}:{relative_url}"

        # Resolve relative URLs
        return urljoin(current_page_url, relative_url)

    def filter_urls(self, urls: List[str], current_page_url: str = None) -> List[str]:
        """
        Filter a list of URLs to only include those in scope.

        Args:
            urls: List of URLs to filter
            current_page_url: Current page URL for resolving relative links

        Returns:
            List of in-scope absolute URLs
        """
        filtered = []
        for url in urls:
            try:
                absolute_url = self.resolve_url(url, current_page_url)
                if self.is_in_scope(absolute_url):
                    filtered.append(absolute_url)
            except Exception:
                # Skip malformed URLs
                continue
        return filtered

    def add_allowed_domain(self, domain: str):
        """
        Add an additional allowed domain to the scope.

        Args:
            domain: Domain to add (e.g., subdomain.example.com)
        """
        domain = domain.lower()
        if domain.startswith("www."):
            domain = domain[4:]

        if domain not in self.allowed_domains:
            self.allowed_domains.add(domain)
            self._compile_domain_patterns()

    def get_allowed_domains(self) -> Set[str]:
        """
        Get all allowed domains.

        Returns:
            Set of allowed domains
        """
        return self.allowed_domains.copy()
