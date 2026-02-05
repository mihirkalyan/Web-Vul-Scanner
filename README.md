# Web Vulnerability Scanner - Orchestrator Engine

A high-performance, async-based orchestrator engine for vulnerability scanning with intelligent scope management and concurrency control.

## Features

### 🚀 Async Orchestration
- **Concurrent Task Management**: Control up to 10 concurrent scans simultaneously using `asyncio.Semaphore`
- **Task Prioritization**: Support for HIGH, MEDIUM, and LOW priority scans
- **Retry Logic**: Automatic retry with exponential backoff for failed tasks
- **Timeout Handling**: Configurable per-task timeouts with graceful failure handling

### 🎯 Intelligent Scope Management
- **Domain Validation**: Regex-based scope checker ensures all URLs match the target domain
- **Subdomain Support**: Automatically includes subdomains in scan scope
- **Scope Expansion**: Dynamically add additional allowed domains during scanning
- **Protocol Security**: Only HTTP/HTTPS protocols allowed (blocks FTP, file://, etc.)

### 📊 Comprehensive Monitoring
- **Real-time Statistics**: Track pending, running, completed, and failed tasks
- **Detailed Logging**: Structured logging for audit trails and debugging
- **Result Aggregation**: Separate tracking of successful and failed scans

---

## Architecture

### System Components

```
┌──────────────────────────────────────────┐
│     Web Crawler (Discovery)              │
│  • URL discovery from HTML                │
│  • Form extraction                        │
│  • Visited tracking (memory/SQLite)      │
└────────────────┬─────────────────────────┘
                 │
         ┌───────▼──────────┐
         │ LinkExtractor    │
         │ Plugin (RESPONSE │
         │ _ANALYZER)       │
         └───────┬──────────┘
                 │
         ┌───────▼──────────────────┐
         │  OrchestratorEngine      │
         │ • Task management        │
         │ • Concurrency control    │
         │ • Scope validation       │
         └───────┬──────────────────┘
                 │
    ┌────────────┴────────────┐
    │                         │
┌───▼──────┐           ┌────▼──────────┐
│ScopeCheck│           │Task Handler   │
│(URL valid│           │(Scan plugins) │
│ation)    │           └────┬──────────┘
└──────────┘                │
                 ┌──────────┴──────────┐
                 │                     │
            ┌────▼────┐          ┌────▼──────┐
            │ScanReq  │          │ScanResp   │
            │(mutable)│          │(immutable)│
            └────┬────┘          └───────────┘
                 │
            ┌────▼──────────────┐
            │Plugin System      │
            │• REQUEST_MODIFIER │
            │• RESPONSE_ANALYZER│
            │• DETECTORS        │
            │• PAYLOAD_GENERATOR│
            └───────────────────┘
```

### OrchestratorEngine
Main orchestrator class responsible for:
- Task submission and validation
- Concurrency control via semaphore
- Task execution with retry logic
- Result collection and statistics
- Crawler integration for automated URL discovery

### WebCrawler
Async web crawler for discovering URLs and forms:
- **Link Extraction**: Parse HTML for `<a>` tags and resolve relative URLs
- **Form Discovery**: Extract `<form>` elements with input field analysis
- **State Management**: Track visited URLs using memory set or SQLite database
- **Scope Filtering**: Respect domain boundaries while discovering URLs
- **Depth & Limits**: Configurable crawl depth and maximum URL/domain limits
- **Rate Limiting**: Adjustable crawl delay between requests
- **Statistics**: Comprehensive tracking of discovery metrics

### LinkExtractorPlugin
Response analyzer plugin providing:
- HTML parsing with BeautifulSoup
- Automatic link and form extraction
- Scope-aware URL filtering
- Form field enumeration for testing

### ScopeChecker
URL validation component that:
- Validates domain scope using compiled regex patterns
- Resolves relative URLs to absolute forms
- Filters URL lists to only include in-scope targets
- Supports multiple allowed domains

### Plugin System
Extensible plugin architecture with types:
- **REQUEST_MODIFIER**: Modify requests before sending
- **RESPONSE_ANALYZER**: Analyze responses (like LinkExtractor)
- **DETECTOR**: Detect vulnerabilities
- **PAYLOAD_GENERATOR**: Generate test payloads

### Data Classes
- **ScanTask**: Represents a single scan task with priority and metadata
- **ScanResult**: Contains execution results, errors, and timing information
- **ScanRequest**: HTTP request with header/cookie/parameter manipulation
- **ScanResponse**: HTTP response with parsing and analysis utilities
- **CrawlStatistics**: Crawler metrics and performance data

---

## Installation

```bash
# Clone repository
git clone <repository-url>
cd Web-Vul-Scanner

# Install dependencies
pip install -r requirements.txt
```

## Requirements

```
pytest>=7.0.0
pytest-asyncio>=0.20.0
```

---

## Usage Examples

### Basic Setup

```python
import asyncio
from src.orchestrator import OrchestratorEngine, ScanPriority

async def example_handler(url: str):
    """Example scan handler - replace with actual scanner logic"""
    # Perform vulnerability checks here
    return {
        "url": url,
        "vulnerabilities": [],
        "status": "scanned"
    }

async def main():
    # Create engine with base URL
    engine = OrchestratorEngine(
        base_url="https://example.com",
        max_concurrent_tasks=10,
        max_retries=3,
        request_timeout=30.0
    )
    
    # Submit URLs for scanning
    await engine.submit_task("https://example.com/page1")
    await engine.submit_urls([
        "https://example.com/page2",
        "https://api.example.com/endpoint"
    ])
    
    # Run scan with handler
    results = await engine.run_scan(example_handler)
    
    # Print results
    for task_id, result in results.items():
        print(f"Task {task_id}: {result.status}")

asyncio.run(main())
```

### Advanced Configuration

```python
from src.orchestrator import OrchestratorEngine, ScanPriority

# Create engine with additional domains
engine = OrchestratorEngine(
    base_url="https://main.example.com",
    max_concurrent_tasks=5,  # Limit to 5 concurrent tasks
    max_retries=2,
    request_timeout=20.0,
    additional_domains=["api.example.com", "cdn.example.com"]
)

# Submit high-priority tasks
await engine.submit_task(
    "https://example.com/critical",
    priority=ScanPriority.HIGH
)

# Add new domain during scan
engine.add_allowed_domain("partner.example.com")

# Get statistics
stats = engine.get_stats()
print(f"Pending: {stats['pending']}")
print(f"Allowed Domains: {stats['allowed_domains']}")
```

### Scope Validation

```python
from src.scope_checker import ScopeChecker

# Create scope checker
checker = ScopeChecker("https://example.com")

# Check single URL
if checker.is_in_scope("https://api.example.com/endpoint"):
    print("In scope - proceed with scan")

# Filter multiple URLs
urls = [
    "https://example.com/page",
    "https://evil.com/attack",
    "/relative/path"
]

filtered = checker.filter_urls(urls, "https://example.com/current")
print(f"Filtered: {filtered}")

# Add allowed domain
checker.add_allowed_domain("trusted.partner.com")
```

### Crawler - Automatic URL Discovery

```python
import asyncio
from src.crawler import WebCrawler
from src.orchestrator import OrchestratorEngine

async def crawl_example():
    """Discover URLs and forms from a target website"""
    
    # Create engine for scanning
    engine = OrchestratorEngine(
        base_url="https://example.com",
        max_concurrent_tasks=5
    )
    
    # Define HTTP request handler
    async def fetch_handler(url: str):
        """Fetch URL and return (status, html)"""
        # Replace with actual HTTP client (aiohttp, httpx, etc.)
        # For now, example stub
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as resp:
                html = await resp.text()
                return (resp.status, html)
    
    # Start crawler with automatic URL discovery
    crawl_results = await engine.start_crawl(
        start_urls=["https://example.com"],
        request_handler=fetch_handler,
        max_depth=3,           # Crawl up to 3 levels deep
        max_urls=500,          # Discover max 500 URLs
        max_urls_per_domain=50, # Max 50 URLs per domain
        crawl_delay_ms=100,    # 100ms delay between requests
        auto_submit_urls=True  # Auto-submit discovered URLs to scanner
    )
    
    print(f"Discovered URLs: {len(crawl_results['discovered_urls'])}")
    print(f"Discovered Forms: {len(crawl_results['discovered_forms'])}")
    print(f"Stats: {crawl_results['statistics']}")
    
    # Now run scan on discovered URLs
    async def scan_handler(url: str):
        """Example scan handler"""
        return {"url": url, "status": "scanned"}
    
    results = await engine.run_scan(scan_handler)
    return results

# Run crawler and scanner
asyncio.run(crawl_example())
```

### Using Crawler with Custom State Management

```python
from src.crawler import WebCrawler, MemoryURLTracker, SQLiteURLTracker
from src.scope_checker import ScopeChecker

async def crawl_with_sqlite():
    """Use SQLite for persistent URL tracking"""
    
    scope = ScopeChecker("https://example.com")
    
    # Create crawler with SQLite state backend
    crawler = WebCrawler(
        scope_checker=scope,
        start_urls=["https://example.com"],
        max_depth=2,
        state_backend="sqlite",
        db_path="./crawler_state.db"  # Persistent database
    )
    
    async def fetch_handler(url: str):
        # HTTP fetch implementation
        pass
    
    results = await crawler.start_crawl(fetch_handler)
    
    # Get discovered URLs
    discovered = await crawler.get_discovered_urls()
    forms = await crawler.get_discovered_forms()
    
    return {
        "urls": discovered,
        "forms": forms,
        "stats": crawler.get_statistics().to_dict()
    }

asyncio.run(crawl_with_sqlite())
```

### LinkExtractor Plugin Usage

```python
from src.plugins.link_extractor import LinkExtractorPlugin, FormDetectorPlugin
from src.models import ScanRequest, ScanResponse
from src.scope_checker import ScopeChecker

async def extract_links_from_response():
    """Use LinkExtractor plugin to find links and forms"""
    
    scope = ScopeChecker("https://example.com")
    
    # Create plugins
    link_extractor = LinkExtractorPlugin(scope_checker=scope)
    form_detector = FormDetectorPlugin()
    
    # Simulate a response
    request = ScanRequest(url="https://example.com")
    response = ScanResponse(
        status=200,
        body="""
        <html>
            <a href="/page1">Page 1</a>
            <a href="https://example.com/page2">Page 2</a>
            <form method="POST" action="/login">
                <input type="text" name="username" />
                <input type="password" name="password" />
            </form>
        </html>
        """,
        headers={"Content-Type": "text/html"}
    )
    
    # Execute plugins
    link_result = await link_extractor.execute(request, response)
    form_result = await form_detector.execute(request, response)
    
    print(f"Extracted links: {link_result.data['links']}")
    print(f"Forms detected: {form_result.data['total_forms']}")
    
    return {
        "links": link_result.data,
        "forms": form_result.data
    }

asyncio.run(extract_links_from_response())
```

---

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_orchestrator.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

### Test Coverage

- **test_scope_checker.py**: 30+ tests for domain validation, URL resolution, edge cases
- **test_orchestrator.py**: 25+ tests for concurrency, error handling, task lifecycle

---

## Key Components

### Concurrency Control
```python
# Semaphore limits concurrent tasks to max_concurrent_tasks
async with self.semaphore:
    result = await task_handler(url)
```

### Scope Validation
```python
# Regex pattern ensures subdomain matching without parent hijacking
pattern = re.compile(
    rf"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)*{re.escape(domain)}$",
    re.IGNORECASE,
)
```

### Retry with Exponential Backoff
```python
for retry_count in range(task.max_retries):
    try:
        result = await task_handler(url)
    except Exception:
        await asyncio.sleep(2 ** retry_count)  # 2s, 4s, 8s...
```

---

## Configuration Guide

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `base_url` | Required | Target domain for scanning |
| `max_concurrent_tasks` | 10 | Semaphore limit to prevent DoS |
| `max_retries` | 3 | Retry attempts for failed tasks |
| `request_timeout` | 30.0 | Timeout per request in seconds |
| `additional_domains` | None | Extra domains to include in scope |

---

## Error Handling

The engine gracefully handles:
- **Scope violations**: Out-of-scope URLs are rejected with warning log
- **Timeouts**: Tasks exceeding timeout are retried with exponential backoff
- **Failures**: Failed tasks tracked separately with error messages
- **Malformed URLs**: Invalid URLs are skipped with error logging

---

## Performance Considerations

1. **Semaphore Tuning**: Set `max_concurrent_tasks` based on target server capacity
   - Too high: May cause DoS or server rejection
   - Too low: Underutilizes scan capacity
   - Recommended: 5-10 for most targets

2. **Timeout Adjustment**: Consider target response time
   - Network latency
   - Processing time for complex pages
   - Default 30s suitable for most scenarios

3. **Retry Strategy**: Balance between reliability and duration
   - Max retries: 3 (default) is standard
   - Exponential backoff prevents hammering failed services

---

## Security Notes

- **Scope Enforcement**: Prevents accidental scanning of external domains
- **Protocol Filtering**: Only HTTP/HTTPS allowed, blocks dangerous schemes
- **Domain Validation**: Subdomain inclusion prevents parent domain hijacking
- **Audit Logging**: All scans logged for compliance and incident response

---

## Future Enhancements

- [ ] Distributed scanning across multiple nodes
- [ ] Machine learning for smart URL discovery
- [ ] WebSocket support for real-time result streaming
- [ ] Custom authentication handlers
- [ ] Proxy support for enterprise environments
- [ ] Rate limiting and adaptive throttling
- [ ] Persistent task queue for long-running scans

---

## License

MIT License - See LICENSE file for details

---

## Contributing

Contributions welcome! Please ensure:
- All tests pass: `pytest tests/`
- Code follows PEP 8: `black src/ tests/`
- Type hints included for all functions
- New features include test coverage
