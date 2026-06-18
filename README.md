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
git clone https://github.com/mihirkalyan/Web-Vul-Scanner.git
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
