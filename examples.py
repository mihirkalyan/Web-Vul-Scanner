"""
Example usage of the Web Vulnerability Scanner Orchestrator Engine

This demonstrates how to:
1. Create an orchestrator engine
2. Submit URLs for scanning
3. Implement a custom scan handler
4. Monitor scan progress and results
"""

import asyncio
import logging
from src.orchestrator import OrchestratorEngine, ScanPriority
from src.scope_checker import ScopeChecker

# Setup logging to see engine activity
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


# Example 1: Basic Scanning
async def example_basic_scanning():
    """Demonstrate basic URL submission and scanning."""
    print("\n" + "="*60)
    print("Example 1: Basic Scanning")
    print("="*60)

    # Create orchestrator engine
    engine = OrchestratorEngine(
        base_url="https://example.com",
        max_concurrent_tasks=10,
        max_retries=3,
        request_timeout=30.0
    )

    # Define a simple scan handler
    async def simple_scanner(url: str) -> dict:
        """Mock scanner - simulates vulnerability scanning."""
        await asyncio.sleep(0.1)  # Simulate network request
        return {
            "url": url,
            "vulnerabilities": ["XSS", "CSRF"],
            "status": "completed"
        }

    # Submit URLs
    await engine.submit_task("https://example.com/")
    await engine.submit_task("https://example.com/admin")
    await engine.submit_task("https://api.example.com/users")

    # Run scan
    results = await engine.run_scan(simple_scanner)

    # Display results
    for task_id, result in results.items():
        print(f"✓ {result.url}: {result.status}")


# Example 2: Scope Management
async def example_scope_management():
    """Demonstrate scope validation and domain management."""
    print("\n" + "="*60)
    print("Example 2: Scope Management")
    print("="*60)

    # Create scope checker
    checker = ScopeChecker(
        "https://example.com",
        additional_domains=["api.example.com"]
    )

    # Test various URLs
    test_urls = [
        ("https://example.com/page", True),
        ("https://api.example.com/endpoint", True),
        ("https://admin.example.com/dash", True),
        ("https://evil.com/attack", False),
        ("ftp://example.com/file", False),
        ("https://example.com.evil.com", False),
    ]

    print("\nScope Validation Results:")
    for url, expected in test_urls:
        result = checker.is_in_scope(url)
        status = "✓" if result == expected else "✗"
        in_scope = "IN SCOPE" if result else "OUT OF SCOPE"
        print(f"{status} {url}: {in_scope}")

    # Filter URLs
    print("\nFiltering Multiple URLs:")
    urls = [
        "https://example.com/home",
        "https://malicious.com/attack",
        "https://api.example.com/users",
        "javascript:alert('xss')",
    ]
    filtered = checker.filter_urls(urls)
    print(f"Input: {len(urls)} URLs")
    print(f"Output: {len(filtered)} in-scope URLs")
    for url in filtered:
        print(f"  ✓ {url}")


# Example 3: Priority-Based Scanning
async def example_priority_scanning():
    """Demonstrate task prioritization."""
    print("\n" + "="*60)
    print("Example 3: Priority-Based Scanning")
    print("="*60)

    engine = OrchestratorEngine(
        base_url="https://example.com",
        max_concurrent_tasks=2
    )

    execution_log = []

    async def tracking_scanner(url: str) -> dict:
        """Scanner that tracks execution order."""
        execution_log.append(url)
        await asyncio.sleep(0.2)  # Simulate work
        return {"url": url, "scanned": True}

    # Submit tasks with different priorities
    print("\nSubmitting tasks with different priorities:")
    
    await engine.submit_task(
        "https://example.com/low-priority",
        priority=ScanPriority.LOW
    )
    print("  • LOW: /low-priority")
    
    await engine.submit_task(
        "https://example.com/high-priority",
        priority=ScanPriority.HIGH
    )
    print("  • HIGH: /high-priority")
    
    await engine.submit_task(
        "https://example.com/medium-priority",
        priority=ScanPriority.MEDIUM
    )
    print("  • MEDIUM: /medium-priority")

    # Run scan and show execution order
    print("\nExecution order (HIGH → MEDIUM → LOW):")
    await engine.run_scan(tracking_scanner)
    for i, url in enumerate(execution_log, 1):
        print(f"  {i}. {url}")


# Example 4: Error Handling and Retries
async def example_error_handling():
    """Demonstrate error handling and retry logic."""
    print("\n" + "="*60)
    print("Example 4: Error Handling and Retries")
    print("="*60)

    engine = OrchestratorEngine(
        base_url="https://example.com",
        max_retries=3,
        request_timeout=5.0
    )

    attempt_tracker = {}

    async def unreliable_scanner(url: str) -> dict:
        """Scanner that fails initially then succeeds."""
        attempt_tracker[url] = attempt_tracker.get(url, 0) + 1
        
        if attempt_tracker[url] < 3:
            raise Exception(f"Attempt {attempt_tracker[url]}: Network timeout")
        
        return {"url": url, "scanned": True}

    # Submit task
    await engine.submit_task("https://example.com/unreliable")

    # Run scan
    results = await engine.run_scan(unreliable_scanner)

    # Show retry information
    print("\nRetry Behavior:")
    result = list(results.values())[0]
    url = result.url
    attempts = attempt_tracker[url]
    print(f"URL: {url}")
    print(f"Attempts before success: {attempts}")
    print(f"Final status: {result.status}")
    print(f"Elapsed time: {result.elapsed_time:.2f}s")


# Example 5: Real-world Scenario
async def example_real_world_scenario():
    """Simulate a real vulnerability scanning scenario."""
    print("\n" + "="*60)
    print("Example 5: Real-World Scenario")
    print("="*60)

    engine = OrchestratorEngine(
        base_url="https://example.com",
        max_concurrent_tasks=5,
        max_retries=2,
        additional_domains=["api.example.com", "cdn.example.com"]
    )

    print("\nScanning configuration:")
    print(f"  Target: https://example.com")
    print(f"  Max concurrent: 5")
    print(f"  Max retries: 2")
    print(f"  Allowed domains: {engine.scope_checker.get_allowed_domains()}")

    # Mock URLs to scan (mix of in-scope and out-of-scope)
    urls_to_scan = [
        "https://example.com/",
        "https://example.com/products",
        "https://example.com/users",
        "https://api.example.com/v1/data",
        "https://cdn.example.com/assets",
        "https://external.com/attack",  # Out of scope
        "https://api.example.com/admin",
    ]

    async def vulnerability_scanner(url: str) -> dict:
        """Simulate real vulnerability scanner."""
        await asyncio.sleep(0.2)  # Network latency
        return {
            "url": url,
            "vulnerabilities": ["SQL Injection"],
            "scan_date": "2024-01-15"
        }

    # Submit URLs
    print("\nSubmitting URLs for scanning...")
    submitted = await engine.submit_urls(urls_to_scan)
    print(f"  Accepted: {len(submitted)}/{len(urls_to_scan)}")

    # Run scan
    print("\nRunning scan...")
    results = await engine.run_scan(vulnerability_scanner)

    # Summary
    stats = engine.get_stats()
    print("\nScan Summary:")
    print(f"  Total tasks: {stats['total_tasks']}")
    print(f"  Completed: {stats['completed']}")
    print(f"  Failed: {stats['failed']}")
    print(f"  Max concurrent used: {stats['max_concurrent']}")


# Example 6: Dynamic Domain Addition
async def example_dynamic_domain_addition():
    """Demonstrate adding domains dynamically during operation."""
    print("\n" + "="*60)
    print("Example 6: Dynamic Domain Addition")
    print("="*60)

    engine = OrchestratorEngine(
        base_url="https://example.com"
    )

    async def dummy_scanner(url: str) -> dict:
        await asyncio.sleep(0.05)
        return {"url": url, "scanned": True}

    # Initial scan
    print("\nPhase 1: Initial scope")
    print(f"  Allowed domains: {engine.scope_checker.get_allowed_domains()}")
    
    result = await engine.submit_task("https://trusted.partner.com")
    print(f"  Submit https://trusted.partner.com: {'✓ Accepted' if result else '✗ Rejected'}")

    # Expand scope
    print("\nPhase 2: Expanding scope")
    engine.add_allowed_domain("trusted.partner.com")
    print(f"  Added domain: trusted.partner.com")
    print(f"  Allowed domains: {engine.scope_checker.get_allowed_domains()}")
    
    result = await engine.submit_task("https://trusted.partner.com/api")
    print(f"  Submit https://trusted.partner.com/api: {'✓ Accepted' if result else '✗ Rejected'}")

    # Run scan on new domain
    if result:
        await engine.run_scan(dummy_scanner)
        print("\n  Scan completed successfully")


async def main():
    """Run all examples."""
    print("\n" + "█"*60)
    print("█" + " "*58 + "█")
    print("█" + "  Web Vulnerability Scanner - Orchestrator Examples".center(58) + "█")
    print("█" + " "*58 + "█")
    print("█"*60)

    try:
        await example_basic_scanning()
        await example_scope_management()
        await example_priority_scanning()
        await example_error_handling()
        await example_real_world_scenario()
        await example_dynamic_domain_addition()

        print("\n" + "="*60)
        print("All examples completed successfully! ✓")
        print("="*60 + "\n")

    except Exception as e:
        print(f"\n✗ Error during examples: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
