#!/usr/bin/env python3
"""
Crawl CLI - Command-line interface for the Auto-Crawling System

Usage:
    python crawl_cli.py crawl <url> [options]
    python crawl_cli.py resume <session_id>
    python crawl_cli.py status [session_id]
    python crawl_cli.py export <session_id> [--format=json|csv|html]
"""

import argparse
import asyncio
import sys
import yaml
import logging
from pathlib import Path
from typing import Optional, Set
from urllib.parse import urlparse
from datetime import datetime

from crawl_orchestrator import CrawlOrchestrator, CrawlConfig, CrawlStats
from link_prioritizer import HybridLinkPrioritizer
from business_flow_detector import BusinessFlowDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(f"Config file not found: {config_path}, using defaults")
        return {}


def create_crawl_config(args, yaml_config: dict) -> CrawlConfig:
    """Create CrawlConfig from CLI args and YAML config."""
    # Extract domain from URL
    parsed = urlparse(args.url)
    domain = parsed.netloc

    # Merge allowed domains
    allowed_domains = set(yaml_config.get('scope', {}).get('allowed_domains', []))
    if args.domain:
        allowed_domains.update(args.domain)
    if not allowed_domains:
        allowed_domains = {domain, f"*.{domain}"}

    # Get excluded paths
    excluded_paths = yaml_config.get('scope', {}).get('excluded_paths', [])

    # Create config
    config = CrawlConfig(
        seed_urls=[args.url],
        allowed_domains=allowed_domains,
        excluded_paths=excluded_paths,
        max_depth=args.depth or yaml_config.get('crawl', {}).get('max_depth', 3),
        max_urls=args.max_urls or yaml_config.get('crawl', {}).get('max_urls', 1000),
        max_concurrent_browsers=args.concurrency or yaml_config.get('crawl', {}).get('concurrent_browsers', 3),
        request_delay_ms=args.delay or yaml_config.get('crawl', {}).get('request_delay_ms', 500),
        page_timeout_ms=yaml_config.get('crawl', {}).get('page_timeout_ms', 60000),
        proxy_host=yaml_config.get('proxy', {}).get('host', '127.0.0.1'),
        proxy_port=args.proxy_port or yaml_config.get('proxy', {}).get('port', 8085),
        headless=not args.no_headless,
        ignore_https_errors=True,
        extract_js_endpoints=True,
        detect_business_flows=not args.no_flows,
        save_screenshots=args.screenshots,
        screenshot_dir=yaml_config.get('output', {}).get('screenshot_dir', './screenshots'),
        model_path=args.model or yaml_config.get('q_learning', {}).get('model_path'),
        save_model_on_exit=yaml_config.get('q_learning', {}).get('save_on_exit', True)
    )

    return config


async def cmd_crawl(args) -> int:
    """Execute crawl command."""
    # Load config
    yaml_config = load_config(args.config)

    # Create crawl config
    config = create_crawl_config(args, yaml_config)

    print(f"\n{'='*60}")
    print("  CRAWL ORCHESTRATOR")
    print(f"{'='*60}")
    print(f"  Target URL: {args.url}")
    print(f"  Max Depth: {config.max_depth}")
    print(f"  Max URLs: {config.max_urls}")
    print(f"  Concurrency: {config.max_concurrent_browsers}")
    print(f"  Proxy: {config.proxy_host}:{config.proxy_port}")
    print(f"  Headless: {config.headless}")
    print(f"  Business Flows: {config.detect_business_flows}")
    print(f"{'='*60}\n")

    # Confirm if needed
    if args.confirm:
        response = input("Start crawl? [y/N]: ")
        if response.lower() != 'y':
            print("Crawl cancelled.")
            return 0

    # Create and run orchestrator
    orchestrator = CrawlOrchestrator(config)

    try:
        stats = await orchestrator.start()

        # Print results
        print(f"\n{'='*60}")
        print("  CRAWL RESULTS")
        print(f"{'='*60}")
        for key, value in stats.to_dict().items():
            print(f"  {key}: {value}")
        print(f"{'='*60}\n")

        return 0

    except KeyboardInterrupt:
        print("\nCrawl interrupted by user.")
        await orchestrator.stop()
        return 1
    except Exception as e:
        logger.error(f"Crawl failed: {e}")
        return 1


async def cmd_analyze(args) -> int:
    """Analyze a single URL for business flows."""
    import aiohttp
    from bs4 import BeautifulSoup

    print(f"Analyzing URL: {args.url}")

    async with aiohttp.ClientSession() as session:
        async with session.get(args.url) as response:
            html = await response.text()

    detector = BusinessFlowDetector()
    flows = detector.detect_flows(args.url, html)

    print(f"\nDetected {len(flows)} business flows:\n")

    for flow in flows:
        print(f"  [{flow.priority.name}] {flow.flow_type.value}")
        print(f"    Confidence: {flow.confidence:.2%}")
        print(f"    Indicators: {', '.join(flow.indicators[:3])}")
        print(f"    Suggested Tests: {len(flow.suggested_tests)}")

        if args.verbose:
            tests = detector.suggest_tests(flow)
            for test in tests[:3]:
                print(f"      - {test.name} [{test.risk_level}]")
        print()

    return 0


def cmd_status(args) -> int:
    """Show status of crawl sessions."""
    print("Session status not yet implemented.")
    print("Would query database for session stats.")
    return 0


def cmd_export(args) -> int:
    """Export crawl results."""
    print(f"Exporting session {args.session_id} to {args.format}")
    print("Export not yet implemented.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Crawl Orchestrator CLI - Auto-Crawling & Business Flow Discovery"
    )
    parser.add_argument(
        '--config', '-c',
        default='crawl_config.yaml',
        help='Configuration file path'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Crawl command
    crawl_parser = subparsers.add_parser('crawl', help='Start a new crawl')
    crawl_parser.add_argument('url', help='Seed URL to start crawling')
    crawl_parser.add_argument('--depth', '-d', type=int, help='Maximum crawl depth')
    crawl_parser.add_argument('--max-urls', '-m', type=int, help='Maximum URLs to crawl')
    crawl_parser.add_argument('--concurrency', type=int, help='Parallel browser instances')
    crawl_parser.add_argument('--delay', type=int, help='Request delay in ms')
    crawl_parser.add_argument('--proxy-port', '-p', type=int, help='mitmproxy port')
    crawl_parser.add_argument('--domain', action='append', help='Additional allowed domains')
    crawl_parser.add_argument('--no-headless', action='store_true', help='Show browser window')
    crawl_parser.add_argument('--no-flows', action='store_true', help='Disable business flow detection')
    crawl_parser.add_argument('--screenshots', action='store_true', help='Save page screenshots')
    crawl_parser.add_argument('--model', help='Q-learning model path')
    crawl_parser.add_argument('--confirm', action='store_true', help='Require confirmation before starting')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a URL for business flows')
    analyze_parser.add_argument('url', help='URL to analyze')

    # Status command
    status_parser = subparsers.add_parser('status', help='Show crawl session status')
    status_parser.add_argument('session_id', nargs='?', help='Session ID (optional)')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export crawl results')
    export_parser.add_argument('session_id', help='Session ID to export')
    export_parser.add_argument('--format', '-f', default='json', choices=['json', 'csv', 'html'])
    export_parser.add_argument('--output', '-o', help='Output file path')

    # Parse arguments
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Execute command
    if args.command == 'crawl':
        return asyncio.run(cmd_crawl(args))
    elif args.command == 'analyze':
        return asyncio.run(cmd_analyze(args))
    elif args.command == 'status':
        return cmd_status(args)
    elif args.command == 'export':
        return cmd_export(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
