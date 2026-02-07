"""
Crawl Orchestrator Module

Main coordinator for the auto-crawling system.
Manages browser pool, crawl queue, link extraction, and prioritization.

Features:
- Multi-URL seed support
- Parallel browser contexts
- Automatic link discovery and following
- Business flow detection
- Integration with mitmproxy for traffic capture
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set, Dict, Any
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page

from link_extractor import LinkExtractor, Link as ExtractedLink, LinkPriority
from crawl_queue import CrawlQueue, CrawlTask, CrawlStatus
from link_prioritizer import HybridLinkPrioritizer, Link as PrioritizerLink, CrawlResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class CrawlConfig:
    """Configuration for crawl orchestrator"""
    # Seed URLs
    seed_urls: List[str] = field(default_factory=list)

    # Scope
    allowed_domains: Set[str] = field(default_factory=set)
    excluded_paths: List[str] = field(default_factory=list)

    # Limits
    max_depth: int = 3
    max_urls: int = 1000
    max_concurrent_browsers: int = 3
    request_delay_ms: int = 500
    page_timeout_ms: int = 60000

    # Proxy configuration (mitmproxy)
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8085

    # Browser options
    headless: bool = True
    ignore_https_errors: bool = True

    # Features
    extract_js_endpoints: bool = True
    detect_business_flows: bool = True
    save_screenshots: bool = False
    screenshot_dir: str = "./screenshots"

    # Q-learning model
    model_path: Optional[str] = None
    save_model_on_exit: bool = True


@dataclass
class CrawlStats:
    """Statistics for crawl session"""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    pages_crawled: int = 0
    pages_failed: int = 0
    links_discovered: int = 0
    links_followed: int = 0
    forms_detected: int = 0
    api_endpoints_found: int = 0
    admin_pages_found: int = 0
    errors: List[str] = field(default_factory=list)

    def duration_seconds(self) -> float:
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    def pages_per_minute(self) -> float:
        duration = self.duration_seconds()
        if duration > 0:
            return (self.pages_crawled / duration) * 60
        return 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration_seconds(),
            'pages_crawled': self.pages_crawled,
            'pages_failed': self.pages_failed,
            'links_discovered': self.links_discovered,
            'links_followed': self.links_followed,
            'forms_detected': self.forms_detected,
            'api_endpoints_found': self.api_endpoints_found,
            'admin_pages_found': self.admin_pages_found,
            'pages_per_minute': self.pages_per_minute(),
            'errors_count': len(self.errors),
        }


class CrawlOrchestrator:
    """
    Main orchestrator for automated crawling.

    Coordinates:
    - Browser pool management
    - URL queue and prioritization
    - Link extraction and discovery
    - Business flow detection
    - Traffic capture via mitmproxy
    """

    def __init__(self, config: CrawlConfig):
        """
        Initialize the crawl orchestrator.

        Args:
            config: Crawl configuration
        """
        self.config = config
        self.stats = CrawlStats()

        # Initialize components
        self.queue = CrawlQueue(
            max_depth=config.max_depth,
            max_urls=config.max_urls,
            allowed_domains=config.allowed_domains
        )

        self.link_extractor = LinkExtractor(
            allowed_domains=config.allowed_domains
        )

        self.prioritizer = HybridLinkPrioritizer(
            allowed_domains=config.allowed_domains
        )

        # Load existing model if available
        if config.model_path:
            try:
                self.prioritizer.load_model(config.model_path)
                logger.info(f"Loaded Q-learning model from {config.model_path}")
            except FileNotFoundError:
                logger.info("No existing model found, starting fresh")

        # Browser and context management
        self._browser: Optional[Browser] = None
        self._active_contexts: List[BrowserContext] = []
        self._semaphore: Optional[asyncio.Semaphore] = None

        # Shutdown flag
        self._shutdown = False

    async def start(self) -> CrawlStats:
        """
        Start the crawling process.

        Returns:
            CrawlStats with session statistics
        """
        logger.info("Starting crawl orchestrator")
        self.stats = CrawlStats()

        # Add seed URLs to queue
        for url in self.config.seed_urls:
            self.queue.add_url(url, priority=1, depth=0)
            logger.info(f"Added seed URL: {url}")

        # Initialize browser pool
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_browsers)

        async with async_playwright() as playwright:
            # Launch browser
            self._browser = await playwright.chromium.launch(
                headless=self.config.headless
            )

            logger.info(f"Browser launched (headless={self.config.headless})")

            # Process queue
            await self._process_queue()

            # Cleanup
            await self._browser.close()

        # Finalize stats
        self.stats.end_time = datetime.now()

        # Save model if configured
        if self.config.save_model_on_exit and self.config.model_path:
            self.prioritizer.save_model(self.config.model_path)
            logger.info(f"Saved Q-learning model to {self.config.model_path}")

        logger.info(f"Crawl completed: {self.stats.to_dict()}")
        return self.stats

    async def stop(self) -> None:
        """Signal graceful shutdown."""
        logger.info("Stopping crawl orchestrator")
        self._shutdown = True

    async def _process_queue(self) -> None:
        """Process URLs from the queue using parallel workers."""
        tasks = []

        while not self._shutdown:
            # Check if queue is empty and no tasks running
            if self.queue.is_empty() and not tasks:
                logger.info("Queue empty, no pending tasks - crawl complete")
                break

            # Get next task from queue
            crawl_task = self.queue.get_next()

            if crawl_task:
                # Create worker task
                task = asyncio.create_task(
                    self._crawl_url(crawl_task)
                )
                tasks.append(task)

            # Clean up completed tasks
            done_tasks = [t for t in tasks if t.done()]
            for t in done_tasks:
                tasks.remove(t)
                # Check for exceptions
                try:
                    t.result()
                except Exception as e:
                    logger.error(f"Worker task error: {e}")
                    self.stats.errors.append(str(e))

            # If we have max concurrent tasks, wait for one to complete
            if len(tasks) >= self.config.max_concurrent_browsers:
                done, _ = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_COMPLETED
                )
                for t in done:
                    tasks.remove(t)

            # Small delay to prevent tight loop
            await asyncio.sleep(0.1)

        # Wait for remaining tasks
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _crawl_url(self, task: CrawlTask) -> None:
        """
        Crawl a single URL.

        Args:
            task: CrawlTask to process
        """
        async with self._semaphore:
            context = None
            page = None

            try:
                # Create browser context with proxy
                context = await self._browser.new_context(
                    proxy={
                        "server": f"http://{self.config.proxy_host}:{self.config.proxy_port}"
                    },
                    ignore_https_errors=self.config.ignore_https_errors
                )

                # Create page
                page = await context.new_page()
                page.set_default_timeout(self.config.page_timeout_ms)

                logger.info(f"Crawling [{task.priority}] depth={task.depth}: {task.url} (timeout={self.config.page_timeout_ms}ms)")

                # Navigate to URL
                start_time = time.time()
                response = await page.goto(task.url, wait_until="load", timeout=self.config.page_timeout_ms)
                response_time = (time.time() - start_time) * 1000

                if not response:
                    raise Exception("No response received")

                status_code = response.status
                content_type = response.headers.get('content-type', '')

                # Wait for dynamic content
                await page.wait_for_load_state('networkidle')

                # Get page content
                html = await page.content()

                # Extract links
                extracted_links = self.link_extractor.extract_from_html(html, task.url)
                self.stats.links_discovered += len(extracted_links)

                # Analyze page for business flows
                crawl_result = await self._analyze_page(page, html, status_code, content_type, response_time)
                crawl_result.discovered_links = len(extracted_links)

                # Update prioritizer with result
                prioritizer_link = PrioritizerLink(url=task.url)
                self.prioritizer.update_from_result(prioritizer_link, crawl_result)

                # Add discovered links to queue
                for link in extracted_links:
                    if self._should_follow(link, task.depth):
                        # Score the link
                        p_link = PrioritizerLink(
                            url=link.url,
                            anchor_text=link.anchor_text,
                            context=link.context,
                            source_url=task.url
                        )
                        score = self.prioritizer.score_link(p_link, html)
                        priority = self.prioritizer.get_priority_bucket(score)

                        # Add to queue
                        if self.queue.add_url(
                            link.url,
                            priority=priority,
                            depth=task.depth + 1,
                            discovered_from=task.url
                        ):
                            self.stats.links_followed += 1

                # Save screenshot if configured
                if self.config.save_screenshots:
                    await self._save_screenshot(page, task.url)

                # Mark task completed
                self.queue.mark_completed(task)
                self.stats.pages_crawled += 1

                # Request delay
                await asyncio.sleep(self.config.request_delay_ms / 1000)

            except Exception as e:
                logger.error(f"Error crawling {task.url}: {e}")
                self.queue.mark_failed(task, str(e))
                self.stats.pages_failed += 1
                self.stats.errors.append(f"{task.url}: {str(e)}")

            finally:
                if page:
                    await page.close()
                if context:
                    await context.close()

    async def _analyze_page(
        self,
        page: Page,
        html: str,
        status_code: int,
        content_type: str,
        response_time: float
    ) -> CrawlResult:
        """
        Analyze page for security-relevant features.

        Returns:
            CrawlResult with analysis results
        """
        url = page.url

        result = CrawlResult(
            url=url,
            status_code=status_code,
            content_type=content_type,
            response_time_ms=response_time
        )

        html_lower = html.lower()

        # Check for forms
        forms = await page.locator('form').count()
        if forms > 0:
            result.has_form = True
            self.stats.forms_detected += forms

        # Check for authentication indicators
        auth_indicators = [
            'type="password"',
            'name="password"',
            'login', 'signin', 'sign in',
            'authenticate', 'credential'
        ]
        if any(indicator in html_lower for indicator in auth_indicators):
            result.has_authentication = True

        # Check for admin indicators
        admin_indicators = [
            '/admin', 'dashboard', 'console',
            'management', 'control panel'
        ]
        if any(indicator in html_lower for indicator in admin_indicators):
            result.has_admin_indicator = True
            self.stats.admin_pages_found += 1

        # Check for API endpoints
        api_indicators = [
            '/api/', '/v1/', '/v2/', '/graphql',
            'application/json', 'swagger', 'openapi'
        ]
        if any(indicator in html_lower or indicator in url.lower() for indicator in api_indicators):
            result.has_api_endpoint = True
            self.stats.api_endpoints_found += 1

        # Check for static content
        static_types = ['text/css', 'application/javascript', 'image/', 'font/']
        if any(st in content_type for st in static_types):
            result.is_static_content = True

        return result

    def _should_follow(self, link: ExtractedLink, current_depth: int) -> bool:
        """
        Determine if a link should be followed.

        Args:
            link: Extracted link
            current_depth: Current crawl depth

        Returns:
            True if link should be added to queue
        """
        # Check depth
        if current_depth >= self.config.max_depth:
            return False

        # Skip static assets
        if link.priority == LinkPriority.SKIP:
            return False

        # Skip external links
        if link.is_external:
            return False

        # Skip excluded paths
        path = urlparse(link.url).path.lower()
        for excluded in self.config.excluded_paths:
            if excluded in path:
                return False

        return True

    async def _save_screenshot(self, page: Page, url: str) -> None:
        """Save screenshot of current page."""
        try:
            # Generate filename from URL
            parsed = urlparse(url)
            filename = f"{parsed.netloc}_{parsed.path.replace('/', '_')}.png"
            filepath = f"{self.config.screenshot_dir}/{filename}"

            await page.screenshot(path=filepath, full_page=True)
            logger.debug(f"Saved screenshot: {filepath}")
        except Exception as e:
            logger.warning(f"Failed to save screenshot: {e}")


async def run_crawl(
    seed_urls: List[str],
    allowed_domains: Set[str],
    max_depth: int = 3,
    max_urls: int = 1000,
    proxy_port: int = 8085
) -> CrawlStats:
    """
    Convenience function to run a crawl.

    Args:
        seed_urls: Starting URLs
        allowed_domains: Domains to stay within
        max_depth: Maximum crawl depth
        max_urls: Maximum URLs to crawl
        proxy_port: mitmproxy port

    Returns:
        CrawlStats from the session
    """
    config = CrawlConfig(
        seed_urls=seed_urls,
        allowed_domains=allowed_domains,
        max_depth=max_depth,
        max_urls=max_urls,
        proxy_port=proxy_port
    )

    orchestrator = CrawlOrchestrator(config)
    return await orchestrator.start()


# CLI Entry point
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Crawl Orchestrator")
    parser.add_argument("url", help="Seed URL to start crawling")
    parser.add_argument("--depth", type=int, default=3, help="Maximum crawl depth")
    parser.add_argument("--max-urls", type=int, default=1000, help="Maximum URLs to crawl")
    parser.add_argument("--proxy-port", type=int, default=8085, help="mitmproxy port")
    parser.add_argument("--headless", action="store_true", default=True, help="Run headless")
    parser.add_argument("--no-headless", dest="headless", action="store_false", help="Show browser")
    parser.add_argument("--delay", type=int, default=500, help="Delay between requests (ms)")
    parser.add_argument("--model", type=str, help="Path to Q-learning model file")

    args = parser.parse_args()

    # Extract domain from seed URL
    parsed = urlparse(args.url)
    domain = parsed.netloc

    config = CrawlConfig(
        seed_urls=[args.url],
        allowed_domains={domain, f"*.{domain}"},
        max_depth=args.depth,
        max_urls=args.max_urls,
        proxy_port=args.proxy_port,
        headless=args.headless,
        request_delay_ms=args.delay,
        model_path=args.model
    )

    async def main():
        orchestrator = CrawlOrchestrator(config)
        stats = await orchestrator.start()
        print("\nCrawl Statistics:")
        for key, value in stats.to_dict().items():
            print(f"  {key}: {value}")

    asyncio.run(main())
