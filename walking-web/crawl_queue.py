"""
Crawl Queue Module

Priority-based URL queue with deduplication, depth tracking, and scope filtering.
Supports persistent storage via PostgreSQL for resumable crawls.
"""

import hashlib
import heapq
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Set, List, Dict, Any
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode


class CrawlStatus(Enum):
    """Status of a crawl task"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(order=True)
class CrawlTask:
    """
    Represents a URL to be crawled with metadata.

    Ordering is based on priority (lower = higher priority).
    """
    priority: int
    url: str = field(compare=False)
    depth: int = field(compare=False, default=0)
    status: CrawlStatus = field(compare=False, default=CrawlStatus.PENDING)
    discovered_from: Optional[str] = field(compare=False, default=None)
    created_at: datetime = field(compare=False, default_factory=datetime.now)
    processed_at: Optional[datetime] = field(compare=False, default=None)

    # Additional metadata
    retry_count: int = field(compare=False, default=0)
    error_message: Optional[str] = field(compare=False, default=None)
    fingerprint: str = field(compare=False, default="")

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = self._generate_fingerprint()

    def _generate_fingerprint(self) -> str:
        """Generate a unique fingerprint for this URL"""
        # Normalize the URL for fingerprinting
        normalized = self._normalize_url(self.url)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for deduplication"""
        parsed = urlparse(url)

        # Lowercase scheme and host
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Remove default ports
        if ':80' in netloc and scheme == 'http':
            netloc = netloc.replace(':80', '')
        if ':443' in netloc and scheme == 'https':
            netloc = netloc.replace(':443', '')

        # Sort query parameters
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query_params.items()), doseq=True)

        # Remove trailing slash from path (unless it's root)
        path = parsed.path.rstrip('/') or '/'

        # Reconstruct URL
        normalized = urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            sorted_query,
            ''  # Remove fragment
        ))

        return normalized


class CrawlQueue:
    """
    Thread-safe priority queue for managing crawl URLs.

    Features:
    - Priority-based ordering (lower priority value = crawled first)
    - URL deduplication via fingerprinting
    - Depth tracking with configurable maximum
    - Domain scope filtering
    - Concurrent access support
    """

    def __init__(
        self,
        max_depth: int = 3,
        max_urls: int = 1000,
        allowed_domains: Optional[Set[str]] = None
    ):
        """
        Initialize the crawl queue.

        Args:
            max_depth: Maximum crawl depth (0 = only seed URLs)
            max_urls: Maximum URLs to queue
            allowed_domains: Set of domains to allow (supports wildcards)
        """
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.allowed_domains = allowed_domains or set()

        # Internal data structures
        self._heap: List[CrawlTask] = []
        self._fingerprints: Set[str] = set()
        self._processing: Dict[str, CrawlTask] = {}

        # Statistics
        self._stats = {
            'total_added': 0,
            'total_processed': 0,
            'total_skipped': 0,
            'total_failed': 0,
            'duplicates_rejected': 0,
            'depth_rejected': 0,
            'scope_rejected': 0,
        }

        # Thread safety
        self._lock = threading.RLock()

    def add_url(
        self,
        url: str,
        priority: int = 3,
        depth: int = 0,
        discovered_from: Optional[str] = None
    ) -> bool:
        """
        Add a URL to the crawl queue.

        Args:
            url: URL to add
            priority: Priority level (1 = highest, 5 = lowest)
            depth: Current crawl depth
            discovered_from: Parent URL that led to this URL

        Returns:
            True if URL was added, False if rejected
        """
        with self._lock:
            # Check queue size limit
            if len(self._heap) >= self.max_urls:
                return False

            # Check depth limit
            if depth > self.max_depth:
                self._stats['depth_rejected'] += 1
                return False

            # Check domain scope
            if not self._is_in_scope(url):
                self._stats['scope_rejected'] += 1
                return False

            # Create task
            task = CrawlTask(
                priority=priority,
                url=url,
                depth=depth,
                discovered_from=discovered_from
            )

            # Check for duplicate
            if task.fingerprint in self._fingerprints:
                self._stats['duplicates_rejected'] += 1
                return False

            # Add to queue
            self._fingerprints.add(task.fingerprint)
            heapq.heappush(self._heap, task)
            self._stats['total_added'] += 1

            return True

    def add_urls(
        self,
        urls: List[str],
        priority: int = 3,
        depth: int = 0,
        discovered_from: Optional[str] = None
    ) -> int:
        """
        Add multiple URLs to the queue.

        Args:
            urls: List of URLs to add
            priority: Priority for all URLs
            depth: Crawl depth for all URLs
            discovered_from: Parent URL

        Returns:
            Number of URLs successfully added
        """
        added = 0
        for url in urls:
            if self.add_url(url, priority, depth, discovered_from):
                added += 1
        return added

    def get_next(self) -> Optional[CrawlTask]:
        """
        Get the next URL to crawl (highest priority).

        Returns:
            CrawlTask or None if queue is empty
        """
        with self._lock:
            while self._heap:
                task = heapq.heappop(self._heap)

                # Skip if already processed (shouldn't happen, but safety check)
                if task.fingerprint in self._processing:
                    continue

                # Mark as processing
                task.status = CrawlStatus.PROCESSING
                self._processing[task.fingerprint] = task

                return task

            return None

    def mark_completed(self, task: CrawlTask) -> None:
        """Mark a task as successfully completed."""
        with self._lock:
            task.status = CrawlStatus.COMPLETED
            task.processed_at = datetime.now()
            self._processing.pop(task.fingerprint, None)
            self._stats['total_processed'] += 1

    def mark_failed(self, task: CrawlTask, error: str = "") -> None:
        """Mark a task as failed."""
        with self._lock:
            task.status = CrawlStatus.FAILED
            task.processed_at = datetime.now()
            task.error_message = error
            task.retry_count += 1
            self._processing.pop(task.fingerprint, None)
            self._stats['total_failed'] += 1

    def mark_skipped(self, task: CrawlTask, reason: str = "") -> None:
        """Mark a task as skipped (e.g., static asset)."""
        with self._lock:
            task.status = CrawlStatus.SKIPPED
            task.processed_at = datetime.now()
            task.error_message = reason
            self._processing.pop(task.fingerprint, None)
            self._stats['total_skipped'] += 1

    def retry_failed(self, task: CrawlTask, max_retries: int = 3) -> bool:
        """
        Retry a failed task if retry limit not reached.

        Returns:
            True if task was re-queued, False otherwise
        """
        with self._lock:
            if task.retry_count >= max_retries:
                return False

            # Reset status and re-add to queue
            task.status = CrawlStatus.PENDING
            task.error_message = None

            # Lower priority for retries
            task.priority += 1

            heapq.heappush(self._heap, task)
            return True

    def is_visited(self, url: str) -> bool:
        """Check if a URL has already been visited or queued."""
        task = CrawlTask(priority=0, url=url)
        with self._lock:
            return task.fingerprint in self._fingerprints

    def size(self) -> int:
        """Get the number of pending URLs in the queue."""
        with self._lock:
            return len(self._heap)

    def processing_count(self) -> int:
        """Get the number of URLs currently being processed."""
        with self._lock:
            return len(self._processing)

    def is_empty(self) -> bool:
        """Check if the queue is empty."""
        with self._lock:
            return len(self._heap) == 0 and len(self._processing) == 0

    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        with self._lock:
            return {
                **self._stats,
                'pending': len(self._heap),
                'processing': len(self._processing),
                'total_fingerprints': len(self._fingerprints),
            }

    def clear(self) -> None:
        """Clear all queued URLs."""
        with self._lock:
            self._heap.clear()
            self._fingerprints.clear()
            self._processing.clear()
            self._stats = {k: 0 for k in self._stats}

    def get_pending_tasks(self, limit: int = 100) -> List[CrawlTask]:
        """Get a list of pending tasks (for inspection)."""
        with self._lock:
            # Return sorted copy without modifying the heap
            return sorted(self._heap[:limit])

    def set_domain_scope(self, domains: Set[str]) -> None:
        """Update the allowed domains."""
        with self._lock:
            self.allowed_domains = domains

    # --- Private methods ---

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within allowed domain scope."""
        if not self.allowed_domains:
            return True

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        for allowed in self.allowed_domains:
            allowed = allowed.lower()

            if allowed.startswith('*.'):
                # Wildcard match
                suffix = allowed[2:]
                if domain == suffix or domain.endswith('.' + suffix):
                    return True
            else:
                # Exact match
                if domain == allowed:
                    return True

        return False


class PersistentCrawlQueue(CrawlQueue):
    """
    Crawl queue with PostgreSQL persistence for resumable crawls.

    Extends CrawlQueue to save/load state from database.
    """

    def __init__(
        self,
        db_connection,
        max_depth: int = 3,
        max_urls: int = 1000,
        allowed_domains: Optional[Set[str]] = None
    ):
        """
        Initialize persistent queue.

        Args:
            db_connection: psycopg2 connection object
            max_depth: Maximum crawl depth
            max_urls: Maximum URLs to queue
            allowed_domains: Allowed domain scope
        """
        super().__init__(max_depth, max_urls, allowed_domains)
        self.db = db_connection

    def save_to_db(self, task: CrawlTask) -> int:
        """
        Save a task to the database.

        Returns:
            Database row ID
        """
        cursor = self.db.cursor()
        cursor.execute("""
            INSERT INTO crawl_queue (url, priority, depth, status, discovered_from, fingerprint)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (fingerprint) DO UPDATE SET
                status = EXCLUDED.status,
                priority = EXCLUDED.priority
            RETURNING id
        """, (
            task.url,
            task.priority,
            task.depth,
            task.status.value,
            task.discovered_from,
            task.fingerprint
        ))
        row_id = cursor.fetchone()[0]
        self.db.commit()
        return row_id

    def load_from_db(self, status: Optional[str] = None, limit: int = 100) -> List[CrawlTask]:
        """
        Load tasks from database.

        Args:
            status: Filter by status (None = all)
            limit: Maximum tasks to load

        Returns:
            List of CrawlTask objects
        """
        cursor = self.db.cursor()

        if status:
            cursor.execute("""
                SELECT url, priority, depth, status, discovered_from, fingerprint, created_at
                FROM crawl_queue
                WHERE status = %s
                ORDER BY priority ASC, created_at ASC
                LIMIT %s
            """, (status, limit))
        else:
            cursor.execute("""
                SELECT url, priority, depth, status, discovered_from, fingerprint, created_at
                FROM crawl_queue
                ORDER BY priority ASC, created_at ASC
                LIMIT %s
            """, (limit,))

        tasks = []
        for row in cursor.fetchall():
            task = CrawlTask(
                priority=row[1],
                url=row[0],
                depth=row[2],
                status=CrawlStatus(row[3]),
                discovered_from=row[4],
                fingerprint=row[5],
                created_at=row[6]
            )
            tasks.append(task)

        return tasks

    def resume_from_db(self) -> int:
        """
        Resume crawl by loading pending tasks from database.

        Returns:
            Number of tasks loaded
        """
        pending_tasks = self.load_from_db(status=CrawlStatus.PENDING.value, limit=self.max_urls)

        with self._lock:
            for task in pending_tasks:
                if task.fingerprint not in self._fingerprints:
                    self._fingerprints.add(task.fingerprint)
                    heapq.heappush(self._heap, task)

        return len(pending_tasks)

    def update_status_in_db(self, task: CrawlTask) -> None:
        """Update task status in database."""
        cursor = self.db.cursor()
        cursor.execute("""
            UPDATE crawl_queue
            SET status = %s, processed_at = %s, error_message = %s
            WHERE fingerprint = %s
        """, (
            task.status.value,
            task.processed_at,
            task.error_message,
            task.fingerprint
        ))
        self.db.commit()


# Example usage
if __name__ == "__main__":
    # Create queue
    queue = CrawlQueue(
        max_depth=3,
        max_urls=1000,
        allowed_domains={"example.com", "*.example.com"}
    )

    # Add seed URLs
    queue.add_url("https://example.com/", priority=1, depth=0)
    queue.add_url("https://example.com/login", priority=2, depth=0)
    queue.add_url("https://example.com/admin", priority=1, depth=0)

    # Add some discovered links
    queue.add_url("https://example.com/users", priority=3, depth=1, discovered_from="https://example.com/")
    queue.add_url("https://example.com/api/v1/data", priority=1, depth=1, discovered_from="https://example.com/")

    # Try to add duplicate (should be rejected)
    result = queue.add_url("https://example.com/login", priority=3, depth=1)
    print(f"Duplicate add result: {result}")  # False

    # Try to add out-of-scope URL
    result = queue.add_url("https://other.com/page", priority=3, depth=1)
    print(f"Out-of-scope add result: {result}")  # False

    # Process queue
    print(f"\nProcessing queue (size: {queue.size()}):")
    while task := queue.get_next():
        print(f"  [{task.priority}] Depth {task.depth}: {task.url}")
        queue.mark_completed(task)

    # Show stats
    print(f"\nQueue stats: {queue.get_stats()}")
