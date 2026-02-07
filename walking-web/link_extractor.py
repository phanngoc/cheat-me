"""
Link Extractor Module

Extracts and categorizes links from HTML content and JavaScript files.
Supports HTML parsing, JavaScript endpoint discovery, and link prioritization.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class LinkType(Enum):
    """Type of link discovered"""
    ANCHOR = "anchor"           # <a href="...">
    FORM = "form"               # <form action="...">
    SCRIPT = "script"           # <script src="...">
    STYLESHEET = "stylesheet"   # <link rel="stylesheet">
    API_DOC = "api_doc"         # OpenAPI, Swagger links
    JAVASCRIPT = "javascript"   # Extracted from JS code
    REDIRECT = "redirect"       # Meta refresh, JS redirect
    IFRAME = "iframe"           # <iframe src="...">
    IMAGE = "image"             # <img src="...">
    MEDIA = "media"             # <video>, <audio>


class LinkPriority(Enum):
    """Priority level for crawling"""
    CRITICAL = 1    # admin, api, auth, checkout
    HIGH = 2        # login, register, account, payment
    MEDIUM = 3      # products, users, search
    LOW = 4         # about, contact, help
    SKIP = 5        # static assets


@dataclass
class Link:
    """Represents a discovered link"""
    url: str
    link_type: LinkType
    priority: LinkPriority = LinkPriority.MEDIUM
    anchor_text: str = ""
    context: str = ""  # surrounding text/context
    source_url: str = ""

    # Additional metadata
    is_external: bool = False
    has_parameters: bool = False
    form_method: Optional[str] = None  # GET, POST for forms
    form_fields: List[str] = field(default_factory=list)

    def __hash__(self):
        return hash(self.url)

    def __eq__(self, other):
        if isinstance(other, Link):
            return self.url == other.url
        return False


class LinkExtractor:
    """
    Extracts links from HTML content and JavaScript code.

    Features:
    - HTML parsing for anchors, forms, scripts
    - JavaScript endpoint discovery
    - Link categorization by type and priority
    - Domain scope filtering
    - Static asset detection
    """

    # Patterns for high-priority security-relevant paths
    CRITICAL_PATTERNS = [
        r'/admin', r'/api', r'/auth', r'/checkout',
        r'/config', r'/debug', r'/internal', r'/manage',
        r'/console', r'/dashboard', r'/control', r'/system'
    ]

    HIGH_PATTERNS = [
        r'/login', r'/signin', r'/signup', r'/register',
        r'/account', r'/payment', r'/billing', r'/user',
        r'/profile', r'/session', r'/oauth', r'/token'
    ]

    MEDIUM_PATTERNS = [
        r'/products?', r'/users?', r'/search', r'/catalog',
        r'/orders?', r'/cart', r'/items?', r'/categories'
    ]

    LOW_PATTERNS = [
        r'/about', r'/contact', r'/help', r'/faq',
        r'/terms', r'/privacy', r'/legal', r'/support'
    ]

    # Static asset extensions to skip
    STATIC_EXTENSIONS = {
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.ico', '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp3', '.mp4', '.webm', '.ogg', '.wav',
        '.pdf', '.zip', '.tar', '.gz', '.rar',
        '.map', '.min.js', '.min.css'
    }

    # JavaScript patterns for API endpoint discovery
    JS_ENDPOINT_PATTERNS = [
        # fetch() calls
        r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        # axios calls
        r'axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        # jQuery ajax
        r'\$\.(ajax|get|post)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
        # XMLHttpRequest
        r'\.open\s*\(\s*[\'"`]\w+[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]',
        # String literals that look like API paths
        r'[\'"`](/api/[^\'"`]+)[\'"`]',
        r'[\'"`](/v\d+/[^\'"`]+)[\'"`]',
        # GraphQL endpoint
        r'[\'"`](/graphql)[\'"`]',
    ]

    def __init__(self, allowed_domains: Optional[Set[str]] = None):
        """
        Initialize the link extractor.

        Args:
            allowed_domains: Set of domains to consider in-scope.
                           Supports wildcards like "*.example.com"
        """
        self.allowed_domains = allowed_domains or set()
        self._compiled_js_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.JS_ENDPOINT_PATTERNS
        ]

    def extract_from_html(self, html: str, base_url: str) -> List[Link]:
        """
        Extract all links from HTML content.

        Args:
            html: HTML content to parse
            base_url: Base URL for resolving relative links

        Returns:
            List of discovered Link objects
        """
        links = []
        soup = BeautifulSoup(html, 'html.parser')

        # Extract anchor links
        links.extend(self._extract_anchors(soup, base_url))

        # Extract form actions
        links.extend(self._extract_forms(soup, base_url))

        # Extract script sources
        links.extend(self._extract_scripts(soup, base_url))

        # Extract stylesheets
        links.extend(self._extract_stylesheets(soup, base_url))

        # Extract iframes
        links.extend(self._extract_iframes(soup, base_url))

        # Extract meta refresh redirects
        links.extend(self._extract_meta_redirects(soup, base_url))

        # Extract inline JavaScript endpoints
        links.extend(self._extract_inline_js_endpoints(soup, base_url))

        # Deduplicate and categorize
        unique_links = self._deduplicate(links)

        return unique_links

    def extract_from_js(self, js_content: str, base_url: str) -> List[Link]:
        """
        Extract API endpoints from JavaScript code.

        Args:
            js_content: JavaScript source code
            base_url: Base URL for resolving relative paths

        Returns:
            List of discovered Link objects (API endpoints)
        """
        links = []

        for pattern in self._compiled_js_patterns:
            matches = pattern.findall(js_content)
            for match in matches:
                # Handle tuple matches (from groups)
                if isinstance(match, tuple):
                    url = match[-1]  # Usually the URL is the last group
                else:
                    url = match

                # Skip empty or invalid matches
                if not url or url.startswith('#') or url.startswith('javascript:'):
                    continue

                # Resolve relative URLs
                absolute_url = urljoin(base_url, url)

                # Create link
                link = Link(
                    url=absolute_url,
                    link_type=LinkType.JAVASCRIPT,
                    source_url=base_url,
                    context="JavaScript API call"
                )

                # Categorize priority
                link.priority = self._categorize_priority(absolute_url)
                link.is_external = not self._is_in_scope(absolute_url)
                link.has_parameters = '?' in absolute_url

                links.append(link)

        return self._deduplicate(links)

    def categorize_link(self, url: str) -> LinkPriority:
        """
        Categorize a link by its security/business value.

        Args:
            url: URL to categorize

        Returns:
            LinkPriority enum value
        """
        return self._categorize_priority(url)

    def is_static_asset(self, url: str) -> bool:
        """
        Check if a URL points to a static asset.

        Args:
            url: URL to check

        Returns:
            True if URL is a static asset
        """
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Check extension
        for ext in self.STATIC_EXTENSIONS:
            if path.endswith(ext):
                return True

        # Check common static paths
        static_paths = ['/static/', '/assets/', '/dist/', '/build/', '/node_modules/']
        for sp in static_paths:
            if sp in path:
                return True

        return False

    def is_in_scope(self, url: str) -> bool:
        """
        Check if a URL is within the allowed domain scope.

        Args:
            url: URL to check

        Returns:
            True if URL is in scope
        """
        return self._is_in_scope(url)

    # --- Private methods ---

    def _extract_anchors(self, soup: BeautifulSoup, base_url: str) -> List[Link]:
        """Extract <a href="..."> links"""
        links = []

        for anchor in soup.find_all('a', href=True):
            href = anchor['href']

            # Skip javascript: and mailto: links
            if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue

            absolute_url = urljoin(base_url, href)

            # Get anchor text
            anchor_text = anchor.get_text(strip=True)[:100]

            # Get surrounding context
            parent = anchor.parent
            context = parent.get_text(strip=True)[:200] if parent else ""

            link = Link(
                url=absolute_url,
                link_type=LinkType.ANCHOR,
                anchor_text=anchor_text,
                context=context,
                source_url=base_url
            )

            link.priority = self._categorize_priority(absolute_url)
            link.is_external = not self._is_in_scope(absolute_url)
            link.has_parameters = '?' in absolute_url

            links.append(link)

        return links

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Link]:
        """Extract <form action="..."> links"""
        links = []

        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()

            # Empty action means submit to current page
            if not action:
                action = base_url

            absolute_url = urljoin(base_url, action)

            # Extract form field names
            field_names = []
            for inp in form.find_all(['input', 'select', 'textarea']):
                name = inp.get('name')
                if name:
                    field_names.append(name)

            link = Link(
                url=absolute_url,
                link_type=LinkType.FORM,
                source_url=base_url,
                form_method=method,
                form_fields=field_names,
                context=f"Form with fields: {', '.join(field_names[:5])}"
            )

            # Forms are generally higher priority (potential attack surface)
            link.priority = self._categorize_priority(absolute_url)
            if link.priority.value > LinkPriority.HIGH.value:
                link.priority = LinkPriority.HIGH

            link.is_external = not self._is_in_scope(absolute_url)

            links.append(link)

        return links

    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[Link]:
        """Extract <script src="..."> links"""
        links = []

        for script in soup.find_all('script', src=True):
            src = script['src']
            absolute_url = urljoin(base_url, src)

            link = Link(
                url=absolute_url,
                link_type=LinkType.SCRIPT,
                source_url=base_url,
                priority=LinkPriority.SKIP  # Scripts are usually static
            )

            link.is_external = not self._is_in_scope(absolute_url)

            links.append(link)

        return links

    def _extract_stylesheets(self, soup: BeautifulSoup, base_url: str) -> List[Link]:
        """Extract <link rel="stylesheet"> links"""
        links = []

        for link_tag in soup.find_all('link', rel='stylesheet'):
            href = link_tag.get('href')
            if not href:
                continue

            absolute_url = urljoin(base_url, href)

            link = Link(
                url=absolute_url,
                link_type=LinkType.STYLESHEET,
                source_url=base_url,
                priority=LinkPriority.SKIP
            )

            link.is_external = not self._is_in_scope(absolute_url)

            links.append(link)

        return links

    def _extract_iframes(self, soup: BeautifulSoup, base_url: str) -> List[Link]:
        """Extract <iframe src="..."> links"""
        links = []

        for iframe in soup.find_all('iframe', src=True):
            src = iframe['src']

            if src.startswith('javascript:'):
                continue

            absolute_url = urljoin(base_url, src)

            link = Link(
                url=absolute_url,
                link_type=LinkType.IFRAME,
                source_url=base_url
            )

            link.priority = self._categorize_priority(absolute_url)
            link.is_external = not self._is_in_scope(absolute_url)

            links.append(link)

        return links

    def _extract_meta_redirects(self, soup: BeautifulSoup, base_url: str) -> List[Link]:
        """Extract meta refresh redirects"""
        links = []

        for meta in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
            content = meta.get('content', '')

            # Parse "5; url=http://example.com"
            match = re.search(r'url\s*=\s*[\'"]?([^\'"\s>]+)', content, re.IGNORECASE)
            if match:
                url = match.group(1)
                absolute_url = urljoin(base_url, url)

                link = Link(
                    url=absolute_url,
                    link_type=LinkType.REDIRECT,
                    source_url=base_url,
                    context="Meta refresh redirect"
                )

                link.priority = self._categorize_priority(absolute_url)
                link.is_external = not self._is_in_scope(absolute_url)

                links.append(link)

        return links

    def _extract_inline_js_endpoints(self, soup: BeautifulSoup, base_url: str) -> List[Link]:
        """Extract API endpoints from inline JavaScript"""
        links = []

        for script in soup.find_all('script'):
            if script.string:
                js_links = self.extract_from_js(script.string, base_url)
                links.extend(js_links)

        return links

    def _categorize_priority(self, url: str) -> LinkPriority:
        """Determine priority based on URL patterns"""
        path = urlparse(url).path.lower()

        # Check for static assets first
        if self.is_static_asset(url):
            return LinkPriority.SKIP

        # Check critical patterns
        for pattern in self.CRITICAL_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return LinkPriority.CRITICAL

        # Check high patterns
        for pattern in self.HIGH_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return LinkPriority.HIGH

        # Check medium patterns
        for pattern in self.MEDIUM_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return LinkPriority.MEDIUM

        # Check low patterns
        for pattern in self.LOW_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return LinkPriority.LOW

        # Default to medium
        return LinkPriority.MEDIUM

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within allowed domains"""
        if not self.allowed_domains:
            return True  # No restrictions

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        for allowed in self.allowed_domains:
            if allowed.startswith('*.'):
                # Wildcard match
                suffix = allowed[2:]
                if domain == suffix or domain.endswith('.' + suffix):
                    return True
            else:
                # Exact match
                if domain == allowed.lower():
                    return True

        return False

    def _deduplicate(self, links: List[Link]) -> List[Link]:
        """Remove duplicate links, keeping highest priority"""
        url_to_link = {}

        for link in links:
            if link.url in url_to_link:
                existing = url_to_link[link.url]
                # Keep the one with higher priority (lower number)
                if link.priority.value < existing.priority.value:
                    url_to_link[link.url] = link
            else:
                url_to_link[link.url] = link

        return list(url_to_link.values())


# Example usage
if __name__ == "__main__":
    html = """
    <html>
    <head>
        <script src="/static/app.js"></script>
        <link rel="stylesheet" href="/static/style.css">
    </head>
    <body>
        <a href="/login">Login</a>
        <a href="/admin/dashboard">Admin</a>
        <a href="/api/v1/users">API Users</a>
        <form action="/checkout" method="POST">
            <input name="product_id" type="hidden">
            <input name="quantity" type="number">
            <button type="submit">Buy</button>
        </form>
        <script>
            fetch('/api/v1/products');
            axios.get('/api/v2/orders');
        </script>
    </body>
    </html>
    """

    extractor = LinkExtractor(allowed_domains={"example.com", "*.example.com"})
    links = extractor.extract_from_html(html, "https://example.com/page")

    print("Discovered links:")
    for link in sorted(links, key=lambda l: l.priority.value):
        print(f"  [{link.priority.name}] {link.link_type.name}: {link.url}")
