"""
Link Prioritizer Module

Hybrid 3-tier link scoring system:
- Tier 1: Rule-based fast filtering (milliseconds)
- Tier 2: TF-IDF content relevance scoring
- Tier 3: Q-Learning adaptive model

Based on research from Deep-Deep (TeamHG-Memex) and industry practices.
"""

import re
import math
import pickle
import hashlib
import random
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse

# For TF-IDF
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np


@dataclass
class CrawlResult:
    """Result from crawling a page, used for Q-learning rewards"""
    url: str
    status_code: int = 200
    content_type: str = ""
    has_form: bool = False
    has_authentication: bool = False
    has_api_endpoint: bool = False
    has_admin_indicator: bool = False
    is_static_content: bool = False
    is_duplicate: bool = False
    potential_vulnerabilities: List[str] = field(default_factory=list)
    discovered_links: int = 0
    response_time_ms: float = 0


@dataclass
class Link:
    """Simplified link representation for scoring"""
    url: str
    anchor_text: str = ""
    context: str = ""
    source_url: str = ""

    @property
    def path(self) -> str:
        return urlparse(self.url).path.lower()

    @property
    def domain(self) -> str:
        return urlparse(self.url).netloc.lower()


class RuleBasedFilter:
    """
    Tier 1: Fast rule-based filtering and boosting.

    Executes in milliseconds. Handles:
    - Static asset skipping
    - Security keyword boosting
    - Domain scope validation
    """

    # Static asset extensions
    SKIP_EXTENSIONS = {
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.ico', '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp3', '.mp4', '.webm', '.ogg', '.wav', '.avi',
        '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
        '.map', '.min.js', '.min.css', '.bundle.js'
    }

    # Static asset paths
    SKIP_PATHS = [
        '/static/', '/assets/', '/dist/', '/build/',
        '/node_modules/', '/vendor/', '/lib/', '/fonts/',
        '/images/', '/img/', '/css/', '/js/', '/media/'
    ]

    # Critical security paths (highest priority)
    CRITICAL_KEYWORDS = {
        'admin', 'api', 'auth', 'config', 'debug',
        'console', 'dashboard', 'internal', 'manage',
        'system', 'control', 'backend', 'superuser'
    }

    # High priority paths
    HIGH_KEYWORDS = {
        'login', 'signin', 'signup', 'register', 'logout',
        'account', 'user', 'profile', 'password', 'reset',
        'token', 'session', 'oauth', 'sso', 'checkout',
        'payment', 'billing', 'order', 'cart', 'settings'
    }

    # Medium priority paths
    MEDIUM_KEYWORDS = {
        'products', 'users', 'search', 'catalog',
        'items', 'categories', 'filter', 'sort',
        'data', 'export', 'import', 'upload', 'download'
    }

    def __init__(self, allowed_domains: Optional[Set[str]] = None):
        self.allowed_domains = allowed_domains or set()

    def should_skip(self, url: str) -> bool:
        """
        Check if URL should be skipped entirely.

        Returns:
            True if URL should be skipped
        """
        path = urlparse(url).path.lower()

        # Check extension
        for ext in self.SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True

        # Check static paths
        for skip_path in self.SKIP_PATHS:
            if skip_path in path:
                return True

        return False

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within allowed domains."""
        if not self.allowed_domains:
            return True

        domain = urlparse(url).netloc.lower()

        for allowed in self.allowed_domains:
            allowed = allowed.lower()
            if allowed.startswith('*.'):
                suffix = allowed[2:]
                if domain == suffix or domain.endswith('.' + suffix):
                    return True
            elif domain == allowed:
                return True

        return False

    def keyword_boost(self, url: str) -> float:
        """
        Calculate priority boost based on URL keywords.

        Returns:
            Score from 0.0 to 1.0 (higher = more important)
        """
        path = urlparse(url).path.lower()

        # Critical keywords
        for keyword in self.CRITICAL_KEYWORDS:
            if keyword in path:
                return 1.0

        # High keywords
        for keyword in self.HIGH_KEYWORDS:
            if keyword in path:
                return 0.7

        # Medium keywords
        for keyword in self.MEDIUM_KEYWORDS:
            if keyword in path:
                return 0.4

        return 0.2  # Base score for other URLs


class TFIDFSecurityScorer:
    """
    Tier 2: TF-IDF based content relevance scoring.

    Scores pages based on security-relevant vocabulary presence.
    Builds corpus incrementally as pages are crawled.
    """

    # Security-relevant vocabulary
    SECURITY_VOCABULARY = [
        # Authentication
        'login', 'signin', 'auth', 'oauth', 'sso', 'saml',
        'password', 'credential', 'session', 'token', 'jwt',
        'username', 'email', 'authenticate', 'authorization',

        # Authorization
        'admin', 'dashboard', 'console', 'manage', 'control',
        'permission', 'role', 'access', 'privilege', 'superuser',

        # API
        'api', 'graphql', 'rest', 'endpoint', 'webhook',
        'swagger', 'openapi', 'json', 'xml', 'response',

        # Sensitive data
        'config', 'setting', 'secret', 'key', 'private',
        'database', 'backup', 'export', 'import', 'upload',

        # E-commerce
        'checkout', 'payment', 'cart', 'order', 'transaction',
        'card', 'billing', 'invoice', 'price', 'discount',

        # User data
        'profile', 'account', 'user', 'personal', 'data',
        'address', 'phone', 'ssn', 'credit', 'bank',

        # Errors/Debug
        'error', 'exception', 'debug', 'trace', 'stack',
        'log', 'dump', 'test', 'dev', 'staging',

        # Forms
        'form', 'input', 'submit', 'button', 'field',
        'validate', 'required', 'hidden'
    ]

    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            vocabulary=self.SECURITY_VOCABULARY,
            lowercase=True,
            stop_words='english'
        )

        # Initialize with vocabulary
        self.vectorizer.fit([' '.join(self.SECURITY_VOCABULARY)])

        # Corpus for IDF updates
        self.corpus: List[str] = []
        self._needs_refit = False

    def score(self, content: str) -> float:
        """
        Score content based on security vocabulary TF-IDF.

        Args:
            content: Page content (HTML stripped to text)

        Returns:
            Score from 0.0 to 1.0
        """
        if not content or len(content.strip()) < 10:
            return 0.0

        try:
            # Transform content
            tfidf_matrix = self.vectorizer.transform([content.lower()])

            # Sum of all TF-IDF scores
            score = tfidf_matrix.sum()

            # Normalize to 0-1 range (based on empirical max)
            normalized = min(score / 5.0, 1.0)

            return float(normalized)

        except Exception:
            return 0.0

    def add_to_corpus(self, content: str) -> None:
        """Add content to corpus for IDF updates."""
        if content and len(content.strip()) > 50:
            self.corpus.append(content.lower())
            self._needs_refit = True

            # Periodically refit vectorizer
            if len(self.corpus) % 50 == 0:
                self._refit()

    def _refit(self) -> None:
        """Refit vectorizer with updated corpus."""
        if not self._needs_refit or not self.corpus:
            return

        try:
            # Create new vectorizer with same vocabulary but updated IDF
            combined = [' '.join(self.SECURITY_VOCABULARY)] + self.corpus[-1000:]
            self.vectorizer.fit(combined)
            self._needs_refit = False
        except Exception:
            pass

    def get_top_terms(self, content: str, n: int = 5) -> List[Tuple[str, float]]:
        """Get top security terms found in content."""
        if not content:
            return []

        try:
            tfidf_matrix = self.vectorizer.transform([content.lower()])
            feature_names = self.vectorizer.get_feature_names_out()

            # Get non-zero entries
            scores = tfidf_matrix.toarray()[0]
            term_scores = [(feature_names[i], scores[i]) for i in range(len(scores)) if scores[i] > 0]

            # Sort by score
            term_scores.sort(key=lambda x: x[1], reverse=True)

            return term_scores[:n]

        except Exception:
            return []


class QLinkLearner:
    """
    Tier 3: Q-Learning based adaptive link prioritization.

    Learns which types of links lead to high-value pages.
    Features inspired by Deep-Deep (TeamHG-Memex).
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        discount_factor: float = 0.9,
        exploration_rate: float = 0.2
    ):
        """
        Initialize Q-learner.

        Args:
            learning_rate: Alpha - how much to update Q-values
            discount_factor: Gamma - importance of future rewards
            exploration_rate: Epsilon - probability of random exploration
        """
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.exploration_rate = exploration_rate

        # Q-table: state-action -> value
        # State = URL features, Action = follow/skip
        self.q_table: Dict[str, float] = defaultdict(float)

        # Feature weights learned over time
        self.feature_weights: Dict[str, float] = defaultdict(lambda: 0.5)

        # Statistics
        self.total_updates = 0
        self.total_positive_rewards = 0
        self.total_negative_rewards = 0

    def predict_value(self, link: Link) -> float:
        """
        Predict value of following a link.

        Args:
            link: Link to evaluate

        Returns:
            Predicted value (Q-value) from 0.0 to 1.0
        """
        # Extract features
        features = self._extract_features(link)

        # Calculate Q-value from features
        q_value = 0.0
        for feature, present in features.items():
            if present:
                q_value += self.feature_weights[feature]

        # Normalize
        num_features = max(sum(1 for v in features.values() if v), 1)
        normalized = q_value / num_features

        # Clamp to 0-1
        return max(0.0, min(1.0, normalized))

    def update(self, link: Link, reward: float) -> None:
        """
        Update Q-values based on crawl result.

        Args:
            link: Link that was crawled
            reward: Reward received (-1.0 to 1.0)
        """
        features = self._extract_features(link)

        # Update feature weights
        for feature, present in features.items():
            if present:
                old_weight = self.feature_weights[feature]

                # Q-learning update
                new_weight = old_weight + self.learning_rate * (
                    reward - old_weight
                )

                # Clamp to reasonable range
                self.feature_weights[feature] = max(0.0, min(2.0, new_weight))

        # Track statistics
        self.total_updates += 1
        if reward > 0:
            self.total_positive_rewards += 1
        elif reward < 0:
            self.total_negative_rewards += 1

    def should_explore(self) -> bool:
        """Decide whether to explore (random action) or exploit (best action)."""
        # Decay exploration over time
        decayed_rate = self.exploration_rate * math.exp(-self.total_updates / 1000)
        return random.random() < decayed_rate

    def calculate_reward(self, result: CrawlResult) -> float:
        """
        Calculate reward from crawl result.

        Args:
            result: CrawlResult from crawling

        Returns:
            Reward value from -1.0 to 1.0
        """
        reward = 0.0

        # High reward for security-relevant content
        if result.has_form:
            reward += 0.3
        if result.has_authentication:
            reward += 0.5
        if result.has_api_endpoint:
            reward += 0.4
        if result.has_admin_indicator:
            reward += 0.6

        # Bonus for discovered links (more to explore)
        if result.discovered_links > 10:
            reward += 0.2
        elif result.discovered_links > 5:
            reward += 0.1

        # Negative reward for dead ends
        if result.is_static_content:
            reward -= 0.3
        if result.is_duplicate:
            reward -= 0.5

        # Bonus for finding vulnerabilities
        reward += len(result.potential_vulnerabilities) * 0.5

        # Penalty for errors
        if result.status_code >= 400:
            reward -= 0.2
        if result.status_code >= 500:
            reward -= 0.3

        # Clamp to valid range
        return max(-1.0, min(1.0, reward))

    def save(self, filepath: str) -> None:
        """Save learned model to file."""
        data = {
            'feature_weights': dict(self.feature_weights),
            'total_updates': self.total_updates,
            'learning_rate': self.learning_rate,
            'discount_factor': self.discount_factor,
        }
        with open(filepath, 'wb') as f:
            pickle.dump(data, f)

    def load(self, filepath: str) -> None:
        """Load learned model from file."""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)

        self.feature_weights = defaultdict(lambda: 0.5, data['feature_weights'])
        self.total_updates = data['total_updates']
        self.learning_rate = data.get('learning_rate', 0.1)
        self.discount_factor = data.get('discount_factor', 0.9)

    def get_feature_importance(self) -> List[Tuple[str, float]]:
        """Get features sorted by learned importance."""
        sorted_features = sorted(
            self.feature_weights.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_features

    def _extract_features(self, link: Link) -> Dict[str, bool]:
        """Extract features from a link for Q-learning."""
        path = link.path
        anchor = link.anchor_text.lower()
        context = link.context.lower()

        features = {
            # Path-based features
            'path_has_admin': 'admin' in path,
            'path_has_api': 'api' in path or '/v1' in path or '/v2' in path,
            'path_has_auth': any(k in path for k in ['auth', 'login', 'signin', 'oauth']),
            'path_has_user': any(k in path for k in ['user', 'account', 'profile']),
            'path_has_config': any(k in path for k in ['config', 'setting', 'debug']),
            'path_has_payment': any(k in path for k in ['payment', 'checkout', 'cart', 'billing']),
            'path_has_data': any(k in path for k in ['export', 'import', 'download', 'upload']),

            # Anchor text features
            'anchor_has_action': any(k in anchor for k in ['submit', 'send', 'confirm', 'buy']),
            'anchor_has_admin': 'admin' in anchor,
            'anchor_has_login': any(k in anchor for k in ['login', 'signin', 'register']),

            # Context features
            'context_has_form': 'form' in context,
            'context_has_password': 'password' in context,
            'context_has_email': 'email' in context,
            'context_has_sensitive': any(k in context for k in ['card', 'ssn', 'credit', 'bank']),

            # URL structure features
            'has_query_params': '?' in link.url,
            'has_id_param': any(k in link.url for k in ['id=', 'uid=', 'user_id=']),
            'is_deep_path': link.path.count('/') > 3,

            # Extension features
            'is_json_endpoint': link.url.endswith('.json'),
            'is_xml_endpoint': link.url.endswith('.xml'),
        }

        return features


class HybridLinkPrioritizer:
    """
    Main prioritizer combining all three tiers.

    Usage:
        prioritizer = HybridLinkPrioritizer(allowed_domains={'example.com'})

        # Score a link
        score = prioritizer.score_link(link, page_content)

        # After crawling, update learner
        result = CrawlResult(url=link.url, has_form=True, ...)
        prioritizer.update_from_result(link, result)
    """

    def __init__(
        self,
        allowed_domains: Optional[Set[str]] = None,
        tier1_weight: float = 0.2,
        tier2_weight: float = 0.3,
        tier3_weight: float = 0.5
    ):
        """
        Initialize hybrid prioritizer.

        Args:
            allowed_domains: Domains in scope
            tier1_weight: Weight for rule-based score
            tier2_weight: Weight for TF-IDF score
            tier3_weight: Weight for Q-learning score
        """
        self.rule_filter = RuleBasedFilter(allowed_domains)
        self.tfidf_scorer = TFIDFSecurityScorer()
        self.q_learner = QLinkLearner()

        self.tier1_weight = tier1_weight
        self.tier2_weight = tier2_weight
        self.tier3_weight = tier3_weight

    def score_link(
        self,
        link: Link,
        page_content: str = "",
        use_exploration: bool = True
    ) -> float:
        """
        Calculate priority score for a link.

        Args:
            link: Link to score
            page_content: Content of the source page
            use_exploration: Whether to use Q-learning exploration

        Returns:
            Priority score from 0.0 to 1.0 (higher = more important)
        """
        # Tier 1: Fast filter
        if self.rule_filter.should_skip(link.url):
            return 0.0

        if not self.rule_filter.is_in_scope(link.url):
            return 0.0

        # Get tier 1 score
        tier1_score = self.rule_filter.keyword_boost(link.url)

        # Tier 2: TF-IDF score
        tier2_score = self.tfidf_scorer.score(page_content) if page_content else 0.0

        # Tier 3: Q-learning score
        if use_exploration and self.q_learner.should_explore():
            tier3_score = random.uniform(0.3, 0.8)  # Random exploration
        else:
            tier3_score = self.q_learner.predict_value(link)

        # Weighted combination
        final_score = (
            self.tier1_weight * tier1_score +
            self.tier2_weight * tier2_score +
            self.tier3_weight * tier3_score
        )

        return min(1.0, final_score)

    def update_from_result(self, link: Link, result: CrawlResult) -> None:
        """
        Update learner based on crawl result.

        Args:
            link: Link that was crawled
            result: Result from crawling
        """
        # Calculate reward
        reward = self.q_learner.calculate_reward(result)

        # Update Q-learner
        self.q_learner.update(link, reward)

        # Update TF-IDF corpus if we have content
        # (would need to pass content through result)

    def get_priority_bucket(self, score: float) -> int:
        """
        Convert score to priority bucket (1-5).

        Args:
            score: Score from 0.0 to 1.0

        Returns:
            Priority bucket (1 = highest, 5 = lowest)
        """
        if score >= 0.8:
            return 1
        elif score >= 0.6:
            return 2
        elif score >= 0.4:
            return 3
        elif score >= 0.2:
            return 4
        else:
            return 5

    def save_model(self, filepath: str) -> None:
        """Save Q-learning model."""
        self.q_learner.save(filepath)

    def load_model(self, filepath: str) -> None:
        """Load Q-learning model."""
        self.q_learner.load(filepath)

    def get_stats(self) -> Dict[str, Any]:
        """Get prioritizer statistics."""
        return {
            'q_learner_updates': self.q_learner.total_updates,
            'positive_rewards': self.q_learner.total_positive_rewards,
            'negative_rewards': self.q_learner.total_negative_rewards,
            'top_features': self.q_learner.get_feature_importance()[:10],
            'tfidf_corpus_size': len(self.tfidf_scorer.corpus),
        }


# Example usage
if __name__ == "__main__":
    # Create prioritizer
    prioritizer = HybridLinkPrioritizer(
        allowed_domains={"example.com", "*.example.com"}
    )

    # Test links
    test_links = [
        Link(url="https://example.com/admin/dashboard", anchor_text="Admin Panel"),
        Link(url="https://example.com/api/v1/users", anchor_text="API"),
        Link(url="https://example.com/login", anchor_text="Login"),
        Link(url="https://example.com/about", anchor_text="About Us"),
        Link(url="https://example.com/static/style.css", anchor_text=""),
    ]

    print("Link Scores:")
    for link in test_links:
        score = prioritizer.score_link(link, use_exploration=False)
        bucket = prioritizer.get_priority_bucket(score)
        print(f"  [{bucket}] {score:.3f} - {link.url}")

    # Simulate learning
    print("\nSimulating crawl results...")

    # Positive result - admin page with forms
    admin_result = CrawlResult(
        url="https://example.com/admin/dashboard",
        has_form=True,
        has_admin_indicator=True,
        has_authentication=True,
        discovered_links=15
    )
    admin_link = Link(url="https://example.com/admin/dashboard")
    prioritizer.update_from_result(admin_link, admin_result)

    # Negative result - static content
    static_result = CrawlResult(
        url="https://example.com/about",
        is_static_content=True,
        discovered_links=2
    )
    about_link = Link(url="https://example.com/about")
    prioritizer.update_from_result(about_link, static_result)

    print("\nAfter learning:")
    for link in test_links[:3]:
        score = prioritizer.score_link(link, use_exploration=False)
        bucket = prioritizer.get_priority_bucket(score)
        print(f"  [{bucket}] {score:.3f} - {link.url}")

    print(f"\nStats: {prioritizer.get_stats()}")
