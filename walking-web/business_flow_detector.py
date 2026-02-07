"""
Business Flow Detector Module

Detects and categorizes business flows in web applications:
- Authentication flows (login, signup, OAuth)
- E-commerce flows (cart, checkout, payment)
- Admin panels and dashboards
- User management flows
- API endpoints

Suggests security test cases for each flow type.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set, Tuple, Any
from bs4 import BeautifulSoup


class FlowType(Enum):
    """Types of business flows"""
    AUTHENTICATION = "authentication"
    REGISTRATION = "registration"
    PASSWORD_RESET = "password_reset"
    E_COMMERCE = "e_commerce"
    PAYMENT = "payment"
    USER_MANAGEMENT = "user_management"
    ADMIN_PANEL = "admin_panel"
    API_ENDPOINT = "api_endpoint"
    FILE_UPLOAD = "file_upload"
    SEARCH = "search"
    DATA_EXPORT = "data_export"
    SETTINGS = "settings"


class FlowPriority(Enum):
    """Security priority of flows"""
    CRITICAL = 1    # Direct security impact
    HIGH = 2        # Significant security relevance
    MEDIUM = 3      # Moderate security relevance
    LOW = 4         # Minimal security relevance


@dataclass
class FormField:
    """Represents a form field"""
    name: str
    field_type: str  # text, password, email, hidden, etc.
    value: str = ""
    is_required: bool = False
    placeholder: str = ""
    pattern: str = ""


@dataclass
class DetectedForm:
    """Represents a detected form"""
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)
    submit_text: str = ""
    form_id: str = ""
    form_class: str = ""


@dataclass
class BusinessFlow:
    """Represents a detected business flow"""
    flow_type: FlowType
    priority: FlowPriority
    url: str
    confidence: float  # 0.0 to 1.0
    forms: List[DetectedForm] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    suggested_tests: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityTest:
    """Represents a suggested security test"""
    name: str
    description: str
    category: str  # injection, auth_bypass, brute_force, etc.
    payloads: List[Dict[str, str]] = field(default_factory=list)
    risk_level: str = "medium"  # low, medium, high, critical


class BusinessFlowDetector:
    """
    Detects business flows in web pages and suggests security tests.

    Usage:
        detector = BusinessFlowDetector()
        flows = detector.detect_flows(url, html_content)
        for flow in flows:
            tests = detector.suggest_tests(flow)
    """

    # Flow pattern definitions
    FLOW_PATTERNS = {
        FlowType.AUTHENTICATION: {
            'url_keywords': ['login', 'signin', 'sign-in', 'auth', 'authenticate', 'session'],
            'form_fields': ['username', 'password', 'email', 'login', 'user', 'pass'],
            'content_keywords': ['login', 'sign in', 'log in', 'authenticate', 'credentials'],
            'submit_keywords': ['login', 'sign in', 'log in', 'submit', 'enter'],
            'priority': FlowPriority.CRITICAL,
            'min_confidence': 0.6
        },
        FlowType.REGISTRATION: {
            'url_keywords': ['signup', 'sign-up', 'register', 'create-account', 'join'],
            'form_fields': ['email', 'password', 'confirm_password', 'name', 'username', 'phone'],
            'content_keywords': ['sign up', 'register', 'create account', 'join', 'new account'],
            'submit_keywords': ['register', 'sign up', 'create', 'join', 'submit'],
            'priority': FlowPriority.HIGH,
            'min_confidence': 0.5
        },
        FlowType.PASSWORD_RESET: {
            'url_keywords': ['reset', 'forgot', 'recover', 'password'],
            'form_fields': ['email', 'username', 'new_password', 'confirm'],
            'content_keywords': ['reset password', 'forgot password', 'recover', 'new password'],
            'submit_keywords': ['reset', 'recover', 'send', 'submit'],
            'priority': FlowPriority.HIGH,
            'min_confidence': 0.5
        },
        FlowType.E_COMMERCE: {
            'url_keywords': ['cart', 'basket', 'checkout', 'order', 'buy', 'shop'],
            'form_fields': ['quantity', 'product_id', 'add_to_cart', 'coupon', 'promo'],
            'content_keywords': ['add to cart', 'buy now', 'checkout', 'shopping', 'order'],
            'submit_keywords': ['add', 'buy', 'checkout', 'order', 'purchase'],
            'priority': FlowPriority.CRITICAL,
            'min_confidence': 0.5
        },
        FlowType.PAYMENT: {
            'url_keywords': ['payment', 'pay', 'billing', 'card', 'checkout'],
            'form_fields': ['card_number', 'cvv', 'expiry', 'cardholder', 'billing', 'credit'],
            'content_keywords': ['credit card', 'payment', 'billing', 'pay', 'card details'],
            'submit_keywords': ['pay', 'submit', 'process', 'complete'],
            'priority': FlowPriority.CRITICAL,
            'min_confidence': 0.6
        },
        FlowType.USER_MANAGEMENT: {
            'url_keywords': ['profile', 'account', 'settings', 'preferences', 'user'],
            'form_fields': ['name', 'email', 'phone', 'address', 'bio', 'avatar'],
            'content_keywords': ['profile', 'account', 'personal', 'edit', 'update'],
            'submit_keywords': ['save', 'update', 'edit', 'change'],
            'priority': FlowPriority.MEDIUM,
            'min_confidence': 0.4
        },
        FlowType.ADMIN_PANEL: {
            'url_keywords': ['admin', 'dashboard', 'manage', 'console', 'control', 'backend'],
            'form_fields': ['admin', 'role', 'permission', 'status', 'delete', 'edit'],
            'content_keywords': ['admin', 'dashboard', 'management', 'control panel', 'backend'],
            'submit_keywords': ['delete', 'edit', 'update', 'manage', 'approve'],
            'priority': FlowPriority.CRITICAL,
            'min_confidence': 0.5
        },
        FlowType.API_ENDPOINT: {
            'url_keywords': ['api', 'v1', 'v2', 'graphql', 'rest', 'endpoint'],
            'content_keywords': ['api', 'json', 'endpoint', 'request', 'response'],
            'priority': FlowPriority.HIGH,
            'min_confidence': 0.4
        },
        FlowType.FILE_UPLOAD: {
            'url_keywords': ['upload', 'import', 'file', 'document', 'attachment'],
            'form_fields': ['file', 'upload', 'document', 'attachment', 'image'],
            'content_keywords': ['upload', 'choose file', 'drag and drop', 'attach'],
            'submit_keywords': ['upload', 'submit', 'import', 'attach'],
            'priority': FlowPriority.HIGH,
            'min_confidence': 0.5
        },
        FlowType.SEARCH: {
            'url_keywords': ['search', 'find', 'query', 'q='],
            'form_fields': ['search', 'query', 'q', 'keyword', 'term'],
            'content_keywords': ['search', 'find', 'looking for'],
            'submit_keywords': ['search', 'find', 'go'],
            'priority': FlowPriority.MEDIUM,
            'min_confidence': 0.4
        },
        FlowType.DATA_EXPORT: {
            'url_keywords': ['export', 'download', 'report', 'csv', 'pdf'],
            'form_fields': ['format', 'date_range', 'export_type'],
            'content_keywords': ['export', 'download', 'generate report'],
            'submit_keywords': ['export', 'download', 'generate'],
            'priority': FlowPriority.MEDIUM,
            'min_confidence': 0.4
        },
        FlowType.SETTINGS: {
            'url_keywords': ['settings', 'config', 'preferences', 'options'],
            'form_fields': ['setting', 'option', 'preference', 'config'],
            'content_keywords': ['settings', 'configuration', 'preferences'],
            'submit_keywords': ['save', 'apply', 'update'],
            'priority': FlowPriority.MEDIUM,
            'min_confidence': 0.4
        }
    }

    # Security test templates
    TEST_TEMPLATES = {
        FlowType.AUTHENTICATION: [
            SecurityTest(
                name="SQL Injection - Login Bypass",
                description="Test for SQL injection in login form",
                category="injection",
                risk_level="critical",
                payloads=[
                    {"username": "admin'--", "password": "x"},
                    {"username": "' OR '1'='1", "password": "' OR '1'='1"},
                    {"username": "admin'/*", "password": "*/--"},
                    {"username": "' OR 1=1--", "password": "anything"}
                ]
            ),
            SecurityTest(
                name="Default Credentials",
                description="Test for common default credentials",
                category="auth_bypass",
                risk_level="high",
                payloads=[
                    {"username": "admin", "password": "admin"},
                    {"username": "admin", "password": "password"},
                    {"username": "root", "password": "root"},
                    {"username": "test", "password": "test"},
                    {"username": "admin", "password": "123456"}
                ]
            ),
            SecurityTest(
                name="Brute Force Susceptibility",
                description="Test for rate limiting on login attempts",
                category="brute_force",
                risk_level="high",
                payloads=[]
            ),
            SecurityTest(
                name="Session Fixation",
                description="Test for session fixation vulnerabilities",
                category="session",
                risk_level="high",
                payloads=[]
            ),
            SecurityTest(
                name="Username Enumeration",
                description="Test if application reveals valid usernames",
                category="information_disclosure",
                risk_level="medium",
                payloads=[
                    {"username": "admin", "password": "wrongpassword"},
                    {"username": "nonexistent_user_12345", "password": "wrongpassword"}
                ]
            )
        ],
        FlowType.E_COMMERCE: [
            SecurityTest(
                name="Price Manipulation",
                description="Test for price tampering in hidden fields",
                category="business_logic",
                risk_level="critical",
                payloads=[
                    {"price": "0", "quantity": "1"},
                    {"price": "-100", "quantity": "1"},
                    {"price": "0.01", "quantity": "1000"}
                ]
            ),
            SecurityTest(
                name="Quantity Overflow",
                description="Test for integer overflow in quantity",
                category="business_logic",
                risk_level="high",
                payloads=[
                    {"quantity": "99999999"},
                    {"quantity": "-1"},
                    {"quantity": "0"}
                ]
            ),
            SecurityTest(
                name="Coupon Code Abuse",
                description="Test for coupon/promo code vulnerabilities",
                category="business_logic",
                risk_level="medium",
                payloads=[
                    {"coupon": "' OR '1'='1"},
                    {"coupon": "TEST"},
                    {"coupon": "ADMIN"}
                ]
            ),
            SecurityTest(
                name="Race Condition",
                description="Test for race conditions in checkout",
                category="race_condition",
                risk_level="high",
                payloads=[]
            )
        ],
        FlowType.PAYMENT: [
            SecurityTest(
                name="Card Number Validation Bypass",
                description="Test for client-side only validation",
                category="input_validation",
                risk_level="critical",
                payloads=[]
            ),
            SecurityTest(
                name="Amount Manipulation",
                description="Test for payment amount tampering",
                category="business_logic",
                risk_level="critical",
                payloads=[]
            ),
            SecurityTest(
                name="Currency Manipulation",
                description="Test for currency conversion bypass",
                category="business_logic",
                risk_level="high",
                payloads=[]
            )
        ],
        FlowType.ADMIN_PANEL: [
            SecurityTest(
                name="Authorization Bypass",
                description="Test for horizontal/vertical privilege escalation",
                category="authorization",
                risk_level="critical",
                payloads=[]
            ),
            SecurityTest(
                name="IDOR (Insecure Direct Object Reference)",
                description="Test for access to other users' resources",
                category="authorization",
                risk_level="high",
                payloads=[]
            ),
            SecurityTest(
                name="Path Traversal",
                description="Test for directory traversal in admin functions",
                category="path_traversal",
                risk_level="high",
                payloads=[
                    {"file": "../../../etc/passwd"},
                    {"path": "..\\..\\..\\windows\\system32\\config\\sam"}
                ]
            )
        ],
        FlowType.FILE_UPLOAD: [
            SecurityTest(
                name="Unrestricted File Upload",
                description="Test for malicious file upload",
                category="file_upload",
                risk_level="critical",
                payloads=[]
            ),
            SecurityTest(
                name="Extension Bypass",
                description="Test for file extension validation bypass",
                category="file_upload",
                risk_level="high",
                payloads=[]
            ),
            SecurityTest(
                name="Content-Type Bypass",
                description="Test for MIME type validation bypass",
                category="file_upload",
                risk_level="high",
                payloads=[]
            )
        ],
        FlowType.SEARCH: [
            SecurityTest(
                name="SQL Injection - Search",
                description="Test for SQL injection in search",
                category="injection",
                risk_level="high",
                payloads=[
                    {"q": "' OR '1'='1"},
                    {"q": "1; DROP TABLE users--"},
                    {"q": "' UNION SELECT * FROM users--"}
                ]
            ),
            SecurityTest(
                name="XSS - Reflected",
                description="Test for reflected XSS in search results",
                category="xss",
                risk_level="high",
                payloads=[
                    {"q": "<script>alert('XSS')</script>"},
                    {"q": "<img src=x onerror=alert('XSS')>"},
                    {"q": "javascript:alert('XSS')"}
                ]
            ),
            SecurityTest(
                name="LDAP Injection",
                description="Test for LDAP injection in search",
                category="injection",
                risk_level="medium",
                payloads=[
                    {"q": "*)(uid=*))(|(uid=*"},
                    {"q": "admin)(|(password=*"}
                ]
            )
        ],
        FlowType.API_ENDPOINT: [
            SecurityTest(
                name="API Authentication Bypass",
                description="Test for missing authentication on API endpoints",
                category="authorization",
                risk_level="critical",
                payloads=[]
            ),
            SecurityTest(
                name="Mass Assignment",
                description="Test for mass assignment vulnerabilities",
                category="mass_assignment",
                risk_level="high",
                payloads=[]
            ),
            SecurityTest(
                name="Rate Limiting",
                description="Test for API rate limiting",
                category="dos",
                risk_level="medium",
                payloads=[]
            ),
            SecurityTest(
                name="JSON Injection",
                description="Test for JSON injection in API",
                category="injection",
                risk_level="high",
                payloads=[]
            )
        ],
        FlowType.REGISTRATION: [
            SecurityTest(
                name="Email Verification Bypass",
                description="Test for email verification bypass",
                category="auth_bypass",
                risk_level="medium",
                payloads=[]
            ),
            SecurityTest(
                name="Weak Password Policy",
                description="Test password policy enforcement",
                category="auth_policy",
                risk_level="medium",
                payloads=[
                    {"password": "123"},
                    {"password": "password"},
                    {"password": "a"}
                ]
            ),
            SecurityTest(
                name="Mass Registration",
                description="Test for registration rate limiting",
                category="dos",
                risk_level="low",
                payloads=[]
            )
        ],
        FlowType.PASSWORD_RESET: [
            SecurityTest(
                name="Reset Token Prediction",
                description="Test for predictable reset tokens",
                category="auth_bypass",
                risk_level="critical",
                payloads=[]
            ),
            SecurityTest(
                name="Host Header Injection",
                description="Test for host header injection in reset emails",
                category="injection",
                risk_level="high",
                payloads=[]
            ),
            SecurityTest(
                name="Token Reuse",
                description="Test if reset tokens can be reused",
                category="auth_bypass",
                risk_level="medium",
                payloads=[]
            )
        ]
    }

    def __init__(self):
        pass

    def detect_flows(self, url: str, html: str) -> List[BusinessFlow]:
        """
        Detect business flows in a web page.

        Args:
            url: Page URL
            html: HTML content

        Returns:
            List of detected BusinessFlow objects
        """
        flows = []
        soup = BeautifulSoup(html, 'html.parser')
        html_lower = html.lower()
        url_lower = url.lower()

        # Extract forms
        forms = self._extract_forms(soup)

        # Check each flow type
        for flow_type, pattern in self.FLOW_PATTERNS.items():
            confidence, indicators = self._calculate_confidence(
                url_lower, html_lower, forms, pattern
            )

            if confidence >= pattern.get('min_confidence', 0.5):
                # Find relevant forms
                relevant_forms = self._get_relevant_forms(forms, pattern)

                flow = BusinessFlow(
                    flow_type=flow_type,
                    priority=pattern['priority'],
                    url=url,
                    confidence=confidence,
                    forms=relevant_forms,
                    indicators=indicators,
                    suggested_tests=[t.name for t in self.TEST_TEMPLATES.get(flow_type, [])]
                )

                flows.append(flow)

        # Sort by priority and confidence
        flows.sort(key=lambda f: (f.priority.value, -f.confidence))

        return flows

    def suggest_tests(self, flow: BusinessFlow) -> List[SecurityTest]:
        """
        Suggest security tests for a business flow.

        Args:
            flow: Detected business flow

        Returns:
            List of SecurityTest objects
        """
        return self.TEST_TEMPLATES.get(flow.flow_type, [])

    def get_test_payloads(self, flow: BusinessFlow) -> Dict[str, List[Dict[str, str]]]:
        """
        Get test payloads organized by form field.

        Args:
            flow: Detected business flow

        Returns:
            Dictionary mapping field names to test payloads
        """
        payloads = {}
        tests = self.suggest_tests(flow)

        for test in tests:
            for payload in test.payloads:
                for field_name, value in payload.items():
                    if field_name not in payloads:
                        payloads[field_name] = []
                    if {'value': value, 'test': test.name} not in payloads[field_name]:
                        payloads[field_name].append({
                            'value': value,
                            'test': test.name,
                            'category': test.category,
                            'risk': test.risk_level
                        })

        return payloads

    def _extract_forms(self, soup: BeautifulSoup) -> List[DetectedForm]:
        """Extract all forms from HTML."""
        forms = []

        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()

            # Extract fields
            fields = []
            for inp in form.find_all(['input', 'select', 'textarea']):
                name = inp.get('name', '')
                if not name:
                    continue

                field = FormField(
                    name=name,
                    field_type=inp.get('type', 'text'),
                    value=inp.get('value', ''),
                    is_required=inp.has_attr('required'),
                    placeholder=inp.get('placeholder', ''),
                    pattern=inp.get('pattern', '')
                )
                fields.append(field)

            # Get submit button text
            submit_text = ""
            submit_btn = form.find(['button', 'input'], type='submit')
            if submit_btn:
                submit_text = submit_btn.get_text(strip=True) or submit_btn.get('value', '')

            detected_form = DetectedForm(
                action=action,
                method=method,
                fields=fields,
                submit_text=submit_text,
                form_id=form.get('id', ''),
                form_class=' '.join(form.get('class', []))
            )
            forms.append(detected_form)

        return forms

    def _calculate_confidence(
        self,
        url_lower: str,
        html_lower: str,
        forms: List[DetectedForm],
        pattern: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """Calculate confidence score for a flow type."""
        score = 0.0
        max_score = 0.0
        indicators = []

        # URL keywords (weight: 0.3)
        url_keywords = pattern.get('url_keywords', [])
        if url_keywords:
            max_score += 0.3
            for keyword in url_keywords:
                if keyword in url_lower:
                    score += 0.3 / len(url_keywords)
                    indicators.append(f"URL contains '{keyword}'")

        # Content keywords (weight: 0.3)
        content_keywords = pattern.get('content_keywords', [])
        if content_keywords:
            max_score += 0.3
            matches = sum(1 for kw in content_keywords if kw in html_lower)
            if matches:
                score += min(0.3, 0.3 * matches / len(content_keywords))
                indicators.append(f"Content matches {matches} keywords")

        # Form fields (weight: 0.3)
        form_fields = pattern.get('form_fields', [])
        if form_fields:
            max_score += 0.3
            all_field_names = set()
            for form in forms:
                for field in form.fields:
                    all_field_names.add(field.name.lower())

            matches = sum(1 for ff in form_fields if any(ff in fn for fn in all_field_names))
            if matches:
                score += min(0.3, 0.3 * matches / len(form_fields))
                indicators.append(f"Form fields match {matches} patterns")

        # Submit button text (weight: 0.1)
        submit_keywords = pattern.get('submit_keywords', [])
        if submit_keywords:
            max_score += 0.1
            for form in forms:
                submit_lower = form.submit_text.lower()
                for kw in submit_keywords:
                    if kw in submit_lower:
                        score += 0.1
                        indicators.append(f"Submit button: '{form.submit_text}'")
                        break

        # Normalize to 0-1
        confidence = score / max_score if max_score > 0 else 0
        return confidence, indicators

    def _get_relevant_forms(
        self,
        forms: List[DetectedForm],
        pattern: Dict[str, Any]
    ) -> List[DetectedForm]:
        """Get forms relevant to a flow pattern."""
        relevant = []
        form_fields = pattern.get('form_fields', [])

        for form in forms:
            field_names = [f.name.lower() for f in form.fields]

            # Check if any pattern field matches
            for pattern_field in form_fields:
                if any(pattern_field in fn for fn in field_names):
                    relevant.append(form)
                    break

        return relevant


# Example usage
if __name__ == "__main__":
    detector = BusinessFlowDetector()

    # Test HTML
    html = """
    <html>
    <body>
        <h1>Login to Your Account</h1>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <a href="/forgot-password">Forgot Password?</a>
    </body>
    </html>
    """

    flows = detector.detect_flows("https://example.com/login", html)

    print("Detected Flows:")
    for flow in flows:
        print(f"\n  Type: {flow.flow_type.value}")
        print(f"  Priority: {flow.priority.name}")
        print(f"  Confidence: {flow.confidence:.2f}")
        print(f"  Indicators: {flow.indicators}")
        print(f"  Suggested Tests: {flow.suggested_tests}")

        tests = detector.suggest_tests(flow)
        print(f"\n  Detailed Tests:")
        for test in tests[:3]:
            print(f"    - {test.name} [{test.risk_level}]")
            print(f"      {test.description}")
            if test.payloads:
                print(f"      Sample payloads: {test.payloads[:2]}")
