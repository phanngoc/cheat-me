# Quick Reference Guide - Security Rules

## Rule ID Format

- **RF-XXX**: Request Filtering (Thinking Phase)
- **DD-XXX**: Directory Discovery (Deep Discovery Phase)
- **AS-XXX**: Authentication & Session Management
- **SE-XXX**: Sensitive Data Exposure
- **SM-XXX**: Security Misconfiguration
- **CF-XXX**: Cryptographic Failures
- **ID-XXX**: Information Disclosure

## Quick Lookup Table

| Rule ID | Name | Severity | OWASP | CWE |
|---------|------|----------|-------|-----|
| **Thinking Phase** |
| RF-001 | Sensitive URL Keywords | MEDIUM | A01:2025 | - |
| RF-002 | Suspicious HTTP Methods | MEDIUM | A01:2025 | - |
| RF-003 | Suspicious Status Codes | HIGH | A01:2025, A05:2025 | - |
| RF-004 | Static Asset Exclusion | INFO | - | - |
| **Discovery Phase** |
| DD-001 | Administrative Directories | HIGH | A01:2025 | - |
| DD-002 | API Versioning Directories | MEDIUM | A01:2025 | - |
| DD-003 | Configuration & Sensitive Folders | CRITICAL | A02:2025 | - |
| **Analysis Phase - Authentication** |
| AS-001 | Bearer Token in Authorization Header | INFO | A07:2025 | - |
| AS-002 | Insecure Cookie - Missing Secure Flag | HIGH | A07:2025, A04:2025 | CWE-614 |
| **Analysis Phase - Sensitive Data** |
| SE-001 | Sensitive Parameters in Query String | HIGH | A04:2025 | CWE-598 |
| SE-002 | Credentials in Request Body | WARNING | A04:2025 | CWE-319 |
| SE-003 | AWS Credentials in Response | CRITICAL | A04:2025 | CWE-522 |
| SE-004 | JWT Token in Response Body | INFO | A07:2025 | - |
| **Analysis Phase - Misconfiguration** |
| SM-001 | Server Information Disclosure | INFO | A05:2025 | CWE-200 |
| SM-002 | Technology Stack Disclosure | INFO | A05:2025 | CWE-200 |
| **Analysis Phase - Cryptography** |
| CF-001 | Missing HSTS Header | HIGH | A04:2025 | CWE-523 |
| CF-002 | Missing Content Security Policy | MEDIUM | A04:2025 | CWE-693 |
| CF-003 | Missing X-Content-Type-Options | MEDIUM | A04:2025 | CWE-693 |
| CF-004 | Missing X-Frame-Options | MEDIUM | A04:2025 | CWE-1021 |
| CF-005 | Cookie Missing HttpOnly Flag | HIGH | A04:2025 | CWE-1004 |
| CF-006 | Cookie Missing SameSite Attribute | MEDIUM | A04:2025 | CWE-352 |
| **Analysis Phase - Information** |
| ID-001 | Directory Listing Enabled | MEDIUM | A05:2025 | CWE-548 |
| ID-002 | Error Messages with Stack Traces | MEDIUM | A10:2025 | CWE-209 |

## Severity Prioritization

### CRITICAL (Immediate Action Required)
- SE-003: AWS Credentials in Response
- DD-003: Configuration & Sensitive Folders

### HIGH (Urgent - Fix Within 24-48 Hours)
- AS-002: Insecure Cookie - Missing Secure Flag
- SE-001: Sensitive Parameters in Query String
- RF-003: Suspicious Status Codes
- DD-001: Administrative Directories
- CF-001: Missing HSTS Header
- CF-005: Cookie Missing HttpOnly Flag

### MEDIUM (Fix Within 1 Week)
- RF-001: Sensitive URL Keywords
- RF-002: Suspicious HTTP Methods
- DD-002: API Versioning Directories
- CF-002: Missing Content Security Policy
- CF-003: Missing X-Content-Type-Options
- CF-004: Missing X-Frame-Options
- CF-006: Cookie Missing SameSite Attribute
- ID-001: Directory Listing Enabled
- ID-002: Error Messages with Stack Traces

### WARNING (Review & Verify)
- SE-002: Credentials in Request Body

### INFO (Informational - Track & Monitor)
- AS-001: Bearer Token in Authorization Header
- SE-004: JWT Token in Response Body
- SM-001: Server Information Disclosure
- SM-002: Technology Stack Disclosure
- RF-004: Static Asset Exclusion

## Common Remediation Actions

### For Cookies (AS-002)
```http
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=3600
```

### For HSTS (CF-001)
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### For Sensitive Parameters (SE-001)
- Use POST requests instead of GET
- Move sensitive data to request headers or body
- Implement proper session management

### For Server Info Disclosure (SM-001, SM-002)
**Nginx:**
```nginx
server_tokens off;
more_clear_headers 'Server' 'X-Powered-By';
```

**Apache:**
```apache
ServerTokens Prod
ServerSignature Off
Header unset X-Powered-By
```

**PHP:**
```ini
expose_php = Off
```

### For AWS Credentials (SE-003)
1. Immediately rotate all exposed credentials
2. Use AWS Secrets Manager or Parameter Store
3. Implement AWS IAM roles instead of hardcoded keys
4. Enable AWS CloudTrail for monitoring
5. Set up budget alerts for unauthorized usage

### Security Headers (CF-001 to CF-004)

**All Headers Combined (Recommended):**
```http
# HSTS (CF-001)
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# CSP (CF-002)
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:

# MIME Sniffing (CF-003)
X-Content-Type-Options: nosniff

# Clickjacking (CF-004)
X-Frame-Options: DENY
```

**Nginx Config:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
```

**Apache Config:**
```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set Content-Security-Policy "default-src 'self'"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
```

### Cookie Security (CF-005, CF-006, AS-002)

**Complete Secure Cookie:**
```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict; Max-Age=3600; Path=/
```

**Breakdown:**
- `HttpOnly` (CF-005) - Prevents JavaScript access
- `Secure` (AS-002) - HTTPS only
- `SameSite=Strict` (CF-006) - CSRF protection
- `Max-Age` - Expiration time
- `Path=/` - Scope restriction

**PHP:**
```php
setcookie('sessionid', $value, [
    'expires' => time() + 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

**Express.js:**
```javascript
res.cookie('sessionid', value, {
  maxAge: 3600000,
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});
```

**Django:**
```python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 3600
```

## OWASP Top 10 2025 Mapping

- **A01:2025** - Broken Access Control: RF-001, RF-002, RF-003, DD-001, DD-002
- **A02:2025** - Security Misconfiguration: DD-003, SM-001, SM-002, ID-001
- **A04:2025** - Cryptographic Failures: AS-002, SE-001, SE-002, SE-003, CF-001, CF-002
- **A05:2025** - Injection: RF-003
- **A07:2025** - Authentication Failures: AS-001, AS-002, SE-004
- **A10:2025** - Mishandling of Exceptional Conditions: ID-002

## CWE Mapping

- **CWE-200**: Exposure of Sensitive Information (SM-001, SM-002)
- **CWE-209**: Generation of Error Message Containing Sensitive Information (ID-002)
- **CWE-319**: Cleartext Transmission of Sensitive Information (SE-002)
- **CWE-352**: Cross-Site Request Forgery (CF-006)
- **CWE-522**: Insufficiently Protected Credentials (SE-003)
- **CWE-523**: Unprotected Transport of Credentials (CF-001)
- **CWE-548**: Information Exposure Through Directory Listing (ID-001)
- **CWE-598**: Use of GET Request Method With Sensitive Query Strings (SE-001)
- **CWE-614**: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute (AS-002)
- **CWE-693**: Protection Mechanism Failure (CF-002, CF-003)
- **CWE-1004**: Sensitive Cookie Without 'HttpOnly' Flag (CF-005)
- **CWE-1021**: Improper Restriction of Rendered UI Layers (CF-004)

## Output Format

When the agent detects a vulnerability, the output format is:

```
[SEVERITY] [RULE_ID] [CATEGORY] Description (Request ID: XXX)
    └─ OWASP: AXX:2025 | CWE: CWE-XXX
```

**Example:**
```
[CRITICAL] [SE-003] [Sensitive Data Exposure] AWS Access Key ID detected in response body (Request ID: 42 | URL: http://example.com/api/config)
    └─ OWASP: A04:2025 | CWE: CWE-522
```

## Using the Documentation

1. **For Developers**: Reference rule IDs when fixing issues in code
2. **For Security Teams**: Use rule IDs in bug tracking systems (JIRA, GitHub Issues)
3. **For Compliance**: Map OWASP/CWE references to compliance requirements
4. **For Reporting**: Include rule IDs in security assessment reports

## Related Files

- **Full Documentation**: `docs/security-rules.md`
- **Configuration**: `agent_rules.yaml`
- **Implementation**: `agent_orchestrator.py`
