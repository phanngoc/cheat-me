# Testing CF Rules - Example Scenarios

## Quick Verification

Check if CF rules are loaded:

```bash
python3 -c "
import yaml
with open('cheat-me/agent_rules.yaml') as f:
    config = yaml.safe_load(f)
    cf_rules = {k: v for k, v in config['rules'].items() if k.startswith('CF-')}
    
print(f'Cryptographic Failures Rules: {len(cf_rules)}')
print()

for rule_id, rule in sorted(cf_rules.items()):
    status = '✓ ENABLED' if rule.get('enabled') else '✗ DISABLED'
    print(f'{status} | {rule_id}: {rule[\"name\"]} ({rule[\"severity\"]})')
"
```

**Expected Output:**
```
Cryptographic Failures Rules: 6

✓ ENABLED | CF-001: Missing HSTS Header (HIGH)
✓ ENABLED | CF-002: Missing Content Security Policy (MEDIUM)
✓ ENABLED | CF-003: Missing X-Content-Type-Options (MEDIUM)
✓ ENABLED | CF-004: Missing X-Frame-Options (MEDIUM)
✓ ENABLED | CF-005: Cookie Missing HttpOnly Flag (HIGH)
✓ ENABLED | CF-006: Cookie Missing SameSite Attribute (MEDIUM)
```

## Example: What CF Rules Detect

### Scenario 1: Missing HSTS (CF-001)

**Vulnerable Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html
# No Strict-Transport-Security header
```

**Detection:** ✅ CF-001 will flag this

**Finding:**
```
[HIGH] [CF-001] [Cryptographic Failures] HSTS header not set - site vulnerable to SSL stripping (Request ID: 42)
    └─ OWASP: A04:2025 | CWE: CWE-523 | Fix: Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

### Scenario 2: Missing CSP (CF-002)

**Vulnerable Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html
# No Content-Security-Policy header
```

**Detection:** ✅ CF-002 will flag this

**Finding:**
```
[MEDIUM] [CF-002] [Cryptographic Failures] CSP header not set - vulnerable to XSS and data injection (Request ID: 43)
```

---

### Scenario 3: Insecure Cookie (CF-005, CF-006, AS-002)

**Vulnerable Response:**
```http
HTTP/1.1 200 OK
Set-Cookie: sessionid=abc123; Path=/
# Missing: HttpOnly, Secure, SameSite
```

**Detection:** ✅ CF-005, CF-006, AS-002 will all flag this

**Findings:**
```
[HIGH] [AS-002] [Session Management] Insecure cookie detected (missing Secure flag) (Request ID: 44)
    └─ OWASP: A07:2025 | CWE: CWE-614 | Fix: Add Secure; HttpOnly; SameSite=Strict attributes

[HIGH] [CF-005] [Cryptographic Failures] Cookie missing HttpOnly flag - vulnerable to XSS theft (Request ID: 44)
    └─ OWASP: A04:2025 | CWE: CWE-1004 | Fix: Add HttpOnly flag to all session cookies

[MEDIUM] [CF-006] [Cryptographic Failures] Cookie missing SameSite attribute - vulnerable to CSRF (Request ID: 44)
```

---

### Scenario 4: Complete Secure Response

**Secure Response:**
```http
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict; Path=/
```

**Detection:** ✅ No findings - all security headers present!

---

## Real-World Testing

### Test Against Public Website

**Disclaimer:** Only test websites you own or have permission to test.

```python
# Manual test example
import requests

response = requests.get('https://example.com')

# Check HSTS
hsts = response.headers.get('Strict-Transport-Security')
print(f"HSTS: {hsts if hsts else '❌ MISSING (CF-001)'}")

# Check CSP
csp = response.headers.get('Content-Security-Policy')
print(f"CSP: {csp if csp else '❌ MISSING (CF-002)'}")

# Check X-Content-Type-Options
nosniff = response.headers.get('X-Content-Type-Options')
print(f"X-Content-Type-Options: {nosniff if nosniff else '❌ MISSING (CF-003)'}")

# Check X-Frame-Options
xframe = response.headers.get('X-Frame-Options')
print(f"X-Frame-Options: {xframe if xframe else '❌ MISSING (CF-004)'}")

# Check Set-Cookie
cookies = response.headers.get('Set-Cookie', '')
if cookies:
    has_httponly = 'httponly' in cookies.lower()
    has_samesite = 'samesite' in cookies.lower()
    has_secure = 'secure' in cookies.lower()
    
    print(f"Cookie HttpOnly: {'✓' if has_httponly else '❌ MISSING (CF-005)'}")
    print(f"Cookie SameSite: {'✓' if has_samesite else '❌ MISSING (CF-006)'}")
    print(f"Cookie Secure: {'✓' if has_secure else '❌ MISSING (AS-002)'}")
```

## Testing with Mock Data

If you want to test locally without actual traffic:

```python
# Create mock GraphQL responses for testing
mock_response = {
    "id": 1,
    "url": "https://example.com/",
    "method": "GET",
    "statusCode": 200,
    "requestHeaders": "{}",
    "requestQuery": "{}",
    "requestBody": None,
    "responseHeaders": json.dumps({
        "Content-Type": "text/html",
        # Missing all security headers - should trigger all CF rules
    }),
    "responseBody": base64.b64encode(b"<html>...</html>").decode(),
    "contentType": "text/html"
}
```

## Expected Detection Summary

When scanning a typical insecure website:

```
================================================================================
AGENT SECURITY REPORT (RULE-BASED DETECTION)
================================================================================

📊 FINDINGS SUMMARY
--------------------------------------------------------------------------------
Total Findings: 9

  🟠 HIGH: 4
    • CF-001: Missing HSTS Header
    • CF-005: Cookie Missing HttpOnly Flag
    • AS-002: Insecure Cookie - Missing Secure Flag
    • SE-001: Sensitive Parameters in Query String

  🟡 MEDIUM: 4
    • CF-002: Missing Content Security Policy
    • CF-003: Missing X-Content-Type-Options
    • CF-004: Missing X-Frame-Options
    • CF-006: Cookie Missing SameSite Attribute

  🔵 INFO: 1
    • SM-001: Server Information Disclosure

📋 Findings by Rule:
  AS-002: 2
  CF-001: 3
  CF-002: 3
  CF-003: 3
  CF-004: 3
  CF-005: 2
  CF-006: 2
  SE-001: 1
  SM-001: 3

🏷️  Findings by Category:
  Cryptographic Failures: 14
  Information Disclosure: 3
  Sensitive Data Exposure: 1
  Session Management: 2

================================================================================
🔍 DETAILED FINDINGS
================================================================================

[HIGH] [CF-001] [Cryptographic Failures] HSTS header not set - site vulnerable to SSL stripping (Request ID: 1)
    └─ OWASP: A04:2025 | CWE: CWE-523 | Fix: Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

[HIGH] [CF-005] [Cryptographic Failures] Cookie missing HttpOnly flag - vulnerable to XSS theft (Request ID: 1)
    └─ OWASP: A04:2025 | CWE: CWE-1004 | Fix: Add HttpOnly flag to all session cookies

[MEDIUM] [CF-002] [Cryptographic Failures] CSP header not set - vulnerable to XSS and data injection (Request ID: 1)

[MEDIUM] [CF-003] [Cryptographic Failures] X-Content-Type-Options not set - vulnerable to MIME sniffing (Request ID: 1)

...

================================================================================
📄 Documentation: docs/security-rules.md
⚙️  Configuration: agent_rules.yaml (21 rules enabled)
================================================================================
```

## Selective Testing

### Test Only CF Rules

Disable other rules to focus on CF:

```yaml
# In agent_rules.yaml
RF-001:
  enabled: false
RF-002:
  enabled: false
# ... disable others

CF-001:
  enabled: true  # Keep CF rules enabled
CF-002:
  enabled: true
# ... etc
```

Run:
```bash
python3 cheat-me/agent_orchestrator.py
# Will only show CF findings
```

### Test Specific Rule

```yaml
# Disable all except one
CF-001:
  enabled: true

CF-002:
  enabled: false
# ... etc
```

## Performance Note

CF rules are very efficient because they:
1. Only run in **analysis phase** (after filtering)
2. Simple header checks (no regex, no parsing)
3. Low false positive rate
4. Instant detection

**Typical performance:**
- 1000 requests scanned
- ~50 suspicious (after thinking/discovery)
- CF rules check 50 responses
- ~0.5 seconds for all CF checks

## Online Tools Comparison

Compare Agent Orchestrator findings with:

- **Mozilla Observatory:** https://observatory.mozilla.org/
- **Security Headers:** https://securityheaders.com/
- **SSL Labs:** https://www.ssllabs.com/ssltest/

Our CF rules detect the same issues as these industry-standard tools!

## Remediation Workflow

1. **Run scan:**
   ```bash
   python3 cheat-me/agent_orchestrator.py
   ```

2. **Identify CF findings** (HIGH/MEDIUM priority)

3. **Apply fixes** from documentation

4. **Re-run scan** to verify

5. **Should see:**
   ```
   Total Findings: 0  # or significantly reduced
   ```

## Success Criteria

✅ **Secure Configuration** when you see:
```
No CF-XXX findings
All security headers present
All cookie attributes set
```

❌ **Needs Attention** when you see:
```
CF-001, CF-005 = HIGH priority
Fix immediately
```

---

**Ready to scan?** Run the Agent Orchestrator and let the CF rules protect your application! 🛡️
