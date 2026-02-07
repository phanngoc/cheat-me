# Testing New Rule-Based Architecture

## Quick Test Guide

### 1. View Current Rules

```bash
cd /Users/ngocp/Documents/projects/pen-testing
python3 -c "
import yaml
with open('cheat-me/agent_rules.yaml') as f:
    config = yaml.safe_load(f)
    rules = config['rules']
    
print(f'Total Rules: {len(rules)}')
print(f'Enabled: {sum(1 for r in rules.values() if r.get(\"enabled\", True))}')
print()

for phase in ['thinking', 'discovery', 'analysis']:
    phase_rules = [r for r in rules.items() if r[1].get('phase') == phase and r[1].get('enabled', True)]
    print(f'{phase.upper()}: {len(phase_rules)} rules')
    for rule_id, rule in phase_rules:
        print(f'  • {rule_id}: {rule[\"name\"]} ({rule[\"severity\"]})')
"
```

### 2. Test Enabling/Disabling Rules

**Disable a rule:**
```yaml
# In agent_rules.yaml
RF-004:
  name: "Static Asset Exclusion"
  enabled: false  # <-- Change this
```

**Run again:**
```bash
python3 cheat-me/agent_orchestrator.py
# Output will show: Loaded 15 rules (14 enabled)
```

### 3. Add a Custom Rule

**Example: Detect API Keys in Response**

Add to `agent_rules.yaml`:
```yaml
  SE-005:
    name: "API Key in Response"
    enabled: true
    phase: analysis
    category: "Sensitive Data Exposure"
    severity: HIGH
    owasp: "A04:2025"
    description: "Detects various API key patterns in response"
    detection:
      type: response_body
      contains:
        - api_key
        - apikey
        - x-api-key
    message: "API key potentially exposed in response body"
```

**Test:**
```bash
python3 cheat-me/agent_orchestrator.py
# Will show: Loaded 16 rules (16 enabled)
```

### 4. Create Custom Rule for Your Environment

**Example: Detect Internal Headers**

```yaml
  SM-003:
    name: "Internal Header Disclosure"
    enabled: true
    phase: analysis
    category: "Information Disclosure"
    severity: MEDIUM
    owasp: "A05:2025"
    description: "Detects internal/debug headers"
    detection:
      type: response_header
      header_name: x-internal-user
      exists: true
    message: "Internal header exposed: {value}"
```

### 5. Test with Different Severities

Rules are sorted by severity:
- 🔴 CRITICAL (shows first)
- 🟠 HIGH
- 🟡 WARNING
- 🔵 INFO (shows last)

### 6. View Rule Documentation

```bash
# Quick reference
cat cheat-me/docs/rules-quick-reference.md

# Full documentation
cat cheat-me/docs/security-rules.md

# Architecture
cat cheat-me/docs/ARCHITECTURE.md
```

## Example Output

When rules match, you'll see:

```
[*] Phase 2: Thinking - Applying detection rules...
[*]   [+] Flagged by [RF-001, RF-002]: ID 42 | POST | 200 | /admin/login
[*]   [+] Flagged by [RF-003]: ID 43 | GET | 500 | /api/users
[*] Total suspicious requests to inspect: 2

[*] Phase 4: Analysis - Applying security detection rules...

📊 FINDINGS SUMMARY
--------------------------------------------------------------------------------
Total Findings: 3
  🔴 CRITICAL: 1
  🟠 HIGH: 1
  🔵 INFO: 1

📋 Findings by Rule:
  AS-002: 1 (Insecure Cookie - Missing Secure Flag)
  SE-003: 1 (AWS Credentials in Response)
  SM-001: 1 (Server Information Disclosure)

🏷️  Findings by Category:
  Information Disclosure: 1
  Sensitive Data Exposure: 1
  Session Management: 1

================================================================================
🔍 DETAILED FINDINGS
================================================================================

[CRITICAL] [SE-003] [Sensitive Data Exposure] AWS Access Key ID detected in response body (Request ID: 42 | URL: http://example.com/api/config)
    └─ OWASP: A04:2025 | CWE: CWE-522 | Fix: Rotate credentials immediately, use AWS Secrets Manager

[HIGH] [AS-002] [Session Management] Insecure cookie detected (missing Secure flag) (Request ID: 43)
    └─ OWASP: A07:2025 | CWE: CWE-614 | Fix: Add Secure; HttpOnly; SameSite=Strict attributes

[INFO] [SM-001] [Information Disclosure] Server version disclosed: nginx/1.18.0 (Request ID: 44)

================================================================================
📄 Documentation: docs/security-rules.md
⚙️  Configuration: agent_rules.yaml (15 rules enabled)
================================================================================
```

## Rule Development Workflow

### 1. Identify Security Pattern

Example: You notice apps leaking database errors

### 2. Research

- What's the OWASP category? **A05:2025 - Security Misconfiguration**
- What's the CWE? **CWE-209 - Error Message Information Leakage**
- What's the severity? **MEDIUM** (info disclosure, not direct compromise)

### 3. Create Rule

```yaml
  ID-001:
    name: "Database Error Disclosure"
    enabled: true
    phase: analysis
    category: "Information Disclosure"
    severity: MEDIUM
    owasp: "A05:2025"
    cwe: "CWE-209"
    description: "Detects database error messages in responses"
    detection:
      type: response_body
      contains:
        - "sql syntax"
        - "mysql error"
        - "postgresql error"
        - "ora-"  # Oracle
        - "syntax error at"
    message: "Database error message leaked in response"
    remediation: "Implement custom error pages, log details server-side only"
```

### 4. Test

```bash
python3 cheat-me/agent_orchestrator.py
```

### 5. Document

Add to `docs/security-rules.md`:

```markdown
#### ID-001: Database Error Disclosure
**Category:** Information Disclosure  
**OWASP Mapping:** A05:2025 - Security Misconfiguration  
**Severity:** MEDIUM  
**CWE:** CWE-209  

**Description:** Detects database error messages leaked in HTTP responses.

**Impact:**
- Reveals database type and version
- Exposes SQL query structure
- Assists in SQL injection attacks
- Shows internal file paths

**Remediation:**
```python
# Django
DEBUG = False

# Express.js
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong');
});
```
```

### 6. Share

Commit to version control:
```bash
git add agent_rules.yaml docs/security-rules.md
git commit -m "Add ID-001: Database Error Disclosure rule"
```

## Performance Tips

### For Large Scans

If you have thousands of requests, optimize by:

1. **Disable INFO-level rules during initial scan**
   ```yaml
   SM-001:
     enabled: false
   SM-002:
     enabled: false
   ```

2. **Focus on high-severity first**
   - Enable only CRITICAL and HIGH rules
   - Run initial scan
   - Fix critical issues
   - Re-enable all rules

3. **Use rule phases efficiently**
   - Thinking phase filters first (fast)
   - Discovery phase explores structure (medium)
   - Analysis phase deep-dives (slow)

### For CI/CD Integration

Create environment-specific configs:

**agent_rules.production.yaml**
```yaml
# Only CRITICAL and HIGH for prod
rules:
  SE-003:
    enabled: true
    severity: CRITICAL
  # ... only critical rules
```

**agent_rules.staging.yaml**
```yaml
# All rules for staging
rules:
  # ... all rules enabled
```

Run with:
```bash
python3 -c "
import sys
sys.argv = ['', '--rules', 'agent_rules.production.yaml']
" agent_orchestrator.py
```

## Troubleshooting

### Rule Not Matching

1. **Check if enabled**
   ```yaml
   enabled: true  # <-- Must be true
   ```

2. **Check phase**
   ```yaml
   phase: analysis  # Must match where it's used
   ```

3. **Check detection type**
   - `url_contains` - for URL text
   - `http_method` - for methods (POST, GET, etc.)
   - `response_body` - for response content
   - etc.

4. **Check patterns are lowercase**
   - All checks are case-insensitive by default
   - Patterns should be lowercase

### Rule Matching Too Much

1. **Make patterns more specific**
   ```yaml
   # Too broad
   patterns: [key]
   
   # Better
   patterns: [api_key, secret_key]
   ```

2. **Add exclusions** (for thinking phase)
   ```yaml
   RF-004:
     detection:
       type: url_extension
       exclude: true  # Exclude these patterns
   ```

3. **Increase severity threshold**
   - Change INFO to WARNING
   - Focus on actionable findings

## Best Practices

1. **Start with framework defaults**
   - Use provided rules as templates
   - Customize for your environment

2. **Test rules incrementally**
   - Add one rule at a time
   - Verify it works before adding more

3. **Document custom rules**
   - Add to `docs/security-rules.md`
   - Include remediation guidance

4. **Version control everything**
   - Track rule changes
   - Document why rules were added/changed

5. **Regular review**
   - Quarterly rule effectiveness review
   - Remove rules that generate false positives
   - Add rules for new vulnerabilities

## Need Help?

- **Rule syntax**: See `agent_rules.yaml` examples
- **Detection types**: Check `REFACTORING_V2.md`
- **OWASP mapping**: Visit [owasp.org/Top10](https://owasp.org/Top10/)
- **CWE reference**: Visit [cwe.mitre.org](https://cwe.mitre.org/)
