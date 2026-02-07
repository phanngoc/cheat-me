# Security Rules Documentation

This directory contains comprehensive documentation for the Agent Orchestrator's security scanning rules.

## 📚 Documentation Files

### 1. [security-rules.md](./security-rules.md)
**Comprehensive Rule Documentation**

The complete reference guide for all security rules with:
- Detailed descriptions for each rule
- OWASP Top 10 2025 mappings
- CWE (Common Weakness Enumeration) references
- Impact analysis and attack scenarios
- Remediation steps with code examples
- Links to external references

**Use this when you need:**
- Complete understanding of a specific vulnerability
- Step-by-step remediation guidance
- Security awareness training materials
- Compliance documentation

### 2. [rules-quick-reference.md](./rules-quick-reference.md)
**Quick Lookup Guide**

A condensed reference for rapid lookups:
- Rule ID lookup table
- Severity prioritization matrix
- Common remediation snippets
- OWASP and CWE cross-references
- Output format examples

**Use this when you need:**
- Quick rule ID lookup during incident response
- Severity assessment for prioritization
- Copy-paste remediation code snippets
- Fast OWASP/CWE mapping

## 🎯 Rule Categories

The rules are organized into the following categories:

### Request Filtering (RF)
Rules that identify suspicious requests during initial reconnaissance.
- **Count:** 4 rules
- **Examples:** RF-001 (Sensitive URL Keywords), RF-003 (Suspicious Status Codes)

### Directory Discovery (DD)
Rules for identifying high-value directories that warrant deeper inspection.
- **Count:** 3 rules
- **Examples:** DD-001 (Admin Directories), DD-003 (Config Folders)

### Authentication & Session (AS)
Rules detecting authentication and session management issues.
- **Count:** 2 rules
- **Examples:** AS-002 (Insecure Cookies)

### Sensitive Data Exposure (SE)
Rules identifying leaked credentials, keys, and sensitive information.
- **Count:** 4 rules
- **Examples:** SE-003 (AWS Credentials), SE-001 (Sensitive Query Params)

### Security Misconfiguration (SM)
Rules detecting configuration weaknesses and information disclosure.
- **Count:** 2 rules
- **Examples:** SM-001 (Server Info Disclosure)

### Cryptographic Failures (CF)
Rules identifying weak cryptography and transport security issues.
- **Count:** 2 rules
- **Examples:** CF-001 (Missing HSTS)

### Information Disclosure (ID)
Rules detecting unintentional information leakage.
- **Count:** 2 rules
- **Examples:** ID-002 (Error Stack Traces)

## 🔥 Severity Levels

| Level | Count | Description |
|-------|-------|-------------|
| CRITICAL | 3 | Immediate data breach or system compromise risk |
| HIGH | 5 | Significant security impact, urgent fixes required |
| MEDIUM | 5 | Moderate risk, should be addressed in sprint |
| WARNING | 1 | Potential issue requiring verification |
| INFO | 5 | Informational, helps understand app behavior |

## 🗺️ OWASP Top 10 2025 Coverage

The ruleset provides coverage for 6 out of 10 OWASP categories:

- ✅ **A01:2025** - Broken Access Control (7 rules)
- ✅ **A02:2025** - Security Misconfiguration (4 rules)
- ❌ **A03:2025** - Software Supply Chain Failures (0 rules)
- ✅ **A04:2025** - Cryptographic Failures (6 rules)
- ✅ **A05:2025** - Injection (1 rule)
- ❌ **A06:2025** - Insecure Design (0 rules)
- ✅ **A07:2025** - Authentication Failures (3 rules)
- ❌ **A08:2025** - Software/Data Integrity Failures (0 rules)
- ❌ **A09:2025** - Security Logging & Alerting Failures (0 rules)
- ✅ **A10:2025** - Mishandling of Exceptional Conditions (1 rule)

**Coverage: 60%** (6/10 categories)

## 🎓 Using This Documentation

### For Developers
```bash
# When you see a finding like:
# [HIGH] [SE-001] [Sensitive Data Exposure] ...

# 1. Look up SE-001 in rules-quick-reference.md for quick context
# 2. Read full details in security-rules.md
# 3. Apply the remediation code snippet
# 4. Test and verify the fix
```

### For Security Analysts
```bash
# During security assessment:
# 1. Run agent_orchestrator.py
# 2. Note rule IDs in findings
# 3. Reference security-rules.md for impact analysis
# 4. Document findings with rule IDs in report
# 5. Use OWASP/CWE mappings for compliance reporting
```

### For Management
The severity levels and OWASP mappings provide:
- **CRITICAL/HIGH**: Immediate resource allocation needed
- **MEDIUM**: Include in next sprint planning
- **INFO**: Track for security awareness and monitoring

## 📝 Contributing New Rules

When adding a new rule, ensure you:

1. **Assign a Rule ID**
   - Use appropriate prefix (RF, DD, AS, SE, SM, CF, ID)
   - Use next sequential number (e.g., SE-005)

2. **Update agent_rules.yaml**
   ```yaml
   - rule_id: SE-005
     name: "Rule Name"
     level: HIGH
     message: "Description"
     owasp: "A04:2025"
     cwe: "CWE-XXX"
     category: "Category Name"
   ```

3. **Document in security-rules.md**
   - Full description
   - Detection logic
   - Impact analysis
   - Remediation steps
   - References

4. **Add to rules-quick-reference.md**
   - Lookup table entry
   - Severity classification
   - Remediation snippet if applicable

## 🔗 See Also

- [OWASP Top 10 2025](https://owasp.org/Top10/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

---

**Version:** 1.0.0  
**Last Updated:** 2026-02-07  
**Rule Count:** 19 active rules
