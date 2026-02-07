import requests
import json
import base64
import re
import yaml
from pathlib import Path
from typing import List, Dict, Any

GRAPHQL_URL = "http://localhost:8085/graphql"

class AgentOrchestrator:
    def __init__(self, url=GRAPHQL_URL, rules_path="agent_rules.yaml"):
        self.url = url
        self.suspicious_ids = []
        self.config = self.load_rules(rules_path)
        self.rules = self.config.get('rules', {})
        self.enabled_rules = {rule_id: rule for rule_id, rule in self.rules.items() if rule.get('enabled', True)}

    def log(self, message):
        print(f"[*] {message}")

    def load_rules(self, rules_path):
        """Load rules from YAML file with fallback to defaults if file missing."""
        try:
            path = Path(rules_path)
            if not path.is_absolute():
                path = Path(__file__).parent / rules_path
            
            if path.exists():
                with open(path, 'r') as f:
                    config = yaml.safe_load(f) or {}
                    self.log(f"Successfully loaded rules from {path}")
                    rule_count = len(config.get('rules', {}))
                    enabled_count = sum(1 for r in config.get('rules', {}).values() if r.get('enabled', True))
                    self.log(f"  Loaded {rule_count} rules ({enabled_count} enabled)")
                    return config
            else:
                self.log(f"Warning: Rules file not found at {path}. Using empty rules.")
                return {}
        except Exception as e:
            self.log(f"Error loading rules: {e}")
            return {}

    def get_rules_by_phase(self, phase: str) -> Dict[str, Any]:
        """Get all enabled rules for a specific phase."""
        return {
            rule_id: rule 
            for rule_id, rule in self.enabled_rules.items() 
            if rule.get('phase') == phase
        }

    def recon_phase(self):
        """Bước 1: Lấy danh sách nhẹ (Metadata) để sàng lọc"""
        self.log("Phase 1: Reconnaissance - Fetching request list...")
        query = """
        query {
          requests {
            id
            method
            statusCode
            url
          }
        }
        """
        response = requests.post(self.url, json={'query': query})
        if response.status_code == 200:
            return response.json()['data']['requests']
        return []

    def thinking_phase(self, all_requests):
        """Bước 2: Áp dụng các thinking rules để lọc requests nghi vấn"""
        self.log("Phase 2: Thinking - Applying detection rules...")
        
        thinking_rules = self.get_rules_by_phase('thinking')
        candidates = []
        matched_rules = {}  # Track which rules matched which requests
        
        for req in all_requests:
            url = req['url'].lower()
            method = req['method'].upper()
            status = req['statusCode']
            
            is_suspicious = False
            rules_matched = []
            
            for rule_id, rule in thinking_rules.items():
                detection = rule.get('detection', {})
                det_type = detection.get('type')
                
                # Kiểm tra từng loại detection
                if det_type == 'url_contains':
                    patterns = detection.get('patterns', [])
                    if any(pattern in url for pattern in patterns):
                        is_suspicious = True
                        rules_matched.append(rule_id)
                
                elif det_type == 'http_method':
                    patterns = detection.get('patterns', [])
                    if method in patterns:
                        is_suspicious = True
                        rules_matched.append(rule_id)
                
                elif det_type == 'status_code':
                    patterns = detection.get('patterns', [])
                    if status in patterns:
                        is_suspicious = True
                        rules_matched.append(rule_id)
                
                elif det_type == 'url_extension':
                    patterns = detection.get('patterns', [])
                    is_exclude = detection.get('exclude', False)
                    has_extension = any(url.endswith(ext) for ext in patterns)
                    
                    if is_exclude and has_extension:
                        # Loại bỏ request này
                        is_suspicious = False
                        rules_matched = []
                        break  # Skip this request entirely
            
            if is_suspicious and rules_matched:
                candidates.append(req['id'])
                matched_rules[req['id']] = rules_matched
                rules_str = ', '.join(rules_matched)
                self.log(f"  [+] Flagged by [{rules_str}]: ID {req['id']} | {method} | {status} | {url[:60]}")
        
        self.suspicious_ids = list(set(candidates))
        self.log(f"Total suspicious requests to inspect: {len(self.suspicious_ids)}")

    def deep_discovery_phase(self):
        """Bước 1.5: Áp dụng discovery rules để tìm folders nghi vấn"""
        self.log("Phase 1.5: Deep Discovery - Applying discovery rules...")
        
        discovery_rules = self.get_rules_by_phase('discovery')
        if not discovery_rules:
            return []
        
        # Lấy danh sách sitemap
        query_roots = """
        query {
          sitemapEntries {
            id
            kind
            label
          }
        }
        """
        response = requests.post(self.url, json={'query': query_roots})
        if response.status_code != 200:
            return []
            
        roots = response.json()['data']['sitemapEntries']
        suspicious_folder_ids = []
        matched_rules = {}
        
        for entry in roots:
            if entry['kind'] != 'DIRECTORY':
                continue
            
            label_lower = entry['label'].lower()
            rules_matched = []
            
            for rule_id, rule in discovery_rules.items():
                detection = rule.get('detection', {})
                if detection.get('type') == 'folder_match':
                    patterns = detection.get('patterns', [])
                    if any(pattern in label_lower for pattern in patterns):
                        rules_matched.append(rule_id)
            
            if rules_matched:
                suspicious_folder_ids.append(entry['id'])
                matched_rules[entry['id']] = rules_matched
                rules_str = ', '.join(rules_matched)
                self.log(f"  [!] Flagged by [{rules_str}]: {entry['label']} (ID: {entry['id']})")
        
        # Lấy descendants của các folders nghi vấn
        discovered_request_ids = []
        query_descendants = """
        query GetDescendants($parentId: String!) {
          sitemapDescendants(parentId: $parentId) {
            id
            kind
            label
            lastRequestId
          }
        }
        """
        
        for fid in suspicious_folder_ids:
            res = requests.post(self.url, json={'query': query_descendants, 'variables': {'parentId': fid}})
            if res.status_code == 200:
                descendants = res.json()['data']['sitemapDescendants']
                for d in descendants:
                    if d['lastRequestId']:
                        discovered_request_ids.append(int(d['lastRequestId']))
                        rules_str = ', '.join(matched_rules.get(fid, []))
                        self.log(f"    [+] Discovered via [{rules_str}]: {d['label']} (Req ID: {d['lastRequestId']})")
        
        return discovered_request_ids

    def inspect_phase(self, target_ids):
        """Bước 3: Lấy dữ liệu đầy đủ cho các requests đã chọn"""
        self.log(f"Phase 3: Inspection - Fetching full details for {len(target_ids)} requests...")
        
        detailed_results = []
        query = """
        query GetDetail($id: Int!) {
          request(id: $id) {
            id
            url
            method
            statusCode
            requestHeaders
            requestQuery
            requestBody
            responseHeaders
            responseBody
            contentType
          }
        }
        """
        
        for rid in target_ids:
            response = requests.post(self.url, json={'query': query, 'variables': {'id': rid}})
            if response.status_code == 200:
                detailed_results.append(response.json()['data']['request'])
                
        return detailed_results

    def analyze_findings(self, detailed_data):
        """Bước 4: Áp dụng analysis rules để tìm vulnerabilities"""
        self.log("Phase 4: Analysis - Applying security detection rules...")
        
        analysis_rules = self.get_rules_by_phase('analysis')
        findings = []
        
        for item in detailed_data:
            # Decode helpers
            def safe_decode(b64):
                if not b64: return ""
                try: return base64.b64decode(b64).decode('utf-8', errors='ignore')
                except: return ""

            req_body = safe_decode(item.get('requestBody'))
            res_body = safe_decode(item.get('responseBody'))
            req_headers = json.loads(item.get('requestHeaders') or '{}')
            res_headers = json.loads(item.get('responseHeaders') or '{}')
            req_query = json.loads(item.get('requestQuery') or '{}')
            
            # Áp dụng từng rule
            for rule_id, rule in analysis_rules.items():
                detection = rule.get('detection', {})
                det_type = detection.get('type')
                matched = False
                match_details = {}
                
                # Request Header Rules
                if det_type == 'request_header':
                    header_name = detection.get('header_name', '').lower()
                    contains = detection.get('contains', '')
                    case_sensitive = detection.get('case_sensitive', True)
                    
                    h_val = next((v for k, v in req_headers.items() if k.lower() == header_name), None)
                    if h_val:
                        check_val = h_val if case_sensitive else h_val.lower()
                        check_pattern = contains if case_sensitive else contains.lower()
                        if check_pattern in check_val:
                            matched = True
                            match_details['value'] = h_val
                
                # Response Header Rules
                elif det_type == 'response_header':
                    header_name = detection.get('header_name', '').lower()
                    case_sensitive = detection.get('case_sensitive', True)
                    
                    h_val = next((v for k, v in res_headers.items() if k.lower() == header_name), None)
                    
                    # Check if header exists
                    if detection.get('exists'):
                        if h_val:
                            matched = True
                            match_details['value'] = h_val
                    
                    # Check if header is missing (completely absent)
                    elif detection.get('missing'):
                        if not h_val:
                            matched = True
                            match_details['header'] = header_name
                    
                    # Check if header exists but missing an attribute
                    elif detection.get('missing_attribute'):
                        missing_attr = detection['missing_attribute']
                        if h_val:
                            check_val = h_val if case_sensitive else h_val.lower()
                            check_attr = missing_attr if case_sensitive else missing_attr.lower()
                            if check_attr not in check_val:
                                matched = True
                                match_details['value'] = h_val
                
                # Query Parameter Rules
                elif det_type == 'query_param':
                    param_contains = detection.get('param_contains', [])
                    for param_name in req_query.keys():
                        if any(pattern in param_name.lower() for pattern in param_contains):
                            matched = True
                            match_details['key'] = param_name
                            break
                
                # Request Body Rules
                elif det_type == 'request_body':
                    contains = detection.get('contains', [])
                    req_body_lower = req_body.lower()
                    if any(pattern in req_body_lower for pattern in contains):
                        matched = True
                
                # Response Body Rules
                elif det_type == 'response_body':
                    contains = detection.get('contains', [])
                    res_body_lower = res_body.lower()
                    if any(pattern in res_body_lower for pattern in contains):
                        matched = True
                
                # Nếu rule matched, tạo finding
                if matched:
                    finding = self._format_finding(
                        rule_id=rule_id,
                        rule=rule,
                        req_id=item['id'],
                        url=item.get('url'),
                        match_details=match_details
                    )
                    findings.append(finding)
        
        return findings

    def _format_finding(self, rule_id: str, rule: Dict, req_id: int, url: str = None, match_details: Dict = None):
        """Format finding với metadata đầy đủ."""
        severity = rule.get('severity', 'INFO')
        category = rule.get('category', 'Unknown')
        message = rule.get('message', rule.get('name', 'Security issue detected'))
        
        # Format message với match details nếu có
        if match_details:
            try:
                message = message.format(**match_details)
            except:
                pass  # Ignore formatting errors
        
        parts = [f"[{severity}]", f"[{rule_id}]", f"[{category}]", message]
        parts.append(f"(Request ID: {req_id}")
        
        if url:
            parts.append(f"| URL: {url[:60]}")
        
        parts.append(")")
        
        # Thêm metadata cho CRITICAL/HIGH findings
        metadata_parts = []
        if rule.get('owasp'):
            metadata_parts.append(f"OWASP: {rule['owasp']}")
        if rule.get('cwe'):
            metadata_parts.append(f"CWE: {rule['cwe']}")
        if rule.get('remediation'):
            metadata_parts.append(f"Fix: {rule['remediation']}")
        
        finding = " ".join(parts)
        if metadata_parts and severity in ['CRITICAL', 'HIGH']:
            finding += "\n    └─ " + " | ".join(metadata_parts)
        
        return finding

    def run(self):
        # Bước 1: Recon
        all_reqs = self.recon_phase()
        
        # Bước 1.5: Deep Discovery
        hidden_ids = self.deep_discovery_phase()
        
        # Bước 2: Thinking
        self.thinking_phase(all_reqs)
        
        # Merge hidden IDs
        for hid in hidden_ids:
            if hid not in self.suspicious_ids:
                self.suspicious_ids.append(hid)
        
        if not self.suspicious_ids:
            self.log("No suspicious requests found. Job done.")
            return

        # Bước 3: Inspect
        detailed_data = self.inspect_phase(self.suspicious_ids)

        # Bước 4: Analyze
        findings = self.analyze_findings(detailed_data)
        
        # Generate Report
        self._print_report(findings)
    
    def _print_report(self, findings: List[str]):
        """In báo cáo với thống kê chi tiết."""
        print("\n" + "="*80)
        print("AGENT SECURITY REPORT (RULE-BASED DETECTION)")
        print("="*80)
        
        if not findings:
            print("\n✅ No vulnerabilities found.")
        else:
            # Sort by severity
            level_priority = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "INFO": 3}
            def get_priority(f):
                for level in level_priority:
                    if f.startswith(f"[{level}]"):
                        return level_priority[level]
                return 4
            
            sorted_findings = sorted(findings, key=get_priority)
            
            # Extract statistics
            severity_counts = {}
            rule_counts = {}
            category_counts = {}
            
            for finding in findings:
                # Severity
                for level in level_priority.keys():
                    if f"[{level}]" in finding:
                        severity_counts[level] = severity_counts.get(level, 0) + 1
                        break
                
                # Rule ID
                rule_match = re.search(r'\[([A-Z]{2}-\d{3})\]', finding)
                if rule_match:
                    rule_id = rule_match.group(1)
                    rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
                
                # Category
                cat_match = re.search(r'\]\s*\[([^\]]+)\]\s*[^[]', finding)
                if cat_match:
                    category = cat_match.group(1)
                    if category not in level_priority:
                        category_counts[category] = category_counts.get(category, 0) + 1
            
            # Print Summary
            print("\n📊 FINDINGS SUMMARY")
            print("-" * 80)
            print(f"Total Findings: {len(findings)}")
            
            for level in ["CRITICAL", "HIGH", "WARNING", "INFO"]:
                count = severity_counts.get(level, 0)
                if count > 0:
                    symbol = "🔴" if level == "CRITICAL" else "🟠" if level == "HIGH" else "🟡" if level == "WARNING" else "🔵"
                    print(f"  {symbol} {level}: {count}")
            
            if rule_counts:
                print(f"\n📋 Findings by Rule:")
                for rule_id in sorted(rule_counts.keys()):
                    rule_name = self.rules.get(rule_id, {}).get('name', 'Unknown')
                    print(f"  {rule_id}: {rule_counts[rule_id]} ({rule_name})")
            
            if category_counts:
                print(f"\n🏷️  Findings by Category:")
                for category in sorted(category_counts.keys()):
                    print(f"  {category}: {category_counts[category]}")
            
            # Print Detailed Findings
            print("\n" + "="*80)
            print("🔍 DETAILED FINDINGS")
            print("="*80 + "\n")
            
            for f in sorted_findings:
                print(f)
                print()
        
        print("="*80)
        print(f"📄 Documentation: docs/security-rules.md")
        print(f"⚙️  Configuration: agent_rules.yaml ({len(self.enabled_rules)} rules enabled)")
        print("="*80)

if __name__ == "__main__":
    orchestrator = AgentOrchestrator()
    orchestrator.run()
