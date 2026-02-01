import requests
import json
import base64
import re

GRAPHQL_URL = "http://localhost:8085/graphql"

class AgentOrchestrator:
    def __init__(self, url=GRAPHQL_URL):
        self.url = url
        self.suspicious_ids = []

    def log(self, message):
        print(f"[*] {message}")

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
        """Bước 2: AI suy luận để chọn ra các request nghi vấn"""
        self.log("Phase 2: Thinking - Filtering suspicious targets...")
        
        # Heuristics để Agent tập trung vào:
        # 1. Các phương thức ghi dữ liệu (POST, PUT, DELETE)
        # 2. Các URL chứa từ khóa nhạy cảm
        # 3. Các lỗi phân quyền (Forbidden 403)
        # 4. Tránh các file tĩnh (.css, .png, .js)
        
        sensitive_keywords = ['login', 'admin', 'api', 'auth', 'config', 'user', 'session']
        ignored_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.woff']
        
        candidates = []
        for req in all_requests:
            url = req['url'].lower()
            method = req['method'].upper()
            status = req['statusCode']
            
            # Loại bỏ file tĩnh
            if any(url.endswith(ext) for ext in ignored_extensions):
                continue
                
            is_suspicious = False
            
            # Điều kiện 1: Method ghi dữ liệu
            if method in ['POST', 'PUT', 'DELETE']:
                is_suspicious = True
                
            # Điều kiện 2: Có từ khóa nhạy cảm
            if any(key in url for key in sensitive_keywords):
                is_suspicious = True
                
            # Điều kiện 3: Lỗi 403 (Tiềm năng Bypass) hoặc 500 (Tiềm năng SQLi)
            if status in [403, 500]:
                is_suspicious = True
                
            if is_suspicious:
                candidates.append(req['id'])
                self.log(f"  [+] Flagged: ID {req['id']} | {method} | {status} | {url[:60]}")
        
        self.suspicious_ids = candidates
        self.log(f"Total suspicious requests to inspect: {len(candidates)}")

    def inspect_phase(self, target_ids):
        """Bước 3: Lấy dữ liệu nặng (Full Headers/Body) cho các mục tiêu đã chọn"""
        self.log(f"Phase 3: Inspection - Deep diving into {len(target_ids)} requests...")
        
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
        """Bước 4: Phân tích sâu để tìm lỗ hổng từ dữ liệu Full"""
        self.log("Phase 4: Final Analysis - Extracting vulnerabilities...")
        
        findings = []
        for item in detailed_data:
            url = item['url']
            req_headers_raw = item['requestHeaders']
            req_query_raw = item['requestQuery']
            req_body_b64 = item['requestBody']
            res_headers_raw = item['responseHeaders']
            res_body_b64 = item['responseBody']
            
            # Helper to decode base64
            def safe_decode(b64):
                if not b64: return ""
                try: return base64.b64decode(b64).decode('utf-8', errors='ignore')
                except: return ""

            req_body = safe_decode(req_body_b64)
            res_body = safe_decode(res_body_b64)

            # 1. Kiểm tra Request Headers (Secrets in Auth headers)
            if req_headers_raw:
                req_headers = json.loads(req_headers_raw)
                auth = req_headers.get('Authorization') or req_headers.get('authorization')
                if auth and 'bearer' in auth.lower():
                    findings.append(f"[INFO] Bearer Token found in Request Auth Header (ID {item['id']})")

            # 2. Kiểm tra Request Query (Sensitve params)
            if req_query_raw:
                req_query = json.loads(req_query_raw)
                sensitive_keys = ['token', 'key', 'password', 'passwd', 'secret']
                for k in req_query.keys():
                    if any(sk in k.lower() for sk in sensitive_keys):
                        findings.append(f"[HIGH] Sensitive key '{k}' found in Request Query Params (ID {item['id']})")

            # 3. Kiểm tra Request Body (PII/Secrets in POST data)
            if "password" in req_body.lower() or "secret" in req_body.lower():
                 findings.append(f"[WARNING] Potential secret in Request Body (ID {item['id']})")

            # 4. Kiểm tra Lộ bí mật trong Response Body
            if "akia" in res_body.lower(): 
                findings.append(f"[CRITICAL] AWS Key found in Response Body (ID {item['id']} - {url})")
            
            # 5. Kiểm tra Insecure Response Cookies
            if res_headers_raw:
                res_headers = json.loads(res_headers_raw)
                for k, v in res_headers.items():
                    if k.lower() == 'set-cookie' and 'secure' not in v.lower():
                        findings.append(f"[HIGH] Insecure Response Cookie (Missing Secure flag) in ID {item['id']}")
            
            # 6. Kiểm tra Server Information Leakage
            if res_headers_raw:
                res_headers = json.loads(res_headers_raw)
                server = res_headers.get('Server') or res_headers.get('server')
                if server:
                    findings.append(f"[INFO] Server info leaked: {server} (ID {item['id']})")

        return findings

    def deep_discovery_phase(self):
        """Bước 1.5: Tìm kiếm sâu (Recursive) trong các folder nghi vấn"""
        self.log("Phase 1.5: Deep Discovery - Searching inside suspicious folders...")
        
        # 1. Lấy danh sách sitemap gốc
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
        folder_keywords = ['admin', 'api', 'v1', 'v2', 'auth', 'config', 'manage']
        
        for entry in roots:
            if entry['kind'] == 'DIRECTORY' and any(k in entry['label'].lower() for k in folder_keywords):
                suspicious_folder_ids.append(entry['id'])
                self.log(f"  [!] Suspicious folder detected: {entry['label']} (ID: {entry['id']})")

        # 2. Với mỗi folder nghi vấn, lấy toàn bộ descendants
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
                        self.log(f"    [+] Discovered hidden request: {d['label']} (Req ID: {d['lastRequestId']})")
        
        return discovered_request_ids

    def run(self):
        # Bước 1: Recon (Dữ liệu bề mặt)
        all_reqs = self.recon_phase()
        
        # Bước 1.5: Deep Discovery (Dữ liệu chiều sâu)
        hidden_ids = self.deep_discovery_phase()
        
        # Bước 2: Thinking - Kết hợp cả 2 nguồn dữ liệu
        self.thinking_phase(all_reqs)
        
        # Bổ sung các hidden_ids vào danh sách cần inspect nếu chưa có
        for hid in hidden_ids:
            if hid not in self.suspicious_ids:
                self.suspicious_ids.append(hid)
        
        if not self.suspicious_ids:
            self.log("No suspicious requests found. Job done.")
            return

        # Bước 3: Inspect
        detailed_data = self.inspect_phase(self.suspicious_ids)

        # Bước 4: Report
        findings = self.analyze_findings(detailed_data)
        
        print("\n" + "="*50)
        print("AGENT SECURITY REPORT (DEEP DISCOVERY MODE)")
        print("="*50)
        if not findings:
            print("No vulnerabilities found.")
        for f in findings:
            print(f)
        print("="*50)

if __name__ == "__main__":
    orchestrator = AgentOrchestrator()
    orchestrator.run()
