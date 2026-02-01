import requests
import json
import re
import base64

GRAPHQL_URL = "http://localhost:8085/graphql"

def fetch_requests_from_graphql():
    query = """
    query {
      requests {
        id
        url
        method
        statusCode
        responseHeaders
        responseBody
        contentType
      }
    }
    """
    response = requests.post(GRAPHQL_URL, json={'query': query})
    if response.status_code == 200:
        return response.json()['data']['requests']
    else:
        print(f"Error fetching from GraphQL: {response.text}")
        return []

def analyze_security():
    rows = fetch_requests_from_graphql()
    
    # 1. Kiểm tra thiếu Security Headers (Response)
    print("\n=== [1] Security Headers Analysis ===")
    security_headers = {
        "Content-Security-Policy": "Ngăn chặn XSS và các cuộc tấn công injection.",
        "Strict-Transport-Security": "Ép buộc kết nối HTTPS (HSTS).",
        "X-Content-Type-Options": "Ngăn chặn sniffing MIME type.",
        "X-Frame-Options": "Ngăn chặn Clickjacking.",
        "Referrer-Policy": "Kiểm soát thông tin referrer gửi đi."
    }
    
    for row in rows:
        url = row['url']
        if row['statusCode'] != 200: continue
        if not row['responseHeaders']: continue
        
        try:
            headers = {k.lower(): v for k, v in json.loads(row['responseHeaders']).items()}
        except:
            continue
            
        missing = []
        for sh, desc in security_headers.items():
            if sh.lower() not in headers:
                missing.append(sh)
        
        if missing and ("mrmax.jp" in url or "karte.io" in url or "localhost" in url):
            print(f"[!] {url[:80]}...")
            print(f"    Missing: {', '.join(missing)}")

    # 2. Kiểm tra rò rỉ thông tin Server/Version
    print("\n=== [2] Information Disclosure Analysis ===")
    for row in rows:
        if not row['responseHeaders']: continue
        try:
            headers = {k.lower(): v for k, v in json.loads(row['responseHeaders']).items()}
        except:
            continue
        
        server = headers.get('server')
        x_powered_by = headers.get('x-powered-by')
        
        if server:
            print(f"[!] Server Info Discovery: {row['url'][:60]} -> {server}")
        if x_powered_by:
            print(f"[!] Framework Info (X-Powered-By): {row['url'][:60]} -> {x_powered_by}")

    # 3. Kiểm tra thông tin nhạy cảm trong URL (PII/Tokens)
    print("\n=== [3] Sensitive Data in URLs ===")
    sensitive_keywords = ['token', 'session', 'auth', 'key', 'email', 'user']
    for row in rows:
        url = row['url'].lower()
        found = [k for k in sensitive_keywords if k in url]
        if found:
            print(f"[!] Potential sensitive param in URL: {url[:100]}")

    # 4. Kiểm tra Cookies bảo mật
    print("\n=== [4] Insecure Cookie Config ===")
    for row in rows:
        if not row['responseHeaders']: continue
        try:
            headers = {k.lower(): v for k, v in json.loads(row['responseHeaders']).items()}
        except:
            continue
            
        set_cookie = headers.get('set-cookie', '')
        if set_cookie:
            issues = []
            if 'secure' not in set_cookie.lower(): issues.append("Missing Secure flag")
            if 'httponly' not in set_cookie.lower(): issues.append("Missing HttpOnly flag")
            if 'samesite' not in set_cookie.lower(): issues.append("Missing SameSite config")
            
            if issues:
                print(f"[!] Cookie issues at {row['url'][:60]}")
                print(f"    Raw: {set_cookie[:100]}...")
                print(f"    Issues: {', '.join(issues)}")

    # 5. Kiểm tra rò rỉ thông tin trong Response Body (PII, IP, Internal Path)
    print("\n=== [5] Pattern Matcher (PII/Internal Data) ===")
    patterns = {
        "Internal IP": r'192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+',
        "Email Pattern": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "AWS Key": r'AKIA[0-9A-Z]{16}',
    }
    
    for row in rows:
        content_type = row['contentType'] or ""
        if 'text' not in content_type.lower() and 'json' not in content_type.lower():
            continue
            
        body_base64 = row['responseBody']
        if not body_base64: continue
        
        try:
            body_text = base64.b64decode(body_base64).decode('utf-8', errors='ignore')
            for name, p in patterns.items():
                if re.search(p, body_text):
                    print(f"[!] {name} found in response from: {row['url'][:80]}")
        except:
            continue

if __name__ == "__main__":
    analyze_security()
