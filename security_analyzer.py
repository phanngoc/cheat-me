import sqlite3
import json
import re

def analyze_security(db_path="audit_traffic.db"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 1. Kiểm tra thiếu Security Headers (Response)
    print("\n=== [1] Security Headers Analysis ===")
    security_headers = {
        "Content-Security-Policy": "Ngăn chặn XSS và các cuộc tấn công injection.",
        "Strict-Transport-Security": "Ép buộc kết nối HTTPS (HSTS).",
        "X-Content-Type-Options": "Ngăn chặn sniffing MIME type.",
        "X-Frame-Options": "Ngăn chặn Clickjacking.",
        "Referrer-Policy": "Kiểm soát thông tin referrer gửi đi."
    }
    
    # Lấy các URL duy nhất để phân tích header
    cursor.execute("SELECT DISTINCT url, response_headers FROM requests WHERE response_status = 200")
    for row in cursor.fetchall():
        url = row['url']
        if not row['response_headers']: continue
        
        headers = {k.lower(): v for k, v in json.loads(row['response_headers']).items()}
        missing = []
        for sh, desc in security_headers.items():
            if sh.lower() not in headers:
                missing.append(sh)
        
        if missing and ("mrmax.jp" in url or "karte.io" in url):
            print(f"[!] {url[:80]}...")
            print(f"    Missing: {', '.join(missing)}")

    # 2. Kiểm tra rò rỉ thông tin Server/Version
    print("\n=== [2] Information Disclosure Analysis ===")
    cursor.execute("SELECT DISTINCT url, response_headers FROM requests")
    for row in cursor.fetchall():
        if not row['response_headers']: continue
        headers = {k.lower(): v for k, v in json.loads(row['response_headers']).items()}
        
        server = headers.get('server')
        x_powered_by = headers.get('x-powered-by')
        
        if server:
            print(f"[!] Server Info Discovery: {row['url'][:60]} -> {server}")
        if x_powered_by:
            print(f"[!] Framework Info (X-Powered-By): {row['url'][:60]} -> {x_powered_by}")

    # 3. Kiểm tra thông tin nhạy cảm trong URL (PII/Tokens)
    print("\n=== [3] Sensitive Data in URLs ===")
    sensitive_keywords = ['token', 'session', 'auth', 'key', 'email', 'user']
    cursor.execute("SELECT DISTINCT url FROM requests")
    for row in cursor.fetchall():
        url = row['url'].lower()
        found = [k for k in sensitive_keywords if k in url]
        if found:
            print(f"[!] Potential sensitive param in URL: {url[:100]}")

    # 4. Kiểm tra Cookies bảo mật
    print("\n=== [4] Insecure Cookie Config ===")
    cursor.execute("SELECT DISTINCT url, response_headers FROM requests WHERE response_headers LIKE '%Set-Cookie%'")
    for row in cursor.fetchall():
        headers = {k.lower(): v for k, v in json.loads(row['response_headers']).items()}
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
    
    cursor.execute("SELECT url, response_body, content_type FROM requests WHERE content_type LIKE '%text%' OR content_type LIKE '%json%'")
    for row in cursor.fetchall():
        body = row['response_body']
        if not body: continue
        try:
            body_text = body.decode('utf-8', errors='ignore')
            for name, p in patterns.items():
                if re.search(p, body_text):
                    print(f"[!] {name} found in response from: {row['url'][:80]}")
        except:
            continue

    conn.close()

if __name__ == "__main__":
    analyze_security("audit_traffic.db")
