import subprocess
import time
import os
from playwright.sync_api import sync_playwright

def run_automation():
    # 1. Khởi động mitmdump trong background
    # Lưu ý: Chúng ta dùng port 8085 để tránh xung đột với port cũ 8080/8082
    proxy_port = 8085
    mitmdump_path = os.path.join(os.getcwd(), ".venv", "bin", "mitmdump")
    mitm_cmd = [
        mitmdump_path, "-p", str(proxy_port), 
        "-s", "audit_addon.py"
    ]
    
    print(f"Starting mitmdump on port {proxy_port}...")
    mitm_process = subprocess.Popen(mitm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Đợi một chút để proxy khởi động
    time.sleep(5)
    
    try:
        with sync_playwright() as p:
            print("Launching browser...")
            # 2. Cấu hình Playwright sử dụng proxy
            browser = p.chromium.launch(headless=True)
            
            # Cấu hình proxy cho context
            context = browser.new_context(
                proxy={
                    "server": f"http://127.0.0.1:{proxy_port}",
                },
                ignore_https_errors=True # Quan trọng để bỏ qua lỗi SSL của mitmproxy
            )
            
            page = context.new_page()
            url = "https://mrmax.jp/products/detail/94710"
            
            print(f"Navigating to {url}...")
            page.goto(url, wait_until="networkidle")
            
            # Lấy title để verify
            title = page.title()
            print(f"Page Title: {title}")
            
            # Đợi thêm 2 giây để mitmproxy kịp ghi file
            time.sleep(2)
            
            browser.close()
            print("Automation finished successfully.")
            
    finally:
        # 3. Dừng mitmdump
        print("Stopping mitmdump...")
        mitm_process.terminate()
        mitm_process.wait()

if __name__ == "__main__":
    run_automation()
