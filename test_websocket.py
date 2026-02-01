import subprocess
import time
from playwright.sync_api import sync_playwright

def run_ws_test():
    proxy_port = 8085
    mitm_cmd = [
        "uv", "run", "--project", "../mitmproxy", 
        "mitmdump", "-p", str(proxy_port), 
        "-s", "audit_addon.py"
    ]
    
    print(f"Starting mitmdump on port {proxy_port}...")
    mitm_process = subprocess.Popen(mitm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    time.sleep(5)
    
    try:
        with sync_playwright() as p:
            print("Launching browser...")
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                proxy={"server": f"http://127.0.0.1:{proxy_port}"},
                ignore_https_errors=True
            )
            
            page = context.new_page()
            # Demo page for websocket
            url = "https://javascript.info/article/websocket/chat/index.html"
            
            print(f"Navigating to {url}...")
            # Sử dụng timeout dài hơn và wait_until đơn giản hơn
            page.goto(url, wait_until="load", timeout=60000)
            
            # Giả lập gửi tin nhắn nếu có thể (điền vào form chat nếu có)
            try:
                page.fill('input[type="text"]', "Hello from Playwright Audit!")
                page.keyboard.press("Enter")
                print("Sent a message through the chat demo.")
            except:
                print("Could not send automated message, just waiting for traffic...")
            
            print("Waiting 15 seconds to collect WebSocket traffic...")
            time.sleep(15)
            
            browser.close()
            print("Test finished.")
            
    finally:
        print("Stopping mitmdump...")
        mitm_process.terminate()
        mitm_process.wait()

if __name__ == "__main__":
    run_ws_test()
