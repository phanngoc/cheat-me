import json
from mitmproxy import http

class CaptureProduct:
    def response(self, flow: http.HTTPFlow) -> None:
        if "mrmax.jp/products/detail/94710" in flow.request.pretty_url:
            print(f"Captured product page: {flow.request.pretty_url}")
            # Ở đây bạn có thể xử lý body của response
            # Ví dụ: lưu vào file
            with open("product_response.html", "w", encoding="utf-8") as f:
                f.write(flow.response.get_text())
            print("Successfully saved response to product_response.html")

addons = [
    CaptureProduct()
]
