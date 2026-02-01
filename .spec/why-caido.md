# Tại sao Strix chọn Caido và GraphQL?

Việc Strix lựa chọn sử dụng **Caido** và **GraphQL** là một quyết định kiến trúc chiến lược để tối ưu hóa khả năng tự động hóa của các Agent AI trong việc kiểm thử bảo mật. Dưới đây là các lý do chính:

## 1. Tại sao Strix dùng Caido?

Caido đóng vai trò là "bộ não" xử lý traffic (HTTP Proxy) của Strix nhờ các ưu điểm vượt trội:

*   **Hiệu năng vượt trội (Rust-based):** Caido cực kỳ nhẹ và nhanh, tiêu tốn ít tài nguyên hơn hẳn so với Burp Suite hay ZAP. Điều này cho phép Strix chạy mượt mà ngay cả trong các container Sandbox nhỏ gọn.
*   **Thiết kế cho Tự động hóa (Automation-first):** Khác với các công cụ truyền thống chủ yếu dựa vào giao diện (GUI), Caido được thiết kế để có thể điều khiển hoàn toàn thông qua code. Điều này cho phép Agent AI có thể liệt kê request, tìm kiếm lỗi, và lặp lại (replay) các cuộc tấn công một cách tự động.
*   **HTTPQL (Ngôn ngữ truy vấn Traffic):** Caido cung cấp HTTPQL, một ngôn ngữ truy vấn mạnh mẽ cho phép Strix lọc traffic cực nhanh (ví dụ: *"tìm tất cả POST request có chứa tham số user_id"*). Agent có thể sử dụng ngôn ngữ này để "quét" nhanh bề mặt tấn công.
*   **Sitemap & Scope Management:** Caido tự động xây dựng bản đồ ứng dụng (Sitemap) và quản lý phạm vi tấn công (Scope) rất hiệu quả, giúp Strix không bị "lạc" khi tấn công các ứng dụng lớn.

## 2. Tại sao dùng GraphQL?

GraphQL được sử dụng với hai mục đích chính trong hệ sinh thái Strix:

### API điều khiển Caido
Caido bản thân nó cung cấp một GraphQL API cực kỳ mạnh mẽ. Thay vì gọi các REST endpoint rời rạc, Strix sử dụng GraphQL để giao tiếp với Caido (thông qua `ProxyManager`).

*   **Lợi ích:** Giúp Agent lấy được chính xác dữ liệu nó cần (chỉ lấy header, hoặc chỉ lấy body) một cách linh hoạt, giúp tiết kiệm băng thông và quan trọng nhất là tiết kiệm Token khi gửi dữ liệu cho LLM xử lý.

### Mục tiêu kiểm thử quan trọng
Rất nhiều ứng dụng hiện đại dùng GraphQL. Trong bộ kỹ năng (`skills/protocols/graphql.md`) của mình, Strix có các kỹ thuật tấn công chuyên biệt cho GraphQL như:

*   **Introspection abuse:** Tự động lấy sơ đồ (schema) của API.
*   **Batching attacks:** Lợi dụng tính năng gộp request để vượt qua giới hạn Rate Limit.
*   **IDOR ở tầng Resolver:** Kiểm tra quyền truy cập ở các tham số sâu trong query.

## Tóm tắt kiến trúc

Trong Strix, sự kết hợp này tạo thành một luồng xử lý khép kín:

1.  **Caido** bắt traffic từ trình duyệt (Playwright).
2.  **Strix Agent** sử dụng GraphQL để truy vấn "não bộ" Caido nhằm tìm ra các request thú vị.
3.  **Strix Agent** tiếp tục dùng GraphQL để ra lệnh cho Caido thực hiện các bản sao tấn công (Replay) và quan sát kết quả trả về.

Bạn có thể thấy rõ sự tích hợp này trong file: `strix/strix/tools/proxy/proxy_manager.py` (nơi class `ProxyManager` sử dụng thư viện `gql` để điều khiển Caido).