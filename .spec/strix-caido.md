# Phân tích Kiến trúc: Strix Control Flow qua Caido GraphQL

Dưới đây là tổng hợp toàn bộ các truy vấn GraphQL mà Strix sử dụng để điều khiển Caido, vai trò của từng loại và phân tích lý do tại sao kiến trúc này vượt trội so với việc truy vấn trực tiếp vào một cơ sở dữ liệu SQLite truyền thống.

## 1. Danh sách các Truy vấn GraphQL chính trong Strix

Strix tập trung toàn bộ logic này trong file `proxy_manager.py`.

### A. Truy vấn Dữ liệu Traffic (Queries)

*   **`GetRequests` (`requestsByOffset`):**
    *   **Vai trò:** Liệt kê và lọc danh sách traffic dựa trên ngôn ngữ HTTPQL.
    *   **Tham số chính:** `limit`, `offset`, `filter` (cú pháp HTTPQL), `order`.
    *   **Dữ liệu lấy về:** ID, method, host, path, status code. Strix thường **KHÔNG** lấy phần raw (content) ở bước này để tiết kiệm RAM và Token.
*   **`GetRequest` (`request(id)`):**
    *   **Vai trò:** Lấy chi tiết toàn bộ nội dung của một Request hoặc Response cụ thể.
    *   **Điểm đặc biệt:** Strix sử dụng các query variant để chỉ lấy raw request hoặc raw response tùy theo nhu cầu của Agent.
*   **`GetSitemap` (`sitemapRootEntries` / `sitemapDescendantEntries`):**
    *   **Vai trò:** Khám phá cấu trúc thư mục/endpoint của ứng dụng mục tiêu theo dạng cây (Hierarchy).

### B. Thao tác Cấu hình (Mutations)

*   **`CreateScope` / `UpdateScope` / `DeleteScope`:**
    *   **Vai trò:** Định nghĩa "vùng an toàn" cho Agent. Giúp Agent chỉ tập trung tấn công vào các domain được phép (Allowlist) và bỏ qua các file rác (Denylist như `.png`, `.css`).

## 2. So sánh: GraphQL của Caido vs. API SQLite truyền thống

Trong các công cụ cũ (hoặc bản cũ của mitmproxy), log traffic thường được lưu vào một file SQLite. Dưới đây là lý do Strix/Caido chọn GraphQL:

| Tiêu chí | SQLite API (Truy vấn trực tiếp) | Caido GraphQL API |
| :--- | :--- | :--- |
| **Độ linh hoạt (Granularity)** | Phải `SELECT *` hoặc viết SQL Join phức tạp để lấy thông tin liên quan giữa Request và Response. | **Cực cao.** Chỉ lấy đúng các trường Agent cần (ví dụ: chỉ lấy Header Authorization). Tiết kiệm 80-90% AI Token. |
| **Khả năng lọc (Filtering)** | Phải biết schema bảng, viết các câu lệnh `LIKE '%...%'` chậm và tốn tài nguyên. | **HTTPQL.** Một ngôn ngữ chuyên dụng cho Pentest (ví dụ: `req.method.eq:"POST"`). Tốc độ xử lý hàng triệu request cực nhanh. |
| **Xử lý dữ liệu Binary** | Lưu blob trong DB, Agent khó xử lý trực tiếp, dễ gây crash nếu request quá lớn. | **Base64 + Pagination.** GraphQL trả về Base64, Strix thực hiện phân trang nội dung (ví dụ: chỉ xem 50 dòng đầu của Response) ngay tại tầng API. |
| **Tính nhất quán (Real-time)** | Việc đọc/ghi vào file SQLite khi có hàng nghìn request/giây dễ gây Lock DB hoặc corruption. | **Concurrent-safe.** Caido (Rust) quản lý việc ghi dữ liệu, GraphQL cung cấp một interface an toàn để đọc dữ liệu mà không làm gián đoạn luồng proxy. |
| **Trải nghiệm Agent AI** | SQL quá phức tạp để AI tự tạo ra các query chính xác mà không gặp lỗi cú pháp. | **Schema-driven.** GraphQL có cơ chế tự gợi ý (Introspection), Agent có thể hiểu rõ các trường dữ liệu có sẵn để đặt câu hỏi chính xác. |

## 3. Tại sao đây là "Điểm mạnh tuyệt đối" của Strix?

Đối với một Agent AI như Strix, **Token là tiền bạc và thời gian.**

### Nếu dùng SQLite truyền thống:
1.  Để quét lỗi XSS, Agent phải tải toàn bộ 1000 request (mỗi request 5KB) = **5MB dữ liệu**.
2.  AI sẽ bị "ngộp" và mất dấu vết (Max context length).

### Với GraphQL của Caido:
1.  Agent gửi 1 query: *"Cho tôi danh sách các request có status:200 và có tham số q"*.
2.  API chỉ trả về 5 cái ID.
3.  Agent chỉ tải nội dung của 5 cái đó -> Tổng cộng chỉ mất **~10KB dữ liệu**.

**Kết luận:** GraphQL biến Caido từ một "thùng chứa dữ liệu thụ động" thành một **Search Engine thông minh**, giúp Strix hoạt động cực nhanh và chính xác với chi phí vận hành thấp nhất.
