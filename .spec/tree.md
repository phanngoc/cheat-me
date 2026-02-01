# Kiến trúc Sitemap trong Caido: Quản lý Không gian Trạng thái thông minh

Với tư cách là một Architecture Developer, bạn sẽ thấy cơ chế Sitemap của **Caido** là một hệ thống thiết kế rất thông minh để giải quyết bài toán: *Làm thế nào để biểu diễn một không gian trạng thái (State Space) khổng lồ của một Website dưới dạng một cấu trúc dữ liệu có thể truy vấn hiệu quả?*

Dưới đây là phân tích sâu về kiến trúc thực thi của cơ chế này trong Caido và cách Strix khai thác nó.

## 1. Mô hình Dữ liệu: Adjacency List Hierarchy

Caido không lưu sitemap như một chuỗi URL phẳng. Thay vào đó, nó sử dụng mô hình **Node-based Graph** lưu trong DB. Mỗi mục (Entry) trong Sitemap là một Node có các thuộc tính:

*   **Kind (Phân loại):** `DOMAIN`, `DIRECTORY`, `REQUEST`, `QUERY`, `BODY`.
*   **Label (Định danh):** Ví dụ: `api`, `v1`, `users`.
*   **Path:** Cấu trúc phân cấp từ gốc.

## 2. Truy vấn Gốc: `sitemapRootEntries`

Đây là điểm khởi đầu (Entry Point). Khi bạn mở Caido hoặc Strix bắt đầu quét, nó sẽ gọi query này để xác định các thực thể cao nhất.

### GraphQL Blueprint:

```graphql
query GetSitemapRoots($scopeId: ID) {
    sitemapRootEntries(scopeId: $scopeId) {
        edges {
            node {
                id       # UUID của Node
                kind     # Thường là DOMAIN
                label    # Ví dụ: "example.com"
                hasDescendants # Cờ boolean cực kỳ quan trọng cho UI/Logic
            }
        }
    }
}
```

**Cơ chế:** Caido quét bảng `sitemap_entries` nơi `parent_id IS NULL`. Nếu có `scopeId`, nó sẽ thực hiện một phép JOIN với bảng `scopes` để lọc traffic chỉ thuộc về dự án hiện tại.

## 3. Truy vấn Mở rộng: `sitemapDescendantEntries`

Đây là nơi sức mạnh của việc phân cấp thực sự phát huy. Strix sử dụng cơ chế **Lazy Loading** (tải chậm) để khám phá ứng dụng.

### GraphQL Blueprint:

```graphql
query GetSitemapDescendants($parentId: ID!, $depth: SitemapDescendantsDepth!) {
    sitemapDescendantEntries(parentId: $parentId, depth: $depth) {
        edges {
            node {
                id
                kind    # DIRECTORY, REQUEST...
                label   # Ví dụ: "login"
                request {
                    method
                    path
                    response { statusCode }
                }
            }
        }
    }
}
```

**Tham số `depth`:**
*   `DIRECT`: Chỉ lấy các con trực tiếp (tương đương `ls` trong Linux). Giúp tiết kiệm dữ liệu.
*   `ALL`: Lấy toàn bộ cây con bên dưới (tương đương `find .`). Dùng khi Strix muốn xây dựng một bản đồ toàn diện để phân tích logic.

## 4. Tại sao thiết kế này ưu việt cho Architecture?

### A. Tránh "Data Overwhelming" (Ngập lụt dữ liệu)
Nếu một ứng dụng có 100,000 URL (do fuzzing hoặc crawling), việc gửi toàn bộ danh sách cho AI là bất khả thi.

*   **Giải pháp:** Bằng cách chia thành các Node cha-con, Strix có thể ra quyết định ở tầng cao (ví dụ: *"Thư mục /admin có vẻ thú vị, hãy mở rộng nó"*) mà không cần quan tâm đến các thư mục khác như `/static`.

### B. Phân loại theo "Context" thay vì "Pattern"
Các Proxy cũ dùng Regex để parse URL. Caido lưu trữ các biến thể của cùng một endpoint (ví dụ: cùng một URL nhưng khác Query Parameter hoặc Body) thành các Node con của cùng một Request Node.

*   **Kiến trúc:** Điều này cho phép Strix nhận diện được Parameter Pollution hoặc các tham số tiềm ẩn mà không phải parse chuỗi string phức tạp.

### C. Metadata Integration
Mỗi Node trong sitemap không chỉ có tên, nó liên kết trực tiếp với các metadata về giao thức (TLS, Port).

*   **Architectural Benefit:** Strix có thể nhanh chóng xác định các điểm yếu về hạ tầng (ví dụ: một endpoint nhạy cảm vô tình chạy trên cổng 80 thay vì 443) chỉ bằng cách duyệt Sitemap, thay vì phải quét lại port từ đầu.

## 5. Luồng Tư duy của Strix thông qua Sitemap

1.  **Recon:** Lấy `sitemapRootEntries` để biết ứng dụng đang chạy ở đâu.
2.  **Expand:** Duyệt `sitemapDescendantEntries` của các thư mục như `/api`, `/v2`.
3.  **Inspect:** Với mỗi Node có `kind: REQUEST`, Strix sẽ gọi `view_sitemap_entry` để lấy các request mẫu thực tế nhất nhằm thực hiện tấn công Replay.

**Tóm lại:** Cơ chế này biến "Traffic Log" hỗn độn thành một **File System ảo**, cho phép AI và Developer thao tác với Web App giống như đang duyệt cây thư mục trên máy tính. Đây chính là chìa khóa để Strix có thể quản lý các ứng dụng cực lớn một cách thông minh.