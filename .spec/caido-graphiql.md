# Làm chủ Caido Control API với GraphQL

Caido không chỉ là một công cụ có giao diện (GUI), mà nó còn là một **Headless Proxy** cực kỳ mạnh mẽ. Thay vì sử dụng các API REST lỗi thời, Caido sử dụng GraphQL để cho phép bạn truy vấn chính xác những gì bạn cần, giúp tiết kiệm băng thông và tối ưu hóa Token khi làm việc với AI.

## 1. Thiết lập kết nối (Connection Setup)

Mặc định, Caido lắng nghe GraphQL API tại:

*   **Endpoint:** `http://127.0.0.1:48080/graphql`
*   **Authentication:** Sử dụng ID Token (API Token) trong header.

### Cấu hình Python Client cơ bản:

```python
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport

CAIDO_URL = "http://127.0.0.1:48080/graphql"
AUTH_TOKEN = "YOUR_CAIDO_API_TOKEN"

transport = RequestsHTTPTransport(
    url=CAIDO_URL,
    headers={"Authorization": f"Bearer {AUTH_TOKEN}"}
)

client = Client(transport=transport, fetch_schema_from_transport=True)
```

## 2. Các kĩ thuật "Control" cốt lõi

### A. Liệt kê Request với Bộ lọc (HTTPQL)
Đây là cách Strix tìm kiếm các điểm yếu. Thay vì tải toàn bộ traffic, bạn chỉ lấy ID và các thông tin cơ bản để phân tích trước.

#### Query:

```graphql
query GetRequests($limit: Int, $offset: Int, $filter: HTTPQL) {
  requestsByOffset(limit: $limit, offset: $offset, filter: $filter) {
    edges {
      node {
        id
        method
        host
        path
        response {
          statusCode
        }
      }
    }
    count { value }
  }
}
```

*   **Lợi ích:** Bạn có thể dùng filter như `req.method.eq:"POST"` hoặc `resp.code.gt:400` để nhắm mục tiêu chính xác.

### B. Chế độ "Tiết kiệm Token" (Selective Data Fetching)
Đây là phần quan trọng nhất cho AI. Thay vì gửi toàn bộ Request (có thể lên tới hàng chục KB) cho LLM, bạn chỉ lấy những gì cần thiết.

#### Kịch bản 1: Chỉ lấy Header để kiểm tra Auth

```graphql
query GetRequestHeaders($id: ID!) {
  request(id: $id) {
    raw # Sau đó bạn có thể parse chỉ phần Header trong code terminal trước khi gửi cho AI
  }
}
```

#### Kịch bản 2: Lấy Response body nhưng giới hạn kích thước
Caido lưu trữ dữ liệu dưới dạng base64. Trong Strix, dữ liệu này được decode và xử lý phân trang (pagination) trước khi đưa vào ngữ cảnh của AI.

## 3. Điều khiển nâng cao (Mutations)

### Quản lý Scope (Tầm kiểm soát)
Để tránh AI tấn công nhầm sang các domain không liên quan (như Google Analytics, Facebook Pixel), bạn cần thiết lập Scope.

#### Mutation tạo Scope mới:

```graphql
mutation CreateScope($name: String!, $allowlist: [String!]!) {
  createScope(input: { name: $name, allowlist: $allowlist }) {
    scope {
      id
      name
    }
  }
}
```

## 4. Tại sao đây là "Vũ khí bí mật" của Strix?

| Tính năng | Cách dùng truyền thống | Caido GraphQL (Strix style) |
| :--- | :--- | :--- |
| **Tìm lỗi IDOR** | Phải đọc từng request thủ công | Gửi 1 query lấy danh sách tất cả ID của `/api/user/*` |
| **Băng thông** | Tải toàn bộ nội dung HTTP | Chỉ lấy `id` và `path` để lọc nhanh |
| **Chi phí AI** | Gửi hàng MB log cho GPT | Chỉ gửi 100 dòng code liên quan nhất (nhờ pagination) |
| **Tốc độ** | Phụ thuộc tốc độ render giao diện | Chạy hàng nghìn truy vấn mỗi giây ở background |

## 5. Ví dụ thực tế: Tìm kiếm bí mật (Secrets) trong traffic

Nếu bạn muốn quét tất cả các response để tìm từ khóa `"admin_token"`:

```python
# Query này cực nhanh vì nó tận dụng engine của Caido
query = gql("""
    query SearchSecret($filter: HTTPQL) {
        requestsByOffset(filter: $filter, limit: 10) {
            edges {
                node {
                    id
                    path
                    response {
                        raw # Chỉ lấy raw của những cái khớp filter
                    }
                }
            }
        }
    }
""")

params = {"filter": 'resp.raw.cont:"admin_token"'}
result = client.execute(query, variable_values=params)
```

## 💡 Lời khuyên cho Developer

*   **Sử dụng Caido GraphiQL:** Bạn có thể truy cập `http://127.0.0.1:48080/graphiql` (nếu đang chạy Caido) để thử nghiệm các query với tính năng nhắc mã (Introspection).
*   **Tận dụng Base64:** Nhớ rằng Caido trả về raw data ở dạng Base64. Bạn cần `base64.b64decode()` trong Python để đọc nội dung thực tế.
*   **HTTPQL là bạn thân:** Hãy học cú pháp HTTPQL của Caido, nó mạnh tương đương với các bộ lọc của Wireshark nhưng dành cho Web.
