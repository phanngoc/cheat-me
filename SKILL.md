---
name: security_validator
description: Skill for running the security scanning workflow (Proxy -> Traffic -> Detect -> Report)
---

# Security Validation Workflow

Tài liệu này hướng dẫn quy trình chạy workflow chuẩn để kiểm tra và xác thực các lỗ hổng bảo mật bằng `AgentOrchestrator`.

## 1. Khởi động server proxy
Khởi động GraphQL Feature Server nội bộ để cung cấp dữ liệu cho Agent.
```bash
source .venv/bin/activate && uvicorn server.main:app --host 0.0.0.0 --port 8085
```

## 2. Khởi động test flow
Chạy bộ script gửi request (qua cổng mitmproxy) để tạo traffic giả lập các kịch bản tấn công/sơ hở thực thực tế.
```bash
bash run_test_flow.sh
```

## 3. Khởi động agent detect lỗi và report
Chạy orchestrator chính để phân tích traffic từ Database và xuất báo cáo PDF/Console.
```bash
source .venv/bin/activate && python3 agent_orchestrator.py
```
