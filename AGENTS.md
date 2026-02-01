# AI Agent Guide for Cheat-Me Project

To run the automation and capture traffic for security analysis, follow these steps:

### 1. Prerequisites
Ensure the GraphQL server is running:
```bash
uv run python start_graphql.py
```

Ensure mitmproxy is running with the audit addon to capture traffic:
```bash
uv run python -m mitmproxy.tools.web -p 8083 --web-port 8084 -s audit_addon.py
```

### 2. Execution & Analysis
Run the automation to generate traffic and then execute the security analyzer:
```bash
uv run python run_automation.py && uv run python security_analyzer.py
```

### 3. Deep Discovery (Optional)
To perform advanced analysis using the AI Orchestrator:
```bash
uv run python agent_orchestrator.py
```
