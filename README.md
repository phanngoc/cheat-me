# Cheat-Me: AI-Powered Penetration Testing Framework

`cheat-me` is a modern security automation framework designed to capture, analyze, and discover vulnerabilities in web applications. It combines Playwright automation with intercepting proxies and an AI-driven orchestrator to provide deep insights into application security.

## 🚀 Key Features

*   **Traffic Interception**: Uses `mitmproxy` with custom addons to capture and store full HTTP(S) request/response cycles and WebSocket messages.
*   **GraphQL Data Layer**: Centralized access to all captured traffic through a flexible GraphQL API.
*   **Automated Reconnaissance**: Integrated Playwright scripts to crawl and interact with target sites automatically.
*   **AI Orchestrator**: A multi-phase analysis engine that mimics a security researcher's workflow:
    *   **Phase 1: Recon**: Metadata gathering.
    *   **Phase 1.5: Deep Discovery**: Recursive search for hidden endpoints and folders.
    *   **Phase 2: Thinking**: Heuristic-based filtering of suspicious targets.
    *   **Phase 3: Inspection**: Deep-dive analysis of full request/response bodies.
    *   **Phase 4: Analysis**: Vulnerability extraction (Secrets, Insecure cookies, Information leakage, etc.).
*   **Sitemap Mapping**: Automatic reconstruction of site hierarchy from captured traffic.

## 🛠 Tech Stack

*   **Runtime**: Python 3.12+ (managed by `uv`)
*   **Database**: PostgreSQL
*   **Automation**: Playwright
*   **Proxy**: mitmproxy
*   **API**: FastAPI & Strawberry (GraphQL)
*   **Orchestration**: Custom Agentic Logic

## 📦 Getting Started

### 1. Prerequisites
- Docker (for PostgreSQL)
- [uv](https://github.com/astral-sh/uv) package manager

### 2. Setup
Clone the repository and install dependencies:
```bash
uv sync
```

Initialize the database:
```bash
docker-compose up -d
```

### 3. Usage

Follow these steps in order (use multiple terminal windows):

#### A. Start the GraphQL Server
```bash
uv run python start_graphql.py
```
*Accessible at `http://localhost:8085/graphql`*

#### B. Start mitmproxy with Audit Addon
```bash
uv run python -m mitmproxy.tools.web -p 8083 --web-port 8084 -s audit_addon.py
```

#### C. Run Automation & Basic Analysis
```bash
uv run python run_automation.py && uv run python security_analyzer.py
```

#### D. Deep AI Analysis
```bash
uv run python agent_orchestrator.py
```

## 📂 Project Structure

- `agent_orchestrator.py`: The core AI analysis engine.
- `audit_addon.py`: mitmproxy script to log traffic into the database.
- `server/`: GraphQL server implementation (FastAPI, Strawberry, Pydantic).
- `run_automation.py`: Playwright script for traffic generation.
- `security_analyzer.py`: Initial heuristic-based vulnerability scanner.
- `sitemap_service.py`: Logic for building site hierarchies.

## 🛡 Disclaimer
This tool is for educational and authorized penetration testing purposes only. Use it responsibly and only on systems you have permission to test.
