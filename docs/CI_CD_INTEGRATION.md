# CI/CD Integration Guide

This guide explains how to integrate Cheat-Me security scanning into your CI/CD pipeline.

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Local Usage](#local-usage)
- [GitHub Actions](#github-actions)
- [GitLab CI/CD](#gitlab-cicd)
- [Docker Deployment](#docker-deployment)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

## 🚀 Quick Start

### Prerequisites

- Docker (for PostgreSQL)
- [uv](https://github.com/astral-sh/uv) package manager
- Python 3.12+

### Installation

```bash
# Clone repository
git clone <repository-url>
cd cheat-me

# Install dependencies
uv sync

# Start database
docker-compose up -d

# Make script executable
chmod +x run_security_scan.sh
```

## 💻 Local Usage

### Basic Scan

```bash
./run_security_scan.sh https://example.com
```

### Advanced Options

```bash
# Scan with custom parameters
./run_security_scan.sh https://example.com \
    --max-urls 100 \
    --depth 3 \
    --proxy-port 8082

# Skip traffic generation (use existing DB data)
./run_security_scan.sh https://example.com --skip-traffic-gen

# Verbose output
./run_security_scan.sh https://example.com --verbose
```

### Full Command Reference

```bash
./run_security_scan.sh <target_url> [options]

Options:
  --max-urls NUM         Maximum URLs to crawl (default: 50)
  --depth NUM            Maximum crawl depth (default: 2)
  --proxy-port NUM       mitmproxy port (default: 8082)
  --graphql-port NUM     GraphQL server port (default: 8085)
  --skip-traffic-gen     Skip traffic generation
  --skip-cleanup         Don't cleanup processes on exit
  --verbose              Enable verbose output
  -h, --help             Show help message
```

## 🔄 GitHub Actions

### Setup

1. Copy `.github/workflows/security-scan.yml` to your repository
2. Configure secrets (optional):
   - `SLACK_WEBHOOK_URL` - For notifications
   - `TARGET_URL` - Default scan target

### Trigger Methods

**On Push/PR:**
```yaml
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
```

**Scheduled Scans:**
```yaml
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
```

**Manual Trigger:**
```bash
# Via GitHub UI: Actions > Security Scan CI/CD > Run workflow
# Or via GitHub CLI:
gh workflow run security-scan.yml \
  -f target_url=https://example.com \
  -f max_urls=100 \
  -f depth=3
```

### Viewing Results

- **Summary:** Check job summary in Actions tab
- **Artifacts:** Download `security-scan-results-*` artifact
- **PR Comments:** Automated comment on pull requests

## 🦊 GitLab CI/CD

### Setup

1. Copy `.gitlab-ci.yml` to your repository
2. Configure CI/CD variables:
   - `SCHEDULED_TARGET_URL` - Target for scheduled scans
   - `MAX_URLS` - Maximum URLs to crawl (optional)
   - `CRAWL_DEPTH` - Crawl depth (optional)

### Running Scans

**On Commit:**
```bash
git push origin main
```

**Manual Pipeline:**
```bash
# Via GitLab UI: CI/CD > Pipelines > Run pipeline
# Or specify variables:
TARGET_URL=https://example.com MAX_URLS=100 git push
```

**Scheduled Pipelines:**
```bash
# Configure in: CI/CD > Schedules
# Set variables:
# - SCHEDULED_TARGET_URL: https://example.com
# - MAX_URLS: 100
```

### Viewing Results

- Navigate to: CI/CD > Pipelines > [Pipeline ID] > Jobs > generate_report
- Download artifacts from the job page

## 🐳 Docker Deployment

### Build Image

```bash
docker build -t cheat-me-scanner .
```

### Run Container

```bash
# Using docker-compose
docker-compose -f docker-compose.ci.yml up

# Or manually
docker run --rm \
  -e TARGET_URL=https://example.com \
  -e MAX_URLS=50 \
  -e CRAWL_DEPTH=2 \
  --network host \
  cheat-me-scanner
```

### Complete docker-compose Setup

Create `docker-compose.ci.yml`:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: strix_user
      POSTGRES_PASSWORD: strix_password
      POSTGRES_DB: strix_pentesting
    volumes:
      - ./init-db:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U strix_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  scanner:
    build: .
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      - TARGET_URL=${TARGET_URL:-https://httpbin.org}
      - MAX_URLS=${MAX_URLS:-50}
      - CRAWL_DEPTH=${CRAWL_DEPTH:-2}
      - DB_HOST=postgres
    volumes:
      - ./scan_results:/app/scan_results
```

Run:
```bash
TARGET_URL=https://example.com docker-compose -f docker-compose.ci.yml up
```

## ⚙️ Configuration

### Environment Variables

```bash
# Database Configuration
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=strix_pentesting
export DB_USER=strix_user
export DB_PASSWORD=strix_password

# Server Ports
export PROXY_PORT=8082
export GRAPHQL_PORT=8085

# Scan Configuration
export MAX_URLS=50
export CRAWL_DEPTH=2
export TIMEOUT_CRAWL=600
export TIMEOUT_ANALYSIS=300
```

### Agent Rules Configuration

Edit `agent_rules.yaml` to customize detection rules:

```yaml
rules:
  SC-001:
    enabled: true
    name: "Exposed Secrets Detection"
    phase: analysis
    severity: CRITICAL
    # ... more configuration
```

### Crawler Configuration

Edit `walking-web/crawl_config.yaml`:

```yaml
crawl:
  max_depth: 3
  max_urls: 1000
  concurrent_browsers: 3
  request_delay_ms: 500

scope:
  allowed_domains:
    - example.com
    - "*.example.com"
  excluded_paths:
    - /logout
    - /admin
```

## 🔧 Troubleshooting

### Common Issues

**1. Database connection failed**
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Restart database
docker-compose restart
```

**2. Port already in use**
```bash
# Find process using port
lsof -i :8082

# Kill process
kill -9 <PID>
```

**3. Crawler timeout**
```bash
# Increase timeout
export TIMEOUT_CRAWL=1200  # 20 minutes
./run_security_scan.sh https://example.com
```

**4. GraphQL server not starting**
```bash
# Check logs
tail -f scan_results/*/graphql.log

# Run health check
python health_check.py
```

### Debug Mode

```bash
# Enable verbose logging
./run_security_scan.sh https://example.com --verbose

# Check individual components
source .venv/bin/activate

# Test GraphQL server
uvicorn server.main:app --host 0.0.0.0 --port 8085

# Test proxy
mitmdump -s audit_addon.py -p 8082

# Test crawler
cd walking-web
python crawl_cli.py crawl https://example.com --max-urls 5
```

## 📊 Understanding Results

### Report Structure

```
scan_results/
└── 20240207_143022/
    ├── SUMMARY.md              # High-level overview
    ├── security_report.txt     # Detailed findings
    ├── scan.log                # Execution log
    ├── graphql.log             # GraphQL server log
    └── proxy.log               # mitmproxy log
```

### Severity Levels

- **CRITICAL** 🔴: Immediate action required
- **HIGH** 🟠: Should be fixed soon
- **WARNING** 🟡: Review recommended
- **INFO** 🔵: Informational finding

### Exit Codes

- `0`: Scan completed successfully, no critical issues
- `1`: Scan failed or critical vulnerabilities found
- `124`: Timeout occurred

## 🔐 Security Best Practices

1. **Credentials Management**
   - Use environment variables for sensitive data
   - Never commit credentials to version control
   - Use CI/CD secrets for credentials

2. **Network Security**
   - Run scans in isolated networks
   - Use VPNs for production scans
   - Configure firewall rules

3. **Data Protection**
   - Encrypt scan results at rest
   - Limit artifact retention time
   - Sanitize reports before sharing

## 📚 Additional Resources

- [Main README](README.md)
- [Agent Rules Documentation](docs/security-rules.md)
- [Walking-Web Documentation](walking-web/README.md)
- [GraphQL API Schema](server/schema.py)

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## 📝 License

See [LICENSE](LICENSE) for license information.
