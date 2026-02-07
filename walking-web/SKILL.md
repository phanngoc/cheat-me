---
name: walking-web
description: An autonomous web crawler designed for security reconnaissance and business flow discovery. It uses Playwright for browser automation, Q-learning for intelligent link prioritization, and integrates with mitmproxy for traffic analysis.
---

# Walking Web: Autonomous Security Crawler

This skill enables an AI agent to perform deep, automated reconnaissance of web applications to discover attack surfaces, business flows, and hidden API endpoints.

## 🛠 Prerequisites

Before running the crawler, ensure the following infrastructure is active:

1.  **Virtual Environment**: Use the project's venv.
    - Path: `/Users/ngocp/Documents/projects/pen-testing/cheat-me/.venv`
2.  **Traffic Capture (Optional but Recommended)**: `mitmdump` should be running to intercept and store traffic into the database.
    - Command: `mitmdump -s audit_addon.py -p 8082` (Note: Port may vary, check active processes).
3.  **Database**: PostgreSQL should be up and running (usually via Docker).
    - Database: `strix_pentesting`
    - User: `strix_user`

## 🚀 Execution Steps

### 1. Pre-Crawl Verification
Always check if the target website has bot protection or captchas that might block Playwright.
- Use a browser subagent to navigate to the target URL first.

### 2. Basic Crawl Command
Navigate to the `walking-web` directory and run the CLI:

```bash
cd walking-web
../.venv/bin/python crawl_cli.py crawl <URL> --max-urls 50 --depth 2 --proxy-port 8082
```

### 3. Parameters Reference
- `crawl <URL>`: Start URL.
- `--max-urls <N>`: Limit the total number of pages to visit.
- `--depth <D>`: How many levels of links to follow.
- `--proxy-port <P>`: Port of the mitmproxy/interceptor (Default in config is 8085, but current active is often 8082).
- `--no-headless`: Use this to see the browser in action (debugging).
- `--verbose`: Enable detailed logs.

### 4. Background Execution
For larger crawls, run in the background and redirect output:

```bash
../.venv/bin/python crawl_cli.py crawl <URL> --max-urls 100 --depth 3 > crawl_output.log 2>&1 & echo $!
```

## 📊 Verification & Results

### Check Crawl Progress
Monitor the log file to see which URLs are being visited:
```bash
tail -f crawl_output.log
```

### Verify Captured Traffic
Query the database to see the requests intercepted by the proxy:
```bash
PGPASSWORD=strix_password psql -h localhost -U strix_user -d strix_pentesting -c "SELECT count(*) FROM requests WHERE url LIKE '%target-domain%';"
```

## ⚠️ Important Notes & Best Practices

- **Proxy Conflicts**: Always verify which port `mitmproxy` is listening on (`lsof -i :8082`). If the proxy is not running or on the wrong port, the crawler will fail with `ERR_TUNNEL_CONNECTION_FAILED`.
- **Scope Control**: The crawler defaults to the domain of the seed URL. Use `--domain` to add allowed subdomains or external integrations.
- **Resource Usage**: High concurrency (default 3) and deep crawls can consume significant CPU/Memory. Monitor system resources.
- **Q-Learning Model**: The system saves its learning state to `./models/q_model.pkl`. This makes subsequent crawls on the same site more efficient over time.
- **Respect Boundaries**: Be mindful of rate limits. Use `--delay <ms>` to slow down requests if the target starts returning 429 errors.
