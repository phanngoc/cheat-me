FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    postgresql-client \
    lsof \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml uv.lock ./
COPY . .

# Install Python dependencies
RUN uv sync

# Install Playwright browsers
RUN . .venv/bin/activate && \
    playwright install chromium && \
    playwright install-deps chromium

# Make scripts executable
RUN chmod +x run_security_scan.sh

# Environment variables
ENV DB_HOST=postgres \
    DB_PORT=5432 \
    DB_NAME=strix_pentesting \
    DB_USER=strix_user \
    DB_PASSWORD=strix_password \
    PROXY_PORT=8082 \
    GRAPHQL_PORT=8085

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python health_check.py || exit 1

# Default command
CMD ["./run_security_scan.sh"]
