#!/usr/bin/env bash
# =============================================================================
# CI/CD Security Scanning Pipeline
# Cheat-Me: Automated Penetration Testing Framework
# =============================================================================
# Usage:
#   ./run_security_scan.sh <target_url> [options]
#
# Examples:
#   ./run_security_scan.sh https://example.com
#   ./run_security_scan.sh https://example.com --max-urls 100 --depth 3
#   ./run_security_scan.sh https://example.com --skip-traffic-gen
# =============================================================================

set -e  # Exit on error
set -o pipefail

# =============================================================================
# Configuration & Defaults
# =============================================================================
TARGET_URL="${1:-}"
MAX_URLS="${MAX_URLS:-50}"
CRAWL_DEPTH="${CRAWL_DEPTH:-2}"
PROXY_PORT="${PROXY_PORT:-8082}"
GRAPHQL_PORT="${GRAPHQL_PORT:-8085}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-strix_pentesting}"
DB_USER="${DB_USER:-strix_user}"
DB_PASSWORD="${DB_PASSWORD:-strix_password}"

# Timeouts (seconds)
TIMEOUT_PROXY_START=10
TIMEOUT_GRAPHQL_START=15
TIMEOUT_CRAWL=600  # 10 minutes
TIMEOUT_ANALYSIS=300  # 5 minutes

# Output paths
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./scan_results/${TIMESTAMP}"
REPORT_FILE="${OUTPUT_DIR}/security_report.txt"
STATS_FILE="${OUTPUT_DIR}/scan_stats.json"
LOG_FILE="${OUTPUT_DIR}/scan.log"

# Process IDs for cleanup
PID_PROXY=""
PID_GRAPHQL=""

# Flags
SKIP_TRAFFIC_GEN=false
SKIP_CLEANUP=false
VERBOSE=false

# =============================================================================
# Color Output
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

log() {
    if [[ -d "$(dirname "${LOG_FILE}")" ]]; then
        echo -e "${CYAN}[$(date +'%H:%M:%S')]${NC} $*" | tee -a "${LOG_FILE}"
    else
        echo -e "${CYAN}[$(date +'%H:%M:%S')]${NC} $*"
    fi
}

log_success() {
    if [[ -d "$(dirname "${LOG_FILE}")" ]]; then
        echo -e "${GREEN}[✓]${NC} $*" | tee -a "${LOG_FILE}"
    else
        echo -e "${GREEN}[✓]${NC} $*"
    fi
}

log_error() {
    if [[ -d "$(dirname "${LOG_FILE}")" ]]; then
        echo -e "${RED}[✗]${NC} $*" | tee -a "${LOG_FILE}"
    else
        echo -e "${RED}[✗]${NC} $*"
    fi
}

log_warning() {
    if [[ -d "$(dirname "${LOG_FILE}")" ]]; then
        echo -e "${YELLOW}[!]${NC} $*" | tee -a "${LOG_FILE}"
    else
        echo -e "${YELLOW}[!]${NC} $*"
    fi
}

log_info() {
    if [[ -d "$(dirname "${LOG_FILE}")" ]]; then
        echo -e "${BLUE}[i]${NC} $*" | tee -a "${LOG_FILE}"
    else
        echo -e "${BLUE}[i]${NC} $*"
    fi
}


show_usage() {
    cat << EOF
Usage: $0 <target_url> [options]

Required:
  target_url              URL to scan (e.g., https://example.com)

Options:
  --max-urls NUM          Maximum URLs to crawl (default: 50)
  --depth NUM             Maximum crawl depth (default: 2)
  --proxy-port NUM        mitmproxy port (default: 8082)
  --graphql-port NUM      GraphQL server port (default: 8085)
  --skip-traffic-gen      Skip traffic generation (use existing DB data)
  --skip-cleanup          Don't cleanup processes on exit
  --verbose               Enable verbose output
  -h, --help              Show this help message

Environment Variables:
  DB_HOST                 Database host (default: localhost)
  DB_PORT                 Database port (default: 5432)
  DB_NAME                 Database name (default: strix_pentesting)
  DB_USER                 Database user (default: strix_user)
  DB_PASSWORD             Database password (default: strix_password)

Examples:
  $0 https://example.com
  $0 https://example.com --max-urls 100 --depth 3
  $0 https://example.com --skip-traffic-gen

EOF
}

# =============================================================================
# Parse Arguments
# =============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_usage
                exit 0
                ;;
            --max-urls)
                MAX_URLS="$2"
                shift 2
                ;;
            --depth)
                CRAWL_DEPTH="$2"
                shift 2
                ;;
            --proxy-port)
                PROXY_PORT="$2"
                shift 2
                ;;
            --graphql-port)
                GRAPHQL_PORT="$2"
                shift 2
                ;;
            --skip-traffic-gen)
                SKIP_TRAFFIC_GEN=true
                shift
                ;;
            --skip-cleanup)
                SKIP_CLEANUP=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                shift
                ;;
        esac
    done
}

# =============================================================================
# Cleanup Function
# =============================================================================

cleanup() {
    log_warning "Cleaning up processes..."
    
    if [[ -n "$PID_PROXY" ]]; then
        log "Stopping mitmproxy (PID: $PID_PROXY)"
        kill "$PID_PROXY" 2>/dev/null || true
    fi
    
    if [[ -n "$PID_GRAPHQL" ]]; then
        log "Stopping GraphQL server (PID: $PID_GRAPHQL)"
        kill "$PID_GRAPHQL" 2>/dev/null || true
    fi
    
    # Additional cleanup for any child processes
    pkill -P $$ 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# =============================================================================
# Prerequisites Check
# =============================================================================

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if uv is installed
    if ! command -v uv &> /dev/null; then
        log_error "uv is not installed. Please install it from https://github.com/astral-sh/uv"
        exit 1
    fi
    
    # Check if docker is running (for PostgreSQL)
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker."
        exit 1
    fi
    
    # Check if database container exists and is running
    if docker ps -a --format '{{.Names}}' | grep -q "^playwright_db$"; then
        # Container exists, check if running
        if ! docker ps --format '{{.Names}}' | grep -q "^playwright_db$"; then
            log_warning "PostgreSQL container exists but not running. Starting it..."
            docker start playwright_db
            sleep 5
        fi
    else
        # Container doesn't exist, create it
        log_warning "PostgreSQL container not found. Creating it..."
        docker-compose up -d
        sleep 5
    fi
    
    # Verify database connection
    if ! docker exec playwright_db pg_isready -U "$DB_USER" &> /dev/null; then
        log_error "Cannot connect to PostgreSQL database"
        exit 1
    fi
    
    # Check virtual environment
    if [[ ! -d ".venv" ]]; then
        log_warning "Virtual environment not found. Creating it..."
        uv sync
    fi
    
    # Check if Playwright is installed
    if ! uv run python -c "import playwright" &> /dev/null; then
        log_warning "Playwright not installed. Installing..."
        uv run python -m playwright install chromium
    fi
    
    log_success "All prerequisites satisfied"
}

# =============================================================================
# Step 1: Start GraphQL Server
# =============================================================================

start_graphql_server() {
    log "Step 1: Starting GraphQL Feature Server..."
    
    # Check if port is already in use
    if lsof -Pi :$GRAPHQL_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        log_warning "Port $GRAPHQL_PORT already in use. Skipping GraphQL server start."
        return 0
    fi
    
    # Start GraphQL server in background
    uv run uvicorn server.main:app --host 0.0.0.0 --port "$GRAPHQL_PORT" > "${OUTPUT_DIR}/graphql.log" 2>&1 &
    PID_GRAPHQL=$!
    
    # Wait for server to be ready
    log "Waiting for GraphQL server to start (timeout: ${TIMEOUT_GRAPHQL_START}s)..."
    local elapsed=0
    while [[ $elapsed -lt $TIMEOUT_GRAPHQL_START ]]; do
        if curl -s "http://localhost:${GRAPHQL_PORT}/graphql" > /dev/null 2>&1; then
            log_success "GraphQL server ready at http://localhost:${GRAPHQL_PORT}/graphql"
            return 0
        fi
        sleep 1
        ((elapsed++))
    done
    
    log_error "GraphQL server failed to start within ${TIMEOUT_GRAPHQL_START}s"
    exit 1
}

# =============================================================================
# Step 2: Start mitmproxy
# =============================================================================

start_proxy() {
    log "Step 2: Starting mitmproxy..."
    
    # Check if port is already in use
    if lsof -Pi :$PROXY_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        log_warning "Port $PROXY_PORT already in use. Skipping proxy start."
        return 0
    fi
    
    # Start mitmproxy in background
    uv run mitmdump -s audit_addon.py -p "$PROXY_PORT" > "${OUTPUT_DIR}/proxy.log" 2>&1 &
    PID_PROXY=$!
    
    # Wait for proxy to be ready
    log "Waiting for mitmproxy to start (timeout: ${TIMEOUT_PROXY_START}s)..."
    local elapsed=0
    while [[ $elapsed -lt $TIMEOUT_PROXY_START ]]; do
        if lsof -Pi :$PROXY_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
            log_success "mitmproxy ready on port ${PROXY_PORT}"
            return 0
        fi
        sleep 1
        ((elapsed++))
    done
    
    log_error "mitmproxy failed to start within ${TIMEOUT_PROXY_START}s"
    exit 1
}

# =============================================================================
# Step 3: Generate Traffic (Walking-Web)
# =============================================================================

generate_traffic() {
    if [[ "$SKIP_TRAFFIC_GEN" == true ]]; then
        log_warning "Skipping traffic generation (--skip-traffic-gen specified)"
        return 0
    fi
    
    log "Step 3: Generating traffic with Walking-Web crawler..."
    log_info "Target: $TARGET_URL"
    log_info "Max URLs: $MAX_URLS"
    log_info "Depth: $CRAWL_DEPTH"
    
    cd walking-web
    
    # Run crawler with timeout
    timeout "$TIMEOUT_CRAWL" uv run python crawl_cli.py crawl "$TARGET_URL" \
        --max-urls "$MAX_URLS" \
        --depth "$CRAWL_DEPTH" \
        --proxy-port "$PROXY_PORT" \
        2>&1 | tee -a "../${LOG_FILE}" || {
            local exit_code=$?
            if [[ $exit_code -eq 124 ]]; then
                log_warning "Crawler timeout after ${TIMEOUT_CRAWL}s"
            else
                log_error "Crawler failed with exit code $exit_code"
                cd ..
                return 1
            fi
        }
    
    cd ..
    log_success "Traffic generation completed"
}

# =============================================================================
# Step 4: Run Security Analysis
# =============================================================================

run_analysis() {
    log "Step 4: Running AI Security Analysis..."
    
    # Run agent orchestrator and capture output
    timeout "$TIMEOUT_ANALYSIS" uv run python agent_orchestrator.py 2>&1 | tee "${REPORT_FILE}" || {
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            log_warning "Analysis timeout after ${TIMEOUT_ANALYSIS}s"
        else
            log_error "Analysis failed with exit code $exit_code"
            return 1
        fi
    }
    
    log_success "Security analysis completed"
}

# =============================================================================
# Step 5: Generate Summary
# =============================================================================

generate_summary() {
    log "Step 5: Generating scan summary..."
    
    local summary_file="${OUTPUT_DIR}/SUMMARY.md"
    
    cat > "$summary_file" << EOF
# Security Scan Summary

**Scan Timestamp:** ${TIMESTAMP}
**Target URL:** ${TARGET_URL}
**Scan Duration:** $(($(date +%s) - START_TIME))s

## Configuration
- Max URLs: ${MAX_URLS}
- Crawl Depth: ${CRAWL_DEPTH}
- Proxy Port: ${PROXY_PORT}
- GraphQL Port: ${GRAPHQL_PORT}

## Output Files
- Security Report: \`$(basename "$REPORT_FILE")\`
- Scan Log: \`$(basename "$LOG_FILE")\`
- GraphQL Log: \`graphql.log\`
- Proxy Log: \`proxy.log\`

## Quick Stats
EOF
    
    # Extract stats from report
    if [[ -f "$REPORT_FILE" ]]; then
        echo "" >> "$summary_file"
        echo '```' >> "$summary_file"
        grep -E "(CRITICAL|HIGH|WARNING|INFO):" "$REPORT_FILE" | sort | uniq -c >> "$summary_file" || true
        echo '```' >> "$summary_file"
    fi
    
    log_success "Summary generated: $summary_file"
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    # Parse arguments first (before any logging)
    parse_args "$@"
    
    # Validate target URL
    if [[ -z "$TARGET_URL" ]]; then
        echo -e "${RED}[✗]${NC} Target URL is required"
        show_usage
        exit 1
    fi
    
    # Create output directory FIRST before any logging
    mkdir -p "$OUTPUT_DIR"
    
    # Setup trap for cleanup
    if [[ "$SKIP_CLEANUP" != true ]]; then
        trap cleanup EXIT INT TERM
    fi
    
    # Record start time
    START_TIME=$(date +%s)
    
    # Print banner
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "  🔒 CHEAT-ME: CI/CD Security Scanning Pipeline"
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "  Target: $TARGET_URL"
    echo "  Output: $OUTPUT_DIR"
    echo "═══════════════════════════════════════════════════════════════════════"
    echo ""
    
    # Execute pipeline
    check_prerequisites
    start_graphql_server
    start_proxy
    generate_traffic
    run_analysis
    generate_summary
    
    # Final summary
    log_success "Security scan completed successfully!"
    log_info "Results saved to: $OUTPUT_DIR"
    log_info "View report: cat $REPORT_FILE"
    
    # Calculate duration
    local duration=$(($(date +%s) - START_TIME))
    log_info "Total duration: ${duration}s"
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    echo -e "  ${GREEN}✓ Scan Complete${NC}"
    echo "═══════════════════════════════════════════════════════════════════════"
    echo ""
}

# Run main function
main "$@"
