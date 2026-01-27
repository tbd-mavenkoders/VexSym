#!/bin/bash
#
# VexHelix Memory-Monitored Runner
# Restarts uvicorn when memory usage exceeds threshold
#
# Usage: ./run_vexhelix_monitored.sh [port] [workers] [memory_limit_gb]
#
# Examples:
#   ./run_vexhelix_monitored.sh              # Default: port 8001, 12 workers, 40GB limit
#   ./run_vexhelix_monitored.sh 8000 8 32    # Port 8000, 8 workers, 32GB limit
#

# Configuration (can be overridden by command line args)
PORT=${1:-8001}
WORKERS=${2:-24}
MEMORY_LIMIT_GB=${3:-40}
CHECK_INTERVAL_SECONDS=5

# Convert GB to KB for comparison (free reports in KB)
MEMORY_LIMIT_KB=$((MEMORY_LIMIT_GB * 1024 * 1024))

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="$SCRIPT_DIR/venv"
LOG_FILE="$SCRIPT_DIR/vexhelix_monitored.log"
PID_FILE="$SCRIPT_DIR/vexhelix.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] $1" | tee -a "$LOG_FILE"
}

log_info() {
    log "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    log "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    log "${RED}[ERROR]${NC} $1"
}

get_memory_usage_kb() {
    # Get total memory used by uvicorn processes in KB
    local mem_kb=0
    if [ -f "$PID_FILE" ]; then
        local main_pid=$(cat "$PID_FILE")
        # Sum memory of main process and all children (worker processes)
        mem_kb=$(ps -o rss= -p $main_pid 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
        # Also get child processes
        local children_mem=$(pgrep -P $main_pid 2>/dev/null | xargs -I{} ps -o rss= -p {} 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
        if [ -n "$children_mem" ] && [ "$children_mem" -gt 0 ] 2>/dev/null; then
            mem_kb=$((mem_kb + children_mem))
        fi
    fi
    echo ${mem_kb:-0}
}

get_memory_usage_gb() {
    local mem_kb=$(get_memory_usage_kb)
    # Convert KB to GB using awk (no bc needed)
    echo "$mem_kb" | awk '{printf "%.2f", $1 / 1024 / 1024}'
}

start_server() {
    log_info "Starting VexHelix server on port $PORT with $WORKERS workers..."
    
    # Activate virtual environment and start uvicorn
    cd "$SCRIPT_DIR"
    source "$VENV_PATH/bin/activate"
    
    # Start uvicorn in background
    nohup uvicorn vexhelix.api.server:app \
        --host 0.0.0.0 \
        --port "$PORT" \
        --workers "$WORKERS" \
        >> "$LOG_FILE" 2>&1 &
    
    local pid=$!
    echo $pid > "$PID_FILE"
    
    # Wait a bit for server to start
    sleep 5
    
    # Check if server started successfully
    if kill -0 $pid 2>/dev/null; then
        log_info "VexHelix started with PID $pid"
        return 0
    else
        log_error "Failed to start VexHelix"
        return 1
    fi
}

stop_server() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 $pid 2>/dev/null; then
            log_warn "Stopping VexHelix (PID $pid)..."
            
            # Kill main process and all children
            pkill -P $pid 2>/dev/null
            kill $pid 2>/dev/null
            
            # Wait for graceful shutdown
            local wait_count=0
            while kill -0 $pid 2>/dev/null && [ $wait_count -lt 10 ]; do
                sleep 1
                wait_count=$((wait_count + 1))
            done
            
            # Force kill if still running
            if kill -0 $pid 2>/dev/null; then
                log_warn "Force killing VexHelix..."
                pkill -9 -P $pid 2>/dev/null
                kill -9 $pid 2>/dev/null
            fi
            
            log_info "VexHelix stopped"
        fi
        rm -f "$PID_FILE"
    fi
}

restart_server() {
    local mem_gb=$(get_memory_usage_gb)
    log_warn "Memory limit exceeded! Current: ${mem_gb}GB, Limit: ${MEMORY_LIMIT_GB}GB"
    log_warn "Restarting VexHelix..."
    
    stop_server
    sleep 2
    start_server
}

is_server_running() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 $pid 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

health_check() {
    curl -s "http://127.0.0.1:$PORT/health" > /dev/null 2>&1
    return $?
}

cleanup() {
    log_info "Shutting down VexHelix monitor..."
    stop_server
    exit 0
}

# Trap signals for clean shutdown
trap cleanup SIGINT SIGTERM

# Main
echo ""
echo "=============================================="
echo "  VexHelix Memory-Monitored Runner"
echo "=============================================="
echo "  Port:          $PORT"
echo "  Workers:       $WORKERS"
echo "  Memory Limit:  ${MEMORY_LIMIT_GB}GB"
echo "  Check Interval: ${CHECK_INTERVAL_SECONDS}s"
echo "  Log File:      $LOG_FILE"
echo "=============================================="
echo ""

# Clear old log
> "$LOG_FILE"

# Stop any existing server
stop_server

# Start the server
if ! start_server; then
    log_error "Failed to start VexHelix. Exiting."
    exit 1
fi

# Wait for server to be healthy
log_info "Waiting for server to be healthy..."
health_wait=0
while ! health_check && [ $health_wait -lt 30 ]; do
    sleep 1
    health_wait=$((health_wait + 1))
done

if health_check; then
    log_info "Server is healthy!"
else
    log_warn "Server health check timed out, but continuing..."
fi

# Main monitoring loop
restart_count=0
while true; do
    sleep "$CHECK_INTERVAL_SECONDS"
    
    # Check if server is still running
    if ! is_server_running; then
        log_error "VexHelix died unexpectedly! Restarting..."
        start_server
        restart_count=$((restart_count + 1))
        continue
    fi
    
    # Check memory usage
    mem_kb=$(get_memory_usage_kb)
    mem_gb=$(get_memory_usage_gb)
    
    # Log memory usage periodically
    log_info "Memory usage: ${mem_gb}GB / ${MEMORY_LIMIT_GB}GB (restarts: $restart_count)"
    
    # Check if memory limit exceeded
    if [ "$mem_kb" -gt "$MEMORY_LIMIT_KB" ]; then
        restart_server
        restart_count=$((restart_count + 1))
    fi
done
