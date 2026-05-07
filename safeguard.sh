#!/usr/bin/env bash
# =============================================================================
# Safeguard Watchdog Manager — Start/Stop/Status/Panic (v5)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCK_FILE="$SCRIPT_DIR/watchdog.lock"
PID_FILE="$SCRIPT_DIR/watchdog.pid"
LOG_FILE="$SCRIPT_DIR/watchdog.log"
PANIC_PID_FILE="$SCRIPT_DIR/panic_button.pid"

usage() {
    cat <<EOF
Safeguard Watchdog Manager v4

Usage: $(basename "$0") <command>

Commands:
  start       Start watchdog in background
  stop        Stop watchdog
  restart     Restart watchdog
  status      Check watchdog status
  log         Tail watchdog log (Ctrl+C to exit)
  panic       Launch panic button (GUI if display available, else terminal)
  panic-term  Launch panic button in terminal mode
  install     Install systemd service (requires sudo)
  uninstall   Remove systemd service (requires sudo)

EOF
}

start_watchdog() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Watchdog already running (PID=$pid)"
            return 0
        fi
    fi

    echo "Starting Safeguard Watchdog v4..."
    nohup bash "$SCRIPT_DIR/watchdog.sh" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    echo "Started (PID=$(cat "$PID_FILE")). Log: $LOG_FILE"
}

stop_watchdog() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Stopping watchdog (PID=$pid)..."
            kill "$pid" 2>/dev/null
            # Wait for clean shutdown
            local waited=0
            while kill -0 "$pid" 2>/dev/null && [[ $waited -lt 10 ]]; do
                sleep 1
                waited=$((waited + 1))
            done
            if kill -0 "$pid" 2>/dev/null; then
                echo "Force killing..."
                kill -9 "$pid" 2>/dev/null
            fi
            echo "Stopped."
        else
            echo "Watchdog not running (stale PID file)."
        fi
        rm -f "$PID_FILE"
    else
        echo "No PID file. Trying flock-based detection..."
        if flock -n "$LOCK_FILE" true 2>/dev/null; then
            echo "Watchdog is not running."
        else
            echo "Watchdog appears running but no PID file. Kill manually if needed."
        fi
    fi
}

show_status() {
    echo "=== Safeguard Watchdog v4 Status ==="
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Status: RUNNING (PID=$pid)"
            echo "CPU/Mem: $(ps -p "$pid" -o %cpu,%mem --no-headers 2>/dev/null || echo 'N/A')"
        else
            echo "Status: STOPPED (stale PID file)"
        fi
    else
        echo "Status: STOPPED"
    fi

    if [[ -f "$LOG_FILE" ]]; then
        echo ""
        echo "Last 5 log lines:"
        tail -5 "$LOG_FILE"
    fi

    # Daemon check
    local daemon_pid
    daemon_pid=$(pgrep -f "safeguard_daemon.py" 2>/dev/null || echo "")
    if [[ -n "$daemon_pid" ]]; then
        echo ""
        echo "Daemon: RUNNING (PID=$daemon_pid)"
    else
        echo ""
        echo "Daemon: NOT RUNNING"
    fi

    # Panic button check
    if [[ -f "$PANIC_PID_FILE" ]]; then
        local ppid
        ppid=$(cat "$PANIC_PID_FILE")
        if kill -0 "$ppid" 2>/dev/null; then
            echo "Panic Button: ACTIVE (PID=$ppid)"
        else
            echo "Panic Button: NOT RUNNING"
            rm -f "$PANIC_PID_FILE"
        fi
    else
        echo "Panic Button: NOT RUNNING"
    fi
}

show_log() {
    if [[ -f "$LOG_FILE" ]]; then
        tail -f "$LOG_FILE"
    else
        echo "No log file yet."
    fi
}

launch_panic() {
    local mode="${1:-gui}"
    echo "Launching Panic Button ($mode mode)..."
    if [[ "$mode" == "terminal" ]]; then
        python3 "$SCRIPT_DIR/panic_button.py" --terminal &
    else
        python3 "$SCRIPT_DIR/panic_button.py" &
    fi
    echo $! > "$PANIC_PID_FILE"
    echo "Panic Button started (PID=$(cat "$PANIC_PID_FILE"))"
}

install_service() {
    local user
    user=$(whoami)
    local service_file="$SCRIPT_DIR/safeguard-watchdog.service"

    if [[ ! -f "$service_file" ]]; then
        echo "ERROR: Service file not found: $service_file"
        return 1
    fi

    # Patch user in service file
    local installed="/etc/systemd/system/safeguard-watchdog.service"
    sudo cp "$service_file" "$installed"
    sudo sed -i "s/User=wakaru-kun/User=$user/" "$installed"
    sudo sed -i "s|/home/wakaru-kun/|$HOME/|g" "$installed"
    sudo systemctl daemon-reload
    sudo systemctl enable safeguard-watchdog.service
    echo "Service installed. Start with: sudo systemctl start safeguard-watchdog"
}

uninstall_service() {
    sudo systemctl stop safeguard-watchdog.service 2>/dev/null || true
    sudo systemctl disable safeguard-watchdog.service 2>/dev/null || true
    sudo rm -f /etc/systemd/system/safeguard-watchdog.service
    sudo systemctl daemon-reload
    echo "Service uninstalled."
}

case "${1:-}" in
    start)      start_watchdog ;;
    stop)       stop_watchdog ;;
    restart)    stop_watchdog; sleep 1; start_watchdog ;;
    status)     show_status ;;
    log)        show_log ;;
    panic)      launch_panic gui ;;
    panic-term) launch_panic terminal ;;
    install)    install_service ;;
    uninstall)  uninstall_service ;;
    *)          usage ;;
esac
