#!/usr/bin/env bash
# =============================================================================
# Safeguard Watchdog for OpenClaw — v5 (Daemon-Centric, Minimal-Fork)
# =============================================================================
# Changes from v4:
#   1. daemon_request: eliminated python3 fork for ID injection (printf only)
#      Response _req_id left in-place (no python3 fork to strip)
#   2. File rotation detection via daemon (inode change = reset position)
#   3. Gateway restart resilience: detect rotated files, reset tracking
#   4. Faster cleanup: check every 10 cycles instead of 20
#   5. Session existence check before sending messages
#   6. Reduced python3 forks in push_filter_config (batch into single call)
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF_FILE="$SCRIPT_DIR/safeguard.conf"
ENV_FILE="$SCRIPT_DIR/safeguard.env"
PROMPT_FILE="$SCRIPT_DIR/safeguard-prompt.txt"
STATE_DIR="$SCRIPT_DIR/state"
LOG_FILE="$SCRIPT_DIR/watchdog.log"
LOCK_FILE="$SCRIPT_DIR/watchdog.lock"

# Load config and env
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"
[[ -f "$ENV_FILE"  ]] && source "$ENV_FILE"

# Log config defaults (overridden by safeguard.conf)
LOG_VERBOSITY="${LOG_VERBOSITY:-normal}"
LOG_SCAN_THRESHOLD_MS="${LOG_SCAN_THRESHOLD_MS:-500}"
LOG_CYCLE_THRESHOLD_MS="${LOG_CYCLE_THRESHOLD_MS:-2000}"
LOG_STATUS_INTERVAL="${LOG_STATUS_INTERVAL:-60}"
LOG_SLOW_THRESHOLD_MS="${LOG_SLOW_THRESHOLD_MS:-500}"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Config loaded: LOG_VERBOSITY=$LOG_VERBOSITY SCAN>${LOG_SCAN_THRESHOLD_MS}ms CYCLE>${LOG_CYCLE_THRESHOLD_MS}ms SLOW>${LOG_SLOW_THRESHOLD_MS}ms STATUS every ${LOG_STATUS_INTERVAL} cycles" >> "$LOG_FILE" 2>/dev/null

mkdir -p "$STATE_DIR"

# --- Instance guard (flock) ---
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "[$(date '+%H:%M:%S')] ERROR: Another watchdog instance is already running. Exiting."
    exit 1
fi

# =============================================================================
# Gateway call wrapper — logs summary instead of raw JSON
# =============================================================================
gateway_call() {
    local tmpfile
    tmpfile=$(mktemp)
    openclaw gateway call "$@" > "$tmpfile" 2>&1
    local rc=$?
    local output
    output=$(cat "$tmpfile")
    rm -f "$tmpfile"

    if [[ "$LOG_VERBOSITY" == "verbose" ]]; then
        echo "$output" >> "$LOG_FILE"
    else
        # Extract ok/model from JSON response for concise logging
        local ok_val model_val
        ok_val=$(echo "$output" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ok','?'))" 2>/dev/null || echo "?")
        model_val=$(echo "$output" | python3 -c "import json,sys; d=json.load(sys.stdin); e=d.get('entry',{}); print(e.get('model',''))" 2>/dev/null)
        if [[ -n "$model_val" ]]; then
            log "Gateway response: ok=$ok_val model=$model_val"
        else
            log "Gateway response: ok=$ok_val"
        fi
        # Log errors if any
        if echo "$output" | grep -qi "error\|fail\|invalid"; then
            log "Gateway error: $(echo "$output" | head -1)"
        fi
    fi
    return $rc
}
declare -A FILE_POSITIONS=()
declare -A SESSION_TURNCOUNTS=()
declare -A LAST_SIZES=()
declare -A LAST_SCAN_TIMES=()
declare -A SUSPICIOUS_UNTIL=()
declare -A LOOP_ABORTED=()
GATEWAY_QUEUE=()
LAST_GATEWAY_FLUSH=0
GATEWAY_FLUSH_INTERVAL=2

DAEMON_PID=0
DAEMON_IN_FD=0
DAEMON_OUT_FD=0
DAEMON_REQ_ID=0
DAEMON_NEEDS_RESTART=0

# Timing configuration
SCAN_BASE_MS=5000
VELOCITY_MULTIPLIER=1
EXACT_MULTIPLIER=2
SIMILARITY_MULTIPLIER=6
POLL_INTERVAL=$((SCAN_BASE_MS / 1000))
SIMILARITY_THRESHOLD="${SIMILARITY_THRESHOLD:-0.90}"
SIMILARITY_LOOKBACK="${SIMILARITY_LOOKBACK:-3}"
VELOCITY_WINDOW_SEC="${VELOCITY_WINDOW_SEC:-30}"
VELOCITY_MAX_BYTES="${VELOCITY_MAX_BYTES:-204800}"
VELOCITY_ABORT_RATE="${VELOCITY_ABORT_RATE:-5000}"
SUSPICION_DURATION="${SUSPICION_DURATION:-30}"
LOOP_ABORT_COOLDOWN="${LOOP_ABORT_COOLDOWN:-60}"
LOOP_THRESHOLD="${LOOP_THRESHOLD:-5}"
CONTEXT_TURNS="${CONTEXT_TURNS:-10}"
REJECT_THRESHOLD="${REJECT_THRESHOLD:-3}"
REJECT_WINDOW="${REJECT_WINDOW:-6}"

# Filter config
FILTER_MODE="${FILTER_MODE:-blacklist}"
FILTER_PROVIDERS="${FILTER_PROVIDERS:-}"
FILTER_AGENTS="${FILTER_AGENTS:-}"
FILTER_MODEL_PATTERNS="${FILTER_MODEL_PATTERNS:-}"

# Embedding config (for semantic similarity detection)
EMBEDDING_PROVIDER="${EMBEDDING_PROVIDER:-}"
EMBEDDING_MODEL="${EMBEDDING_MODEL:-}"
EMBEDDING_API_URL="${EMBEDDING_API_URL:-}"
EMBEDDING_API_KEY="${EMBEDDING_API_KEY:-}"

# Fallback config
ABORT_FALLBACK_MODE="${ABORT_FALLBACK_MODE:-switch}"
ABORT_FALLBACK_MODEL="${ABORT_FALLBACK_MODEL:-}"

# Emergency shutdown
EMERGENCY_SHUTDOWN_ABORT_COUNT="${EMERGENCY_SHUTDOWN_ABORT_COUNT:-5}"
EMERGENCY_SHUTDOWN_WINDOW="${EMERGENCY_SHUTDOWN_WINDOW:-300}"
EMERGENCY_SHUTDOWN_ACTION="${EMERGENCY_SHUTDOWN_ACTION:-gateway}"

# Safeguard fallback config
SAFEGUARD_FALLBACK_PROVIDER="${SAFEGUARD_FALLBACK_PROVIDER:-}"
SAFEGUARD_FALLBACK_MODEL="${SAFEGUARD_FALLBACK_MODEL:-}"
SAFEGUARD_FALLBACK_API_URL="${SAFEGUARD_FALLBACK_API_URL:-}"
SAFEGUARD_FALLBACK_API_KEY="${SAFEGUARD_FALLBACK_API_KEY:-}"
SAFEGUARD_FALLBACK_DURATION="${SAFEGUARD_FALLBACK_DURATION:-300}"

EMERGENCY_TRIGGERED=0

# Session key mapping: sessionId (UUID) -> full session key (agent:name:id)
declare -A SESSION_KEY_MAP=()

# Build session key map from all agents' sessions.json
build_session_key_map() {
    SESSION_KEY_MAP=()
    for agent_sessions in "$AGENTS_DIR"/*/sessions; do
        [[ -d "$agent_sessions" ]] || continue
        local sj="$agent_sessions/sessions.json"
        [[ -f "$sj" ]] || continue
        while IFS='=' read -r sid sessionkey; do
            SESSION_KEY_MAP["$sid"]="$sessionkey"
        done < <(python3 -c "
import json
with open('${sj}') as f:
    d = json.load(f)
for k, v in d.items():
    sid = v.get('sessionId', '')
    if sid:
        print(f'{sid}={k}')
" 2>/dev/null)
    done
    log "Session key map built: ${#SESSION_KEY_MAP[@]} entries"
}


# =============================================================================
# Logging
# =============================================================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
    echo "[$(date '+%H:%M:%S')] $*" >&2
}

rotate_log() {
    local max_size="${LOG_MAX_SIZE:-10485760}"
    [[ "$max_size" -eq 0 ]] && return
    local size
    size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    if [[ "$size" -gt "$max_size" ]]; then
        mv "$LOG_FILE" "$LOG_FILE.old"
        log "Log rotated (was ${size} bytes)"
    fi
}

# =============================================================================
# Python daemon lifecycle
# =============================================================================

start_daemon() {
    local daemon_script="$SCRIPT_DIR/safeguard_daemon.py"
    if [[ ! -f "$daemon_script" ]]; then
        log "FATAL: Daemon script not found: $daemon_script"
        exit 1
    fi
    log "[DEBUG] Starting daemon with embedding provider: ${EMBEDDING_PROVIDER:-none}, model: ${EMBEDDING_MODEL:-none}"

    # Create pipes
    local in_pipe="$STATE_DIR/daemon_in.pipe"
    local out_pipe="$STATE_DIR/daemon_out.pipe"
    rm -f "$in_pipe" "$out_pipe"
    mkfifo "$in_pipe" "$out_pipe"

    # Start daemon: reads from in_pipe, writes to out_pipe
    # Export embedding API key for daemon to read from environment
    export EMBEDDING_API_KEY="${EMBEDDING_API_KEY:-${OPENAI_API_KEY:-${COHERE_API_KEY:-${GROQ_API_KEY:-${MISTRAL_API_KEY:-${DASHSCOPE_API_KEY:-}}}}}}"
    python3 -u "$daemon_script" < "$in_pipe" > "$out_pipe" 2>>"$LOG_FILE" &
    DAEMON_PID=$!

    # Open file descriptors (must open writer first to unblock fifo open)
    exec 3>"$in_pipe"
    exec 4<"$out_pipe"

    DAEMON_IN_FD=3
    DAEMON_OUT_FD=4

    # Drain any stale data left in the output pipe from a previous daemon instance.
    # This is a safety net — stop_daemon should prevent this, but race conditions
    # (e.g., watchdog killed with SIGKILL) can leave orphaned data.
    local drain_count=0
    while IFS= read -r -t 0.1 -u 4 _drain_line 2>/dev/null; do
        drain_count=$((drain_count + 1))
    done
    [[ $drain_count -gt 0 ]] && log "Drained $drain_count stale line(s) from output pipe"

    log "Daemon started (PID=$DAEMON_PID, fd_in=$DAEMON_IN_FD, fd_out=$DAEMON_OUT_FD)"

    # Verify connectivity
    if ! daemon_ping; then
        log "WARNING: Daemon ping failed, retrying..."
        sleep 1
        daemon_ping || log "ERROR: Daemon not responding after retry"
    fi

    # Push filter config to daemon
    push_filter_config
    push_emergency_config
    push_embedding_config
}

stop_daemon() {
    if [[ $DAEMON_PID -gt 0 ]]; then
        log "Stopping daemon (PID=$DAEMON_PID)..."
        # Close BOTH file descriptors before killing daemon.
        # Closing only fd 3 (stdin) leaves fd 4 (stdout) pointing to the old pipe,
        # causing stale reads after daemon restart.
        exec 3>&- 2>/dev/null   # close daemon stdin  → daemon gets EOF
        exec 4<&- 2>/dev/null   # close daemon stdout → prevent stale pipe reads
        sleep 0.5
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
        DAEMON_PID=0
        DAEMON_IN_FD=0
        DAEMON_OUT_FD=0
    fi
    # Remove old pipes BEFORE creating new ones (prevents stale data from previous instance)
    rm -f "$STATE_DIR/daemon_in.pipe" "$STATE_DIR/daemon_out.pipe"
}

restart_daemon() {
    log "Restarting daemon (reason: ${1:-unknown})..."
    stop_daemon
    sleep 1
    start_daemon
}

# =============================================================================
# Daemon communication protocol (v5: NO python3 fork for ID handling)
# Sends one JSON line to daemon stdin, reads one JSON line from stdout.
# =============================================================================

daemon_request() {
    local request="$1"
    local _dr_start=$(date +%s%N)
    DAEMON_REQ_ID=$((DAEMON_REQ_ID + 1))
    local req_id="rq${DAEMON_REQ_ID}_$$"

    # Inject request ID via pure bash (no python3 fork — keeps v5 minimal-fork design)
    # Strip trailing }, inject _req_id, re-close.
    # NOTE: Cannot use ${var%}} because bash parses the first } as closing the
    # parameter expansion, leaving the pattern as just '%' which never matches '}'.
    # This silently produced {"key":"val"}} (double-brace invalid JSON).
    # Use sed to safely strip the last '}' character.
    local trimmed="${request%"${request##*[![:space:]]}"}"
    if [[ "$trimmed" == *"\"_req_id\""* ]]; then
        : # already has _req_id
    elif [[ "$trimmed" == *"}" ]]; then
        request="$(sed 's/}$//' <<< "$trimmed"),\"_req_id\":\"${req_id}\"}"
    else
        log "ERROR: Request is not valid JSON object: ${request:0:80}"
        echo '{"status":"error","error":"invalid request JSON"}'
        return 1
    fi

    # Send request
    if ! echo "$request" >&"$DAEMON_IN_FD" 2>/dev/null; then
        log "ERROR: Failed to write to daemon (broken pipe?)"
        # DO NOT call restart_daemon here — this function runs inside $(...)
        # subshells and FD reassignments would not propagate to the parent.
        DAEMON_NEEDS_RESTART=1
        echo '{"status":"daemon_dead","error":"daemon unreachable"}'
        return 1
    fi

    # Read response with timeout and ID matching
    local response=""
    local attempts=0
    local max_attempts=3
    while [[ $attempts -lt $max_attempts ]]; do
        if ! IFS= read -r -t 15 response <&"$DAEMON_OUT_FD" 2>/dev/null; then
            log "ERROR: Daemon response timeout or EOF (attempt $((attempts+1)))"
            attempts=$((attempts + 1))
            if [[ $attempts -ge $max_attempts ]]; then
                # DO NOT call restart_daemon here — runs in subshell
                DAEMON_NEEDS_RESTART=1
                echo '{"status":"daemon_dead","error":"daemon timeout"}'
                return 1
            fi
            continue
        fi

        # Check response ID matches.
        # NOTE: Python 3.12+ json.dumps outputs ": " (space after colon) by default.
        # Match both with and without space to be version-safe.
        if [[ "$response" == *"\"_req_id\": \"${req_id}\""* ]] || \
           [[ "$response" == *"\"_req_id\":\"${req_id}\""* ]]; then
            # Return response as-is (daemon already includes _req_id, caller ignores it)
            local _dr_end=$(date +%s%N)
            local _dr_ms=$(((_dr_end - _dr_start) / 1000000))
            [[ ${LOG_SLOW_THRESHOLD_MS:-500} -gt 0 ]] && [[ $_dr_ms -gt ${LOG_SLOW_THRESHOLD_MS:-500} ]] && log "[SLOW] daemon_request: ${_dr_ms}ms action=$(echo "$request" | python3 -c 'import json,sys;print(json.loads(sys.stdin.read()).get("action","?"))' 2>/dev/null)"
            echo "$response"
            return 0
        else
            log "WARN: Stale response (expected req_id '$req_id') — discarding"
            attempts=$((attempts + 1))
        fi
    done

    echo '{"status":"error","error":"daemon response mismatch"}'
    return 1
}

# Check if daemon needs restart (call in PARENT context, never in subshell)
daemon_check_restart() {
    if [[ $DAEMON_NEEDS_RESTART -eq 1 ]]; then
        DAEMON_NEEDS_RESTART=0
        log "Daemon flagged for restart (set by subshell) — restarting in parent context"
        restart_daemon "subshell_flag"
    fi
}

daemon_ping() {
    local resp
    resp=$(daemon_request '{"action":"ping"}')
    daemon_check_restart
    [[ "$resp" == *'"pong"'* ]]
}

# =============================================================================
# Push config to daemon (single python3 fork for all arrays)
# =============================================================================

push_filter_config() {
    # Convert all comma-separated values to JSON arrays in ONE python3 call
    local all_json
    all_json=$(python3 -c "
import json, sys

def csv_to_arr(s):
    return [x.strip() for x in s.split(',') if x.strip()] if s.strip() else []

providers = csv_to_arr(sys.argv[1])
agents = csv_to_arr(sys.argv[2])
models = csv_to_arr(sys.argv[3])
print(json.dumps(providers))
print(json.dumps(agents))
print(json.dumps(models))
" "$FILTER_PROVIDERS" "$FILTER_AGENTS" "$FILTER_MODEL_PATTERNS" 2>/dev/null)

    local providers_json agents_json models_json
    providers_json=$(echo "$all_json" | sed -n '1p')
    agents_json=$(echo "$all_json" | sed -n '2p')
    models_json=$(echo "$all_json" | sed -n '3p')

    # Use printf for the request (no python3 fork)
    local req
    printf -v req '{"action":"update_config","filter_mode":"%s","filter_providers":%s,"filter_agents":%s,"filter_model_patterns":%s}' \
        "$FILTER_MODE" "${providers_json:-[]}" "${agents_json:-[]}" "${models_json:-[]}"

    daemon_request "$req" >/dev/null 2>&1
    log "Filter config pushed: mode=$FILTER_MODE providers=$FILTER_PROVIDERS agents=$FILTER_AGENTS models=$FILTER_MODEL_PATTERNS"
}

push_emergency_config() {
    local req
    printf -v req '{"action":"update_config","emergency_threshold":%d,"emergency_window":%d}' \
        "$EMERGENCY_SHUTDOWN_ABORT_COUNT" "$EMERGENCY_SHUTDOWN_WINDOW"
    daemon_request "$req" >/dev/null 2>&1
}

push_embedding_config() {
    local enabled="false"
    [[ -n "${EMBEDDING_PROVIDER:-}" ]] && enabled="true"

    local model="${EMBEDDING_MODEL:-}"
    local url="${EMBEDDING_API_URL:-}"
    local provider="${EMBEDDING_PROVIDER:-}"

    local req
    printf -v req '{"action":"update_config","embedding_enabled":%s,"embedding_provider":"%s","embedding_model":"%s","embedding_url":"%s"}' \
        "$enabled" "$provider" "$model" "$url"
    daemon_request "$req" >/dev/null 2>&1
    log "Embedding config pushed: enabled=$enabled provider=$provider model=$model url=$url"

    # Push fallback embedding config
    if [[ -n "${SAFEGUARD_FALLBACK_PROVIDER:-}" ]]; then
        local fb_model="${SAFEGUARD_FALLBACK_MODEL:-}"
        local fb_url="${SAFEGUARD_FALLBACK_API_URL:-}"
        local fb_key="${SAFEGUARD_FALLBACK_API_KEY:-}"
        printf -v req '{"action":"update_config","fallback_embedding_provider":"%s","fallback_embedding_model":"%s","fallback_embedding_url":"%s","fallback_embedding_api_key":"%s","fallback_duration":%s}' \
            "$SAFEGUARD_FALLBACK_PROVIDER" "$fb_model" "$fb_url" "$fb_key" "${SAFEGUARD_FALLBACK_DURATION:-300}"
        daemon_request "$req" >/dev/null 2>&1
        log "Fallback embedding config pushed: provider=$SAFEGUARD_FALLBACK_PROVIDER model=$fb_model"
    fi
}

# =============================================================================
# Session filter check via daemon
# =============================================================================

bash_pre_filter() {
    local session_file="$1"
    local agent=""

    IFS='/' read -ra parts <<< "$session_file"
    for i in "${!parts[@]}"; do
        if [[ "${parts[$i]}" == "agents" && $((i+1)) -lt ${#parts[@]} ]]; then
            agent="${parts[$((i+1))]}"
            break
        fi
    done

    local agent_lower
    agent_lower=$(echo "$agent" | tr '[:upper:]' '[:lower:]')

    if [[ "$FILTER_MODE" == "blacklist" ]]; then
        if [[ -n "$FILTER_AGENTS" && -n "$agent_lower" ]]; then
            local match=0
            IFS=',' read -ra flist <<< "$FILTER_AGENTS"
            for f in "${flist[@]}"; do
                f=$(echo "$f" | tr '[:upper:]' '[:lower:]' | xargs)
                [[ "$f" == "$agent_lower" ]] && match=1 && break
            done
            [[ $match -eq 1 ]] && return 1
        fi
        if [[ -z "$FILTER_PROVIDERS" && -z "$FILTER_MODEL_PATTERNS" ]]; then
            return 0
        fi
        return 2
    else
        if [[ -n "$FILTER_AGENTS" && -n "$agent_lower" ]]; then
            local match=0
            IFS=',' read -ra flist <<< "$FILTER_AGENTS"
            for f in "${flist[@]}"; do
                f=$(echo "$f" | tr '[:upper:]' '[:lower:]' | xargs)
                [[ "$f" == "$agent_lower" ]] && match=1 && break
            done
            [[ $match -eq 1 ]] && return 0
        fi
        if [[ -z "$FILTER_PROVIDERS" && -z "$FILTER_MODEL_PATTERNS" ]]; then
            return 1
        fi
        return 2
    fi
}

should_monitor_session() {
    local session_file="$1"
    local session_id="$2"

    local pre_result
    bash_pre_filter "$session_file"
    pre_result=$?
    [[ $pre_result -eq 1 ]] && return 1
    [[ $pre_result -eq 0 ]] && return 0

    local resp
    resp=$(daemon_request "{\"action\":\"filter_check\",\"file\":\"${session_file}\",\"session_id\":\"${session_id}\"}")
    [[ "$resp" == *'"monitor":true'* ]]
}

# =============================================================================
# Tool-call scanning via daemon (batch, no fork)
# =============================================================================

scan_tool_calls() {
    local session_file="$1"
    local start_offset="$2"
    local end_offset="$3"

    local request
    printf -v request '{"action":"tool_scan","file":"%s","start":%d,"end":%d}' \
        "$session_file" "$start_offset" "$end_offset"
    daemon_request "$request"
}

# =============================================================================
# Loop detection via daemon (no fork)
# =============================================================================

check_loop_daemon() {
    local session_file="$1"
    local layer="${2:-all}"
    

    local request
    printf -v request '{"action":"loop_check","file":"%s","layer":"%s","sim_threshold":%s,"sim_lookback":%d,"exact_threshold":%d}' \
        "$session_file" "$layer" "$SIMILARITY_THRESHOLD" "$SIMILARITY_LOOKBACK" "$LOOP_THRESHOLD"
    local resp
    resp=$(daemon_request "$request")

    echo "$resp"
}

# =============================================================================
# Context extraction via daemon
# =============================================================================

extract_context_daemon() {
    local session_file="$1"
    local trigger_line="$2"
    local context_turns="${CONTEXT_TURNS:-3}"

    local request
    printf -v request '{"action":"extract_context","file":"%s","trigger_line":%d,"context_turns":%d}' \
        "$session_file" "$trigger_line" "$context_turns"

    local resp
    resp=$(daemon_request "$request")

    # Extract context field from JSON response (single python3 call)
    echo "$resp" | python3 -c "
import json, sys
r = json.loads(sys.stdin.read())
print(r.get('context', ''))
" 2>/dev/null
}

# =============================================================================
# Decision parsing via daemon
# =============================================================================

parse_decision_daemon() {
    local response_json="$1"


    # Build daemon request in python3, then call daemon_request directly (no subshell pipeline)
    local req_payload
    req_payload=$(python3 -c "
import json, sys
escaped = json.dumps(sys.stdin.read())
print('{\"action\":\"parse_decision\",\"response\":' + escaped + '}')
" <<< "$response_json")


    if [[ -z "$req_payload" ]]; then
        echo "ERROR"
        echo "None"
        echo "Failed to build parse_decision request"
        echo ""
        return
    fi

    local resp
    resp=$(daemon_request "$req_payload")


    # Output 4 lines: decision, violation_type, feedback, reasoning
    echo "$resp" | python3 -c "
import json, sys
r = json.loads(sys.stdin.read())
print(r.get('decision', 'ERROR'))
print(r.get('violation_type', 'None'))
print(r.get('feedback', ''))
print(r.get('reasoning', ''))
" 2>/dev/null
}

# =============================================================================
# File change check via daemon (skip unchanged files, detect rotation)
# =============================================================================

daemon_file_changed() {
    local session_file="$1"
    local resp
    resp=$(daemon_request "{\"action\":\"check_file_changed\",\"file\":\"${session_file}\"}")
    [[ "$resp" == *'"changed":true'* ]]
}

daemon_file_rotated() {
    local session_file="$1"
    local resp
    resp=$(daemon_request "{\"action\":\"check_file_changed\",\"file\":\"${session_file}\"}")
    [[ "$resp" == *'"rotated":true'* ]]
}

daemon_init_file() {
    local session_file="$1"
    daemon_request "{\"action\":\"init_file\",\"file\":\"${session_file}\"}" >/dev/null 2>&1
}

# =============================================================================
# Record abort via daemon (for emergency shutdown tracking)
# =============================================================================

record_abort_daemon() {
    local resp
    resp=$(daemon_request '{"action":"record_abort"}')
    local count emergency
    count=$(echo "$resp" | python3 -c "import json,sys; print(json.loads(sys.stdin.read()).get('abort_count',0))" 2>/dev/null)
    emergency=$(echo "$resp" | python3 -c "import json,sys; r=json.loads(sys.stdin.read()); print('yes' if r.get('emergency') else 'no')" 2>/dev/null)

    echo "${count:-0}|${emergency:-no}"
}

# =============================================================================
# Velocity detection (pure bash arithmetic — zero overhead)
# =============================================================================

check_token_velocity() {
    local session_id="$1"
    local current_size="$2"
    local now
    now=$(date +%s)

    local prev_size="${LAST_SIZES[$session_id]:-$current_size}"
    local prev_time="${LAST_SCAN_TIMES[$session_id]:-$now}"

    LAST_SIZES[$session_id]=$current_size
    LAST_SCAN_TIMES[$session_id]=$now

    local elapsed=$((now - prev_time))
    [[ $elapsed -le 0 ]] && return 1

    local growth=$((current_size - prev_size))
    [[ $growth -le 0 ]] && return 1

    if [[ $elapsed -le $VELOCITY_WINDOW_SEC && $growth -gt $VELOCITY_MAX_BYTES ]]; then
        local rate=$((growth / elapsed))
        if [[ $rate -gt $VELOCITY_ABORT_RATE ]]; then
            log "!!! VELOCITY ALERT: $session_id grew ${growth}B in ${elapsed}s (${rate}B/s > ${VELOCITY_ABORT_RATE}B/s)"
            return 0
        fi
    fi

    return 1
}

# =============================================================================
# Emergency shutdown
# =============================================================================

trigger_emergency_shutdown() {
    local reason="$1"
    local abort_count="$2"

    if [[ $EMERGENCY_TRIGGERED -eq 1 ]]; then
        return
    fi
    EMERGENCY_TRIGGERED=1

    log "🚨🚨🚨 EMERGENCY SHUTDOWN TRIGGERED 🚨🚨🚨"
    log "Reason: $reason"
    log "Abort count: $abort_count (threshold: ${EMERGENCY_SHUTDOWN_ABORT_COUNT})"
    log "Action: ${EMERGENCY_SHUTDOWN_ACTION}"

    # Notify all active sessions
    for agent_sessions in "$AGENTS_DIR"/*/sessions; do
        [[ -d "$agent_sessions" ]] || continue
        for f in "$agent_sessions"/*.jsonl; do
            [[ -f "$f" ]] || continue
            local sid
            sid=$(basename "$f" .jsonl)
            send_to_session "$sid" "[EMERGENCY] 緊急停止: ${abort_count}回のabortが発生しました。Gatewayを停止します。原因: ${reason}"
        done
    done

    # Flush pending messages
    flush_gateway_queue
    sleep 2

    if [[ "$EMERGENCY_SHUTDOWN_ACTION" == "system" ]]; then
        log "Executing system shutdown..."
        sudo shutdown -h now "Safeguard emergency shutdown: $reason" 2>>"$LOG_FILE" &
    else
        log "Stopping OpenClaw gateway (CLI)..."
        openclaw gateway stop 2>>"$LOG_FILE" &
        for svc in openclaw-gateway.service openclaw.service; do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                log "Stopping systemd service: $svc"
                sudo systemctl stop "$svc" 2>>"$LOG_FILE" &
                sudo systemctl reset-failed "$svc" 2>>"$LOG_FILE" &
                break
            fi
        done
    fi

    sleep 3
    log "Watchdog exiting after emergency shutdown."
    stop_daemon
    exit 1
}

# =============================================================================
# Unified loop abort
# =============================================================================

abort_loop() {
    local session_id="$1"
    local reason="$2"
    local now
    now=$(date +%s)

    local last_abort="${LOOP_ABORTED[$session_id]:-0}"
    if [[ $((now - last_abort)) -lt $LOOP_ABORT_COOLDOWN ]]; then
        log "SKIP abort for $session_id — cooldown active (${LOOP_ABORT_COOLDOWN}s)"
        return
    fi

    LOOP_ABORTED[$session_id]=$now
    log "!!! LOOP ABORT: $session_id — $reason !!!"

    abort_session "$session_id"

    # Record abort for emergency tracking
    local result
    result=$(record_abort_daemon)
    local abort_count="${result%%|*}"
    local emergency="${result##*|}"

    log "Global abort count: $abort_count / ${EMERGENCY_SHUTDOWN_ABORT_COUNT} (window: ${EMERGENCY_SHUTDOWN_WINDOW}s)"

    if [[ "$emergency" == "yes" ]]; then
        trigger_emergency_shutdown "$reason" "$abort_count"
        return
    fi

    apply_fallback "$session_id" "$reason"

    unset "LAST_SIZES[$session_id]"
    unset "LAST_SCAN_TIMES[$session_id]"
    unset "SUSPICIOUS_UNTIL[$session_id]"
}

# =============================================================================
# Abort fallback — model switch / resume / none
# =============================================================================

apply_fallback() {
    local session_id="$1"
    local reason="$2"

    # Resolve sessionId to full session key
    local mapped="${SESSION_KEY_MAP[$session_id]:-}"
    [[ -n "$mapped" ]] && session_id="$mapped"

    case "$ABORT_FALLBACK_MODE" in
        switch)
            local model_info=""
            if [[ -n "$ABORT_FALLBACK_MODEL" ]]; then
                model_info=" (fallback model: ${ABORT_FALLBACK_MODEL})"
                # Request model switch via gateway
                gateway_call sessions.patch \
                    --params "{\"key\":\"$session_id\",\"model\":\"$ABORT_FALLBACK_MODEL\"}" \
                    --timeout 30000 &
            else
                model_info=" (using system fallback model)"
            fi

            local warning="[SAFEGUARD FALLBACK] 暴走ループを検知したため中断・切り替えました。原因: ${reason}${model_info}。方針を変えて作業を再開してください。"
            local escaped_warning
            escaped_warning=$(printf '%s' "$warning" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
            gateway_call sessions.send --params "{\"sessionKey\":\"$session_id\",\"message\":$escaped_warning}" --timeout 30000
            log "FALLBACK switch: $session_id — injected warning and requested model switch"
            ;;

        resume)
            local warning="[SAFEGUARD RESUME] 暴走ループを検知したため中断しました。原因: ${reason}。方針を変えて作業を再開してください。"
            send_to_session "$session_id" "$warning"
            log "FALLBACK resume: $session_id — injected warning (no model switch)"
            ;;

        none)
            log "FALLBACK none: $session_id — abort only, no resume injection"
            ;;

        *)
            log "WARNING: Unknown ABORT_FALLBACK_MODE='$ABORT_FALLBACK_MODE', using 'none'"
            ;;
    esac
}

# =============================================================================
# Rejection fallback
# =============================================================================

apply_reject_fallback() {
    local session_id="$1"
    local violation_type="$2"
    local feedback="$3"

    # Resolve sessionId to full session key
    local mapped="${SESSION_KEY_MAP[$session_id]:-}"
    [[ -n "$mapped" ]] && session_id="$mapped"

    case "$ABORT_FALLBACK_MODE" in
        switch)
            local model_info=""
            if [[ -n "$ABORT_FALLBACK_MODEL" ]]; then
                model_info=" (fallback model: ${ABORT_FALLBACK_MODEL})"
                gateway_call sessions.patch \
                    --params "{\"key\":\"$session_id\",\"model\":\"$ABORT_FALLBACK_MODEL\"}" \
                    --timeout 30000 &
            fi
            local warning="[SAFEGUARD REJECT FALLBACK] 安全違反を検知 (${violation_type})。モデルを切り替えて作業を再開してください。${model_info} 助言: ${feedback}"
            send_to_session "$session_id" "$warning"
            ;;

        resume)
            local warning="[SAFEGUARD REJECT] 安全違反 (${violation_type})。方針を変えて再開してください。助言: ${feedback}"
            send_to_session "$session_id" "$warning"
            ;;

        none)
            send_to_session "$session_id" "/stop"
            ;;
    esac
}

# =============================================================================
# Context extraction (wrapper)
# =============================================================================

extract_context() {
    local session_file="$1"
    local trigger_line="$2"
    local context_turns="${CONTEXT_TURNS:-3}"
    extract_context_daemon "$session_file" "$trigger_line" "$context_turns"
}

# =============================================================================
# Safeguard API (curl — single fork, fast)
# =============================================================================

call_safeguard() {
    local context="$1"
    local system_prompt
    system_prompt="$(cat "$PROMPT_FILE" 2>/dev/null || echo 'You are a safety reviewer.')"

    local api_url="${SAFEGUARD_API_URL:-}"
    local api_key="${SAFEGUARD_API_KEY:-${OPENROUTER_API_KEY:-}}"
    local provider="${SAFEGUARD_PROVIDER:-openai-compatible}"
    local model="${SAFEGUARD_MODEL:-openai/gpt-oss-safeguard-20b}"

    # Determine effective URL from provider defaults
    if [[ -z "$api_url" ]]; then
        case "$provider" in
            cohere)       api_url="https://api.cohere.ai/v1/chat" ;;
            groq)         api_url="https://api.groq.com/openai/v1/chat/completions" ;;
            mistral)      api_url="https://api.mistral.ai/v1/chat/completions" ;;
            dashscope)    api_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions" ;;
            nvidia-nim)   api_url="https://integrate.api.nvidia.com/v1/chat/completions" ;;
            local)        api_url="http://localhost:11434/v1/chat/completions" ;;
            *)            api_url="https://openrouter.ai/api/v1/chat/completions" ;;
        esac
    fi

    local fallback_url="${SAFEGUARD_FALLBACK_API_URL:-}"
    local fallback_key="${SAFEGUARD_FALLBACK_API_KEY:-}"
    local fallback_provider="${SAFEGUARD_FALLBACK_PROVIDER:-}"
    local fallback_model="${SAFEGUARD_FALLBACK_MODEL:-}"
    local fallback_duration="${SAFEGUARD_FALLBACK_DURATION:-300}"

    # Determine fallback URL from provider defaults if not set
    if [[ -z "$fallback_url" && -n "$fallback_provider" ]]; then
        case "$fallback_provider" in
            cohere)       fallback_url="https://api.cohere.ai/v1/chat" ;;
            groq)         fallback_url="https://api.groq.com/openai/v1/chat/completions" ;;
            mistral)      fallback_url="https://api.mistral.ai/v1/chat/completions" ;;
            dashscope)    fallback_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions" ;;
            nvidia-nim)   fallback_url="https://integrate.api.nvidia.com/v1/chat/completions" ;;
            local)        fallback_url="http://localhost:11434/v1/chat/completions" ;;
            *)            fallback_url="https://openrouter.ai/api/v1/chat/completions" ;;
        esac
    fi

    if [[ -z "$api_key" ]]; then
        log "ERROR: No API key set (SAFEGUARD_API_KEY or OPENROUTER_API_KEY)"
        echo '[SAFEGUARD WARNING] No API key configured — proceeding without LLM safeguard check.'
        return 1
    fi



    # Helper to invoke the python3 request block
    invoke_safeguard() {
        local p="$1" m="$2" u="$3" k="$4"
        printf '%s' "$context" | python3 -c "
import json, sys, urllib.request, urllib.error

provider = sys.argv[1]
model    = sys.argv[2]
api_url  = sys.argv[3]
api_key  = sys.argv[4]
prompt   = sys.argv[5]
ctx      = sys.stdin.read().rstrip('\n')

if provider == 'cohere':
    payload = json.dumps({'model': model, 'message': ctx, 'preamble': prompt, 'max_tokens': 1024, 'temperature': 0.1})
else:
    payload = json.dumps({'model': model, 'messages': [{'role': 'system', 'content': prompt}, {'role': 'user', 'content': ctx}], 'max_tokens': 1024, 'temperature': 0.1})

req = urllib.request.Request(api_url, data=payload.encode(), method='POST')
req.add_header('Authorization', 'Bearer ' + api_key)
req.add_header('Content-Type', 'application/json')

try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = json.loads(resp.read())
except urllib.error.HTTPError as e:
    body = e.read().decode(errors='replace')[:300]
    print(json.dumps({'error': {'message': f'HTTP {e.code}: {body}'}}))
    sys.exit(0)
except Exception as e:
    print(json.dumps({'error': {'message': str(e)}}))
    sys.exit(0)

if 'error' in raw:
    print(json.dumps(raw)); sys.exit(0)

if provider == 'cohere':
    content = ''
    msg = raw.get('message', {})
    if isinstance(msg, dict):
        content = msg.get('content', '')
        if isinstance(content, list): content = ' '.join(str(c) for c in content if c)
        content = str(content)
    normalized = {'choices': [{'message': {'role': 'assistant', 'content': content}}], 'model': raw.get('model', model)}
    print(json.dumps(normalized))
else:
    print(json.dumps(raw))
" "$p" "$m" "$u" "$k" "$system_prompt" 2>>"$LOG_FILE"
    return $?
    }

    # --- Primary attempt ---
    local response
    response=$(invoke_safeguard "$provider" "$model" "$api_url" "$api_key")

    if [[ -n "$response" && "$response" != *'"error"'* ]]; then
        echo "$response"
        return 0
    fi

    log "[SG] Primary failed, trying fallback..."

    # --- Fallback attempt ---
    if [[ -n "$fallback_key" && -n "$fallback_url" ]]; then
        local fb_model="${fallback_model:-${SAFEGUARD_MODEL:-openai/gpt-oss-safeguard-20b}}"
        local fb_provider="${fallback_provider:-$provider}"
        response=$(invoke_safeguard "$fb_provider" "$fb_model" "$fallback_url" "$fallback_key")

        if [[ -n "$response" && "$response" != *'"error"'* ]]; then
            log "[SG] Fallback succeeded"
            echo "$response"
            return 0
        fi
        log "[SG] Fallback also failed"
    fi

    # --- Both failed: inject warning-only message ---
    log "[SG] Both primary and fallback failed — injecting warning"
    echo '[SAFEGUARD WARNING] Could not verify safety. Proceed with caution.'
}

parse_decision() {
    local response="$1"
    parse_decision_daemon "$response"
}

# =============================================================================
# Rejection state tracking
# =============================================================================

get_turn_counter() {
    local session_id="$1"
    local counter_file="$STATE_DIR/${session_id}.turn"
    if [[ -f "$counter_file" ]]; then cat "$counter_file"; else echo "0"; fi
}

increment_turn_counter() {
    local session_id="$1"
    local counter_file="$STATE_DIR/${session_id}.turn"
    local current
    current=$(get_turn_counter "$session_id")
    echo $((current + 1)) > "$counter_file"
    echo $((current + 1))
}

record_rejection() {
    local session_id="$1"
    local turn_num="$2"
    echo "$turn_num" >> "$STATE_DIR/${session_id}.rejects"
}

count_recent_rejections() {
    local session_id="$1"
    local current_turn="$2"
    local window="${REJECT_WINDOW:-5}"
    local state_file="$STATE_DIR/${session_id}.rejects"
    [[ ! -f "$state_file" ]] && { echo "0"; return; }

    local count=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ ^[0-9]+$ ]] && [[ $line -gt $((current_turn - window)) ]]; then
            count=$((count + 1))
        fi
    done < "$state_file"
    echo "$count"
}

reset_rejections() {
    local session_id="$1"
    rm -f "$STATE_DIR/${session_id}.rejects" "$STATE_DIR/${session_id}.turn"
}

# =============================================================================
# Gateway communication
# =============================================================================

queue_gateway_call() {
    local session_id="$1"
    local message="$2"
    local escaped_message
    escaped_message=$(printf '%s' "$message" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
    GATEWAY_QUEUE+=("${session_id}|${escaped_message}")
}

flush_gateway_queue() {
    local now
    now=$(date +%s)
    [[ $((now - LAST_GATEWAY_FLUSH)) -lt $GATEWAY_FLUSH_INTERVAL ]] && return
    [[ ${#GATEWAY_QUEUE[@]} -eq 0 ]] && return

    LAST_GATEWAY_FLUSH=$now
    local batch_size=5 processed=0

    for i in "${!GATEWAY_QUEUE[@]}"; do
        [[ $processed -ge $batch_size ]] && break
        local entry="${GATEWAY_QUEUE[$i]}"
        local sid="${entry%%|*}" msg="${entry#*|}"

        # sid is a full sessionKey (e.g. agent:main:main) — chat.send accepts sessionKey directly
        # No need to check for .jsonl file by sessionKey name; the gateway resolves it.

        # Use chat.send (correct RPC method)
        local idempotent_key="safeguard-${sid}-$(date +%s)-${processed}"
        log "SEND -> $sid: ${msg:0:120}..."
        gateway_call chat.send \
            --params "{\"sessionKey\":\"$sid\",\"message\":$msg,\"idempotencyKey\":\"$idempotent_key\"}" \
            --timeout 30000 &
        processed=$((processed + 1))
    done

    GATEWAY_QUEUE=("${GATEWAY_QUEUE[@]:$processed}")
    wait 2>/dev/null
}

abort_session() {
    local session_id="$1"
    log "ABORT -> $session_id"

    # session_id is a full sessionKey — chat.abort accepts sessionKey directly

    # Use chat.abort (correct RPC method)
    gateway_call chat.abort \
        --params "{\"sessionKey\":\"$session_id\"}" \
        --timeout 30000
    local rc=$?
    [[ $rc -eq 0 ]] && log "ABORT OK: $session_id" || log "ABORT FAILED (rc=$rc): $session_id"
}

send_to_session() {
    local target_session_id="$1"
    local message="$2"
    
    # Resolve sessionId (filename) to full session key via SESSION_KEY_MAP
    if [[ "$target_session_id" != agent:* ]]; then
        local mapped="${SESSION_KEY_MAP[$target_session_id]:-}"
        if [[ -n "$mapped" ]]; then
            target_session_id="$mapped"
        fi
    fi
    
    queue_gateway_call "$target_session_id" "$message"
}

# =============================================================================
# Process a dangerous tool call: extract context → safeguard API → decide
# =============================================================================

process_dangerous_call() {
    local session_file="$1"
    local session_id="$2"
    local line_num="$3"
    local danger_info="$4"

    local turn
    turn=$(increment_turn_counter "$session_id")
    log "--- DANGEROUS TOOL_CALL in $session_id (line $line_num, turn $turn): $danger_info ---"

    local context
    context=$(extract_context "$session_file" "$line_num")
    if [[ -z "$context" ]]; then
        log "ERROR: Failed to extract context. Allowing with warning."
        send_to_session "$session_id" "[SAFEGUARD WARNING] Could not verify: $danger_info. Proceed with caution."
        return
    fi

    local response
    response=$(call_safeguard "$context")

    if [[ -z "$response" ]]; then
        log "ERROR: Empty safeguard response. Allowing with warning."
        send_to_session "$session_id" "[SAFEGUARD WARNING] Could not verify. Proceed with caution: $danger_info"
        return
    fi

    local result
    result=$(parse_decision "$response")
    local decision violation_type feedback reasoning
    decision=$(echo "$result" | sed -n '1p')
    violation_type=$(echo "$result" | sed -n '2p')
    feedback=$(echo "$result" | sed -n '3p')
    reasoning=$(echo "$result" | sed -n '4p')

    log "Safeguard DECISION: $decision | Violation: $violation_type | Reasoning: ${reasoning:0:200}"

    if [[ "$decision" == "APPROVE" ]]; then
        send_to_session "$session_id" "[SAFEGUARD APPROVE] $danger_info - You may proceed."
        log "Sent APPROVE to $session_id (turn $turn)"

    elif [[ "$decision" == "REJECT" ]]; then
        record_rejection "$session_id" "$turn"
        local recent_count
        recent_count=$(count_recent_rejections "$session_id" "$turn")
        log "REJECT #$recent_count (within last ${REJECT_WINDOW:-5} turns) for $session_id"

        if [[ $recent_count -ge ${REJECT_THRESHOLD:-2} ]]; then
            abort_session "$session_id"

            local abort_result
            abort_result=$(record_abort_daemon)
            local abort_count="${abort_result%%|*}"
            local emergency="${abort_result##*|}"

            if [[ "$emergency" == "yes" ]]; then
                trigger_emergency_shutdown "Repeated rejections ($recent_count in session)" "$abort_count"
                return
            fi

            apply_reject_fallback "$session_id" "$violation_type" "$feedback"
            reset_rejections "$session_id"
        else
            send_to_session "$session_id" "[SAFEGUARD REJECT #$recent_count/${REJECT_THRESHOLD:-2} — $violation_type] $feedback"
        fi
    else
        log "ERROR: Unexpected decision '$decision'. Allowing with warning."
        send_to_session "$session_id" "[SAFEGUARD WARNING] Could not determine safety. Proceed: $danger_info"
    fi
}

# =============================================================================
# Reset session tracking (after file rotation / gateway restart)
# =============================================================================

reset_session_tracking() {
    local session_id="$1"
    local session_file="$2"

    log "[ROTATE] $session_id — file rotated, resetting tracking"
    local current_size
    current_size=$(stat -c%s "$session_file" 2>/dev/null || echo 0)
    FILE_POSITIONS[$session_id]=$current_size
    LAST_SIZES[$session_id]=$current_size
    LAST_SCAN_TIMES[$session_id]=$(date +%s)
    daemon_init_file "$session_file"
    unset "SUSPICIOUS_UNTIL[$session_id]"
    unset "LOOP_ABORTED[$session_id]"
}

# =============================================================================
# Session scanning
# =============================================================================

scan_session() {
    local session_file="$1"
    local session_id
    session_id=$(basename "$session_file" .jsonl)
    local _ss_start=$(date +%s%N)

    # --- File filter check ---
    if ! should_monitor_session "$session_file" "$session_id"; then
        return
    fi

    local _ss_after_filter=$(date +%s%N)

    # --- File rotation detection (gateway restart resilience) ---
    local current_size
    current_size=$(stat -c%s "$session_file" 2>/dev/null || echo 0)
    local pos="${FILE_POSITIONS[$session_id]:-0}"

    # Check for file rotation (inode change) via daemon
    if [[ $pos -gt 0 ]]; then
        local resp
        resp=$(daemon_request "{\"action\":\"check_file_changed\",\"file\":\"${session_file}\"}")
        if [[ "$resp" == *'"rotated":true'* ]]; then
            reset_session_tracking "$session_id" "$session_file"
            return
        fi
    fi

    # Initialize on first scan — record position and SKIP historical scanning.
    # Scanning the entire file from the beginning would fire on all past tool calls
    # and spam sessions with stale warnings/rejections.
    if [[ $pos -eq 0 ]]; then
        FILE_POSITIONS[$session_id]=$current_size
        LAST_SIZES[$session_id]=$current_size
        LAST_SCAN_TIMES[$session_id]=$(date +%s)
        daemon_init_file "$session_file"
        return
    fi

    # File shrank (truncated/rotated) — reset
    if [[ $current_size -lt $pos ]]; then
        reset_session_tracking "$session_id" "$session_file"
        return
    fi

    # No new data — skip entirely
    if [[ $current_size -le $pos ]]; then
        return
    fi

    local now
    now=$(date +%s)

    # --- Cooldown check ---
    local last_abort="${LOOP_ABORTED[$session_id]:-0}"
    if [[ $((now - last_abort)) -lt $LOOP_ABORT_COOLDOWN ]]; then
        FILE_POSITIONS[$session_id]=$current_size
        return
    fi
    local _ss_after_cooldown=$(date +%s%N)

    # --- Layer 2: Velocity (pure bash, every scan) ---
    if check_token_velocity "$session_id" "$current_size"; then
        abort_loop "$session_id" "Token velocity exceeded (${VELOCITY_ABORT_RATE}B/s threshold)"
        FILE_POSITIONS[$session_id]=$current_size
        return
    fi

    local should_check_velocity=1
    local should_check_exact=0
    local should_check_similarity=0

    # Velocity: every scan (VELOCITY_MULTIPLIER=1 means every scan)
    if [[ $((scan_count % VELOCITY_MULTIPLIER)) -ne 0 ]]; then
        should_check_velocity=0
    fi
    # Exact: every EXACT_MULTIPLIER scans
    if [[ $((scan_count % EXACT_MULTIPLIER)) -eq 0 ]]; then
        should_check_exact=1
    fi
    # Similarity: every SIMILARITY_MULTIPLIER scans
    if [[ $((scan_count % SIMILARITY_MULTIPLIER)) -eq 0 ]]; then
        should_check_similarity=1
    fi

    # Order: Velocity → Exact → Similarity → LLM Safeguard (break on first trigger)
    local _ss_before_checks=$(date +%s%N)
    local _ss_after_velocity=$_ss_before_checks
    local _ss_after_exact=$_ss_before_checks
    local _ss_after_similarity=$_ss_before_checks

    # --- Layer: Velocity (pure bash, every scan) ---
    if [[ $should_check_velocity -eq 1 ]]; then
        if check_token_velocity "$session_id" "$current_size"; then
            abort_loop "$session_id" "Token velocity exceeded (${VELOCITY_ABORT_RATE}B/s threshold)"
            FILE_POSITIONS[$session_id]=$current_size
            return
        fi
    fi

    # --- Layer: Exact loop (exact match, every EXACT_MULTIPLIER scans) ---
    local _ss_after_velocity=$(date +%s%N)
    if [[ $should_check_exact -eq 1 ]]; then
        local exact_resp
        exact_resp=$(check_loop_daemon "$session_file" "exact")
        if [[ "$exact_resp" == *'"status":"ok"'* || "$exact_resp" == *'"status": "ok"'* ]]; then
            local exact_val
            exact_val=$(echo "$exact_resp" | python3 -c "
import json, sys
r = json.loads(sys.stdin.read())
e = r.get('exact', 'OK')
print(e)
" 2>/dev/null)
            if [[ "$exact_val" == LOOP:* ]]; then
                abort_loop "$session_id" "Exact-match loop (${exact_val#LOOP:} consecutive repeats)"
                FILE_POSITIONS[$session_id]=$current_size
                return
            fi
        fi
    fi

    # --- Layer: Similarity (semantic, every SIMILARITY_MULTIPLIER scans) ---
    local _ss_after_exact=$(date +%s%N)
    if [[ $should_check_similarity -eq 1 ]]; then
        local sim_resp
        sim_resp=$(check_loop_daemon "$session_file" "similarity")
        if [[ "$sim_resp" == *'"status":"ok"'* || "$sim_resp" == *'"status": "ok"'* ]]; then
            local sim_val
            sim_val=$(echo "$sim_resp" | python3 -c "
import json, sys
r = json.loads(sys.stdin.read())
s = r.get('similarity', 'OK:0.0')
print(s)
" 2>/dev/null)

            if [[ "$sim_val" == LOOP:* ]]; then
                abort_loop "$session_id" "Similarity loop (score=${sim_val#LOOP:}, threshold=${SIMILARITY_THRESHOLD})"
                FILE_POSITIONS[$session_id]=$current_size
                return
            elif [[ "$sim_val" == OK:* ]]; then
                local avg="${sim_val#OK:}"
                local is_high
                is_high=$(python3 -c "
t = ${SIMILARITY_THRESHOLD} - 0.1
print('yes' if float('${avg}') > t else 'no')
" 2>/dev/null)
                if [[ "$is_high" == "yes" ]]; then
                    SUSPICIOUS_UNTIL[$session_id]=$((now + SUSPICION_DURATION))
                    log "SUSPICIOUS: $session_id avg_similarity=$avg — fast-check for ${SUSPICION_DURATION}s"
                fi
            fi
        fi
    fi

    # --- Layer: LLM Safeguard (tool-call scan) ---
    local _ss_after_similarity=$(date +%s%N)
    if [[ -n "${SUSPICIOUS_UNTIL[$session_id]:-}" && ${SUSPICIOUS_UNTIL[$session_id]} -gt $now ]]; then
        local scan_resp
        scan_resp=$(scan_tool_calls "$session_file" "$pos" "$current_size")

        if [[ "$scan_resp" == *'"status":"ok"'* || "$scan_resp" == *'"status": "ok"'* ]]; then
            local dangerous_offsets
            dangerous_offsets=$(echo "$scan_resp" | python3 -c "
import json, sys
r = json.loads(sys.stdin.read())
for d in r.get('dangerous', []):
    dangers_str = ' | '.join(d['dangers'])
    line_num = d.get('line_num', 1)
    print(f\"{d['offset']}|{line_num}|{dangers_str}\")
" 2>/dev/null)

            if [[ -n "$dangerous_offsets" ]]; then
                while IFS='|' read -r offset line_num dangers; do
                    [[ -z "$offset" ]] && continue
                    [[ -z "$line_num" ]] && line_num=1
                    process_dangerous_call "$session_file" "$session_id" "$line_num" "$dangers"
                done <<< "$dangerous_offsets"
            fi
        fi
    fi

    local _ss_end=$(date +%s%N)
    local _t_total=$(((_ss_end - _ss_start)/1000000))
    # Only log if something interesting happened or took > threshold
    if [[ ${LOG_SCAN_THRESHOLD_MS:-0} -eq 0 ]] || [[ $_t_total -gt ${LOG_SCAN_THRESHOLD_MS:-500} ]] || [[ -n "${SUSPICIOUS_UNTIL[$session_id]:-}" ]] || [[ -n "${LOOP_ABORTED[$session_id]:-}" ]]; then
        log "[SCAN] $session_id: ${_t_total}ms suspicious=${SUSPICIOUS_UNTIL[$session_id]:-no} aborted=${LOOP_ABORTED[$session_id]:-no}"
    fi
    FILE_POSITIONS[$session_id]=$current_size
}

# =============================================================================
# Housekeeping
# =============================================================================

cleanup_positions() {
    local now
    now=$(date +%s)

    for sid in "${!FILE_POSITIONS[@]}"; do
        local found=0
        for agent_sessions in "$AGENTS_DIR"/*/sessions; do
            [[ -d "$agent_sessions" ]] || continue
            if [[ -f "$agent_sessions/${sid}.jsonl" ]]; then
                found=1
                break
            fi
        done
        if [[ $found -eq 0 ]]; then
            unset "FILE_POSITIONS[$sid]"
            unset "SESSION_TURNCOUNTS[$sid]"
            unset "LAST_SIZES[$sid]"
            unset "LAST_SCAN_TIMES[$sid]"
            unset "SUSPICIOUS_UNTIL[$sid]"
            unset "LOOP_ABORTED[$sid]"
            log "Cleaned up stale session: $sid"
        fi
    done

    for sid in "${!SUSPICIOUS_UNTIL[@]}"; do
        [[ ${SUSPICIOUS_UNTIL[$sid]} -lt $now ]] && unset "SUSPICIOUS_UNTIL[$sid]"
    done

    for sid in "${!LOOP_ABORTED[@]}"; do
        [[ $((now - LOOP_ABORTED[$sid])) -gt $((LOOP_ABORT_COOLDOWN * 2)) ]] && unset "LOOP_ABORTED[$sid]"
    done
}

# =============================================================================
# Signal handling
# =============================================================================

SHUTDOWN=0
shutdown_handler() {
    log "Shutting down watchdog (signal received)..."
    SHUTDOWN=1
}
trap shutdown_handler SIGTERM SIGINT EXIT

# =============================================================================
# Entry point
# =============================================================================

main() {
    log "=========================================="
    log "  Safeguard Watchdog v5 (MINIMAL-FORK)"
    log "  Poll: ${POLL_INTERVAL}s"
    log "  Context: ${CONTEXT_TURNS} turns"
    log "  Reject: ${REJECT_THRESHOLD} within ${REJECT_WINDOW} turns"
    log "  Filter: mode=${FILTER_MODE} providers=${FILTER_PROVIDERS:-all} agents=${FILTER_AGENTS:-all}"
    log "  Fallback: mode=${ABORT_FALLBACK_MODE} model=${ABORT_FALLBACK_MODEL:-system default}"
    log "  Emergency: ${EMERGENCY_SHUTDOWN_ABORT_COUNT} aborts in ${EMERGENCY_SHUTDOWN_WINDOW}s → ${EMERGENCY_SHUTDOWN_ACTION}"
    log "  --- Loop Detection (via daemon) ---"
    log "  L1 Similarity: threshold=${SIMILARITY_THRESHOLD} lookback=${SIMILARITY_LOOKBACK}"
    log "  L2 Velocity:   ${VELOCITY_MAX_BYTES}B in ${VELOCITY_WINDOW_SEC}s (${VELOCITY_ABORT_RATE}B/s)"
    log "  L3 Exact:      ${LOOP_THRESHOLD} consecutive repeats"
    log "  Cooldown:      ${LOOP_ABORT_COOLDOWN}s after abort"
    log "=========================================="

    # Start Python analysis daemon
    start_daemon
    # Build session key map from sessions.json
    build_session_key_map
    
    # Log what we're monitoring
    local _monitored=0
    for agent_sessions in "$AGENTS_DIR"/*/sessions; do
        [[ -d "$agent_sessions" ]] || continue
        for f in "$agent_sessions"/*.jsonl; do
            [[ -f "$f" ]] || continue
            _monitored=$((_monitored+1))
        done
    done
    log "Monitoring $_monitored session files across all agents"

    if [[ -n "${1:-}" ]]; then
        # --- Single session mode ---
        local session_file=""
        for agent_sessions in "$AGENTS_DIR"/*/sessions; do
            if [[ -f "$agent_sessions/${1}.jsonl" ]]; then
                session_file="$agent_sessions/${1}.jsonl"
                break
            fi
        done
        if [[ -z "$session_file" ]]; then
            log "ERROR: Session not found: ${1}"
            stop_daemon
            exit 1
        fi

        scan_count=0
        while [[ $SHUTDOWN -eq 0 ]]; do
            scan_session "$session_file"
            daemon_check_restart
            flush_gateway_queue
            scan_count=$((scan_count + 1))
            sleep "$POLL_INTERVAL"
        done

    else
        # --- All sessions mode ---
        # Iterate sessions.json directly (no glob, no filename guessing)
        local cleanup_counter=0
        local rotation_counter=0
        scan_count=0

        while [[ $SHUTDOWN -eq 0 ]]; do
            local _cycle_start=$(date +%s%N)
            local session_entries
            session_entries=$(python3 -c "
import json, glob, os
for sj in glob.glob('${AGENTS_DIR}/*/sessions/sessions.json'):
    with open(sj) as f:
        d = json.load(f)
    agent_dir = os.path.dirname(os.path.dirname(sj))
    for k, v in d.items():
        sid = v.get('sessionId', '')
        if not sid:
            continue
        # Try UUID filename first, then sessionKey-derived filename
        fpath = os.path.join(agent_dir, 'sessions', sid + '.jsonl')
        if not os.path.isfile(fpath):
            parts = k.split(':')
            if len(parts) > 1:
                fpath = os.path.join(agent_dir, 'sessions', parts[-1] + '.jsonl')
        if os.path.isfile(fpath):
            print(f'{sid}|{k}|{fpath}')
" 2>/dev/null)

            while IFS='|' read -r sid sessionkey fpath; do
                [[ -z "$sid" ]] && continue
                scan_session "$fpath"
            done <<< "$session_entries"

            daemon_check_restart
            flush_gateway_queue

            scan_count=$((scan_count + 1))
            cleanup_counter=$((cleanup_counter + 1))
            if [[ $cleanup_counter -ge 10 ]]; then
                cleanup_counter=0
                cleanup_positions
            fi

            rotation_counter=$((rotation_counter + 1))
            if [[ $rotation_counter -ge 600 ]]; then
                rotation_counter=0
                rotate_log
            fi

            local _cycle_end=$(date +%s%N)
            local _cycle_ms=$(((_cycle_end - _cycle_start) / 1000000))
            local _cpu=$(ps -p $$ -o %cpu= 2>/dev/null | tr -d ' ')
            local _rss=$(ps -p $$ -o rss= 2>/dev/null | tr -d ' ')
            local _daemon_cpu=$(ps -p $DAEMON_PID -o %cpu= 2>/dev/null | tr -d ' ')
            local _daemon_rss=$(ps -p $DAEMON_PID -o rss= 2>/dev/null | tr -d ' ')
            # Count suspicious and aborted sessions
            local _susp_count=0 _abort_count=0
            for _sid in "${!SUSPICIOUS_UNTIL[@]}"; do [[ ${SUSPICIOUS_UNTIL[$_sid]} -gt $(date +%s) ]] && _susp_count=$((_susp_count+1)); done
            for _sid in "${!LOOP_ABORTED[@]}"; do _abort_count=$((_abort_count+1)); done
            # Only log cycle if something interesting or slow
            if [[ ${LOG_CYCLE_THRESHOLD_MS:-0} -eq 0 ]] || [[ $_cycle_ms -gt ${LOG_CYCLE_THRESHOLD_MS:-2000} ]] || [[ $_susp_count -gt 0 ]] || [[ $_abort_count -gt 0 ]]; then
                log "[CYCLE] #$scan_count: ${_cycle_ms}ms cpu=${_cpu}% rss=${_rss}KB daemon_cpu=${_daemon_cpu}% daemon_rss=${_daemon_rss}KB suspicious=$_susp_count aborted=$_abort_count"
            fi

            # Periodic status log every ~5 minutes (60 cycles at 5s interval)
            if [[ ${LOG_STATUS_INTERVAL:-0} -gt 0 ]] && [[ $((scan_count % LOG_STATUS_INTERVAL)) -eq 0 ]]; then
                local _active_sessions=0
                for _sid in "${!FILE_POSITIONS[@]}"; do _active_sessions=$((_active_sessions+1)); done
                log "[STATUS] alive: cycle=$scan_count sessions=$_active_sessions suspicious=$_susp_count aborted=$_abort_count daemon_pid=$DAEMON_PID"
            fi

            sleep "$POLL_INTERVAL"
        done
    fi

    stop_daemon
    log "Watchdog stopped cleanly."
}

main "$@"
