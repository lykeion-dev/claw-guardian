# 🛡️ claw-guardian

**Because your AI agent doesn't come with a conscience — claw-guardian adds one.**

Real-time safety watchdog for [OpenClaw](https://github.com/openclaw/openclaw). Monitors AI agent sessions, detects dangerous operations, and intervenes before damage is done.

claw-guardian is a watchdog system that monitors AI agent sessions in real-time, detects dangerous or destructive behavior, and intervenes automatically — before damage is done.

## How It Works

```
OpenClaw Agent → tool calls → claw-guardian (watchdog)
                                      │
                              ┌───────┴───────┐
                              │  safeguard.py  │  ← Embedding-based loop detection
                              │  (daemon)      │
                              └───────┬───────┘
                                      │
                              ┌───────┴───────┐
                              │  AI judgment   │  ← LLM-based policy evaluation
                              │  (safeguard)   │
                              └───────┬───────┘
                                      │
                              ┌───────┴───────┐
                              │  Action        │
                              │  APPROVE/REJECT│
                              │  ABORT/SWITCH  │
                              └───────────────┘
```

### Two-Component Architecture

1. **`watchdog.sh`** — Main monitoring loop. Scans agent session transcripts, detects dangerous tool calls, and coordinates intervention.
2. **`safeguard_daemon.py`** — Python daemon for embedding-based semantic similarity analysis and loop detection.

### Detection Layers

| Order | Layer | What it detects | Method |
|-------|-------|----------------|--------|
| 1st | **L2** — Velocity | Token velocity spikes | Bytes/second threshold |
| 2nd | **L1** — Similarity | Semantic repetition loops | Embedding similarity (cosine) |
| 3rd | **L3** — Exact Match | Exact repeated tool calls | Consecutive identical calls |
| 4th | **Policy** | Dangerous operations | LLM-based judgment |

### Policy Enforcement

The safeguard AI evaluates each tool call against these policies:

- **Unsafe File Operations** — modifications without backup
- **Destructive Commands** — `rm -rf`, `dd`, `mkfs`, etc.
- **Privilege Escalation** — unauthorized `sudo`, permission changes
- **Unauthorized Config Changes** — modifying system/agent config without approval
- **Credential Tampering** — changing API keys, tokens, passwords
- **Directive Tampering** — modifying AGENTS.md, SOUL.md, MEMORY.md
- **Service Disruption** — stopping critical services
- **Repetitive Execution Loops** — same command repeated without variation
- **Improper Session Management** — spawning duplicate sessions

### Intervention Levels

1. **REJECT** — Block the tool call, inject warning into agent session
2. **ABORT** — Abort the agent session via `chat.abort`
3. **FALLBACK** — Switch to a safer model and resume
4. **EMERGENCY** — Kill the gateway after repeated violations (optional)

## Quick Start

### Prerequisites

- OpenClaw installed and running
- Bash 4+, Python 3.8+
- API keys for safeguard model and embedding provider

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/claw-guardian.git
cd claw-guardian
cp safeguard.env.example safeguard.env
# Edit safeguard.env with your API keys
```

### Configuration

Edit `safeguard.conf` to customize:

```bash
# Safeguard model (LLM for policy judgment)
SAFEGUARD_PROVIDER="nvidia-nim"
SAFEGUARD_MODEL="nvidia/nemotron-content-safety-reasoning-4b"

# Embedding model (for loop detection)
EMBEDDING_PROVIDER="cohere"
EMBEDDING_MODEL="embed-v4.0"

# Detection thresholds
SIMILARITY_THRESHOLD=0.85
VELOCITY_MAX_BYTES=100000
LOOP_THRESHOLD=3

# Log verbosity: verbose | normal | quiet
LOG_VERBOSITY="normal"
```

Edit `safeguard.env` with your actual API keys:

```bash
NVIDIA_API_KEY=your_key_here
COHERE_API_KEY=your_key_here
OPENROUTER_API_KEY=your_key_here
```

### Running

```bash
# Start the watchdog
./safeguard.sh start

# Check status
./safeguard.sh status

# Stop
./safeguard.sh stop
```

### Systemd Service (optional)

```bash
sudo cp claw-guardian.service /etc/systemd/system/
sudo systemctl enable claw-guardian
sudo systemctl start claw-guardian
```

## Configuration Reference

### Log Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_VERBOSITY` | `normal` | `verbose` (full JSON), `normal` (summary), `quiet` (errors only) |
| `LOG_SCAN_THRESHOLD_MS` | `500` | Minimum scan duration to log `[SCAN]` (0 = always) |
| `LOG_CYCLE_THRESHOLD_MS` | `2000` | Minimum cycle duration to log `[CYCLE]` (0 = always) |
| `LOG_STATUS_INTERVAL` | `60` | Cycles between `[STATUS]` output (0 = disable) |
| `LOG_SLOW_THRESHOLD_MS` | `500` | Daemon request duration for `[SLOW]` warning (0 = disable) |

### Detection Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SIMILARITY_THRESHOLD` | `0.85` | Cosine similarity threshold for loop detection |
| `SIMILARITY_LOOKBACK` | `3` | Number of recent turns to compare |
| `VELOCITY_MAX_BYTES` | `100000` | Max bytes in velocity window |
| `LOOP_THRESHOLD` | `3` | Consecutive identical calls to trigger abort |
| `REJECT_THRESHOLD` | `2` | REJECTs within window to trigger abort |
| `REJECT_WINDOW` | `4` | Turn window for reject counting |

### Filter Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `FILTER_MODE` | `whitelist` | `whitelist` (only listed) or `blacklist` (exclude listed) |
| `FILTER_AGENTS` | `main` | Comma-separated agent IDs |
| `FILTER_PROVIDERS` | `` | Comma-separated providers |
| `FILTER_MODEL_PATTERNS` | `` | Comma-separated model name patterns |

## Log Output Examples

```
[2026-05-08 02:08:16] [SCAN] 344e2b53: 1780ms suspicious=no aborted=no
[2026-05-08 02:08:16] [CYCLE] #451: 2184ms cpu=1.0% rss=5436KB daemon_cpu=0.0% daemon_rss=24644KB suspicious=0 aborted=0
[2026-05-08 02:10:55] [STATUS] alive: cycle=480 sessions=17 suspicious=0 aborted=0 daemon_pid=1649654
[2026-05-08 01:23:09] [SLOW] daemon_request: 858ms action=loop_check
```

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

Built for the [OpenClaw](https://github.com/openclaw/openclaw) ecosystem.
Developed by lykeion-dev.
