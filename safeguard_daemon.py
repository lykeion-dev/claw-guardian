#!/usr/bin/env python3
"""
Safeguard Analysis Daemon (v5)
Long-running process — communicates via stdin/stdout JSON-lines protocol.
All heavy logic centralized here to eliminate bash subprocess fork overhead.

Changes from v4:
  - In-memory file stat cache (mtime/size/inode) — skip unchanged files, detect file rotation
  - Context extraction moved to daemon (no python3 fork per dangerous call)
  - Decision parsing moved to daemon (no python3 fork per decision)
  - Whitelist/Blacklist session filtering
  - Abort tracking for emergency shutdown
  - File-change detection via stat polling (lightweight)
  - Request ID handled entirely in daemon (no python3 fork in bash for ID injection)
"""

import sys
import json
import re
import os
import time
import hashlib
from collections import defaultdict

# =============================================================================
# Embedding provider defaults
# =============================================================================

EMBEDDING_DEFAULTS = {
    'cohere':     {'url': 'https://api.cohere.ai/v1/embed',             'model': 'embed-v4.0'},
    'groq':       {'url': 'https://api.groq.com/openai/v1/embeddings',  'model': 'nomic-embed-text'},
    'mistral':    {'url': 'https://api.mistral.ai/v1/embeddings',       'model': 'mistral-embed'},
    'dashscope':  {'url': 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1/embeddings', 'model': 'text-embedding-v4'},
    'nvidia-nim': {'url': 'https://integrate.api.nvidia.com/v1/embeddings', 'model': 'nvidia/nv-embedqa-e5-v5'},
    'local':      {'url': 'http://localhost:11434/v1/embeddings',       'model': 'nomic-embed-text'},
    'openrouter': {'url': 'https://openrouter.ai/api/v1/embeddings',    'model': 'qwen/qwen3-embedding-8b'},
}

# Safeguard provider defaults
SAFEGUARD_DEFAULTS = {
    'cohere':     {'url': 'https://api.cohere.ai/v1/chat'},
    'groq':       {'url': 'https://api.groq.com/openai/v1/chat/completions'},
    'mistral':    {'url': 'https://api.mistral.ai/v1/chat/completions'},
    'dashscope':  {'url': 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions'},
    'nvidia-nim': {'url': 'https://integrate.api.nvidia.com/v1/chat/completions'},
    'local':      {'url': 'http://localhost:11434/v1/chat/completions'},
    'openrouter': {'url': 'https://openrouter.ai/api/v1/chat/completions'},
    'openai-compatible': {'url': 'https://api.openai.com/v1/chat/completions'},
}

# Embedding config (updated via config action or env)
_embedding_provider = ''
_embedding_model = ''
_embedding_url = ''
_embedding_api_key = ''
_embedding_enabled = False
_embedding_cache = {}  # sha256(text[:200]) -> embedding vector
_embedding_cache_max = 500

# Fallback embedding config
_fallback_embedding_provider = ''
_fallback_embedding_model = ''
_fallback_embedding_url = ''
_fallback_embedding_api_key = ''
_fallback_embedding_active = False
_fallback_activation_time = 0
_fallback_duration = 300

# =============================================================================
# Dangerous tool-call patterns
# =============================================================================

EXEC_PATTERNS = [
    (r'\brm\s+-[rf]', 'rm -rf'),
    (r'\brm\s+.*\*', 'rm with wildcard'),
    (r'\bsed\s+-i\b', 'sed -i (no backup)'),
    (r'\bdd\s+if=', 'dd command'),
    (r'\bmkfs\b', 'mkfs'),
    (r'\bfdisk\b', 'fdisk'),
    (r'\bshutdown\b', 'shutdown'),
    (r'\breboot\b', 'reboot'),
    (r'\binit\s+[06]', 'init 0/6'),
    (r'>\s*/etc/', 'write to /etc'),
    (r'>\s*/boot/', 'write to /boot'),
    (r'\bsudo\s+', 'sudo'),
    (r'\bchmod\s+777', 'chmod 777'),
    (r'\bchown\s+.*:', 'chown'),
    (r'\bcurl\s+.*\|\s*bash', 'curl | bash'),
    (r'\bwget\s+.*\|\s*bash', 'wget | bash'),
    (r'\bgateway\s+restart', 'gateway restart'),
    (r'\bsystemctl\s+restart', 'systemctl restart'),
    (r'\bsystemctl\s+stop', 'systemctl stop'),
    (r'\bdocker\s+rm', 'docker rm'),
    (r'\bdocker\s+system\s+prune', 'docker prune'),
    # Additional dangerous patterns
    (r'\bchmod\s+(\+x|[0-7]{3,4})\s+.*(agent|watchdog|openclaw|gateway)', 'chmod exec on critical binary'),
    (r'\bkill\s+-[9]', 'kill -9 (force kill)'),
    (r'\.\./.*\.\./', 'path traversal attempt'),
    (r'\bsed\s+-i\s+-e\s+.*/etc/', 'sed -i on /etc'),
    (r'\bcurl\s+-[Xk]', 'curl upload/SSRF risk'),
]

DANGEROUS_PATHS = [
    '/etc/passwd', '/etc/shadow', '/etc/sudoers',
    '/boot/', '/.ssh/', 'authorized_keys', '.pem', 'id_rsa',
]

COMPILED_EXEC = [(re.compile(p, re.IGNORECASE), d) for p, d in EXEC_PATTERNS]

# =============================================================================
# Session filter config (updated via config action)
# =============================================================================

_filter_mode = 'blacklist'
_filter_providers = set()
_filter_agents = set()
_filter_model_patterns = []

# =============================================================================
# File stat cache — skip unchanged files, detect rotation
# =============================================================================

_file_stats = {}  # path -> (mtime, size, inode)

def file_changed(path):
    """Return True if file changed since last check (includes inode change = rotation)."""
    try:
        st = os.stat(path)
        key = path
        prev = _file_stats.get(key)
        curr = (st.st_mtime, st.st_size, st.st_ino)
        if prev == curr:
            return False
        _file_stats[key] = curr
        return True
    except OSError:
        return False

def file_rotated(path):
    """Return True if file inode changed (file was replaced/rotated)."""
    try:
        st = os.stat(path)
        prev = _file_stats.get(path)
        if prev is None:
            return False
        return prev[2] != st.st_ino
    except OSError:
        return False

def file_init(path):
    """Initialize stat cache for a file (mark as seen, no change detected)."""
    try:
        st = os.stat(path)
        _file_stats[path] = (st.st_mtime, st.st_size, st.st_ino)
    except OSError:
        pass

# =============================================================================
# Abort tracking for emergency shutdown
# =============================================================================

_abort_timestamps = []  # list of time.time() when aborts occurred
_emergency_threshold = 0  # 0 = disabled
_emergency_window = 300

def record_abort():
    """Record an abort event. Returns total count within window."""
    now = time.time()
    _abort_timestamps.append(now)
    cutoff = now - _emergency_window
    while _abort_timestamps and _abort_timestamps[0] < cutoff:
        _abort_timestamps.pop(0)
    return len(_abort_timestamps)

def get_abort_count():
    """Get current abort count within window."""
    now = time.time()
    cutoff = now - _emergency_window
    while _abort_timestamps and _abort_timestamps[0] < cutoff:
        _abort_timestamps.pop(0)
    return len(_abort_timestamps)

def check_emergency():
    """Returns True if emergency shutdown threshold is reached."""
    if _emergency_threshold <= 0:
        return False
    return get_abort_count() >= _emergency_threshold

# =============================================================================
# Embedding client (multi-provider)
# =============================================================================

def _embedding_provider_defaults():
    """Resolve URL/model from provider name if not explicitly set."""
    global _embedding_url, _embedding_model
    if not _embedding_provider:
        return
    defaults = EMBEDDING_DEFAULTS.get(_embedding_provider, {})
    if not _embedding_url and defaults.get('url'):
        _embedding_url = defaults['url']
    if not _embedding_model and defaults.get('model'):
        _embedding_model = defaults['model']

def get_embedding(text):
    """Get embedding vector for text. Returns list[float] or None on failure."""
    if not _embedding_enabled or not _embedding_api_key or not _embedding_url:
        return None

    # Cache by content hash
    cache_key = hashlib.sha256(text[:500].encode()).hexdigest()[:24]
    if cache_key in _embedding_cache:
        return _embedding_cache[cache_key]

    def _do_fetch(provider, model, url, api_key):
        import urllib.request
        import urllib.error

        # Build request per provider
        if provider == 'cohere':
            payload = json.dumps({
                'model': model or 'embed-english-v3.0',
                'texts': [text[:2000]],
                'input_type': 'classification',
                'truncate': 'END',
            })
        else:
            # OpenAI-compatible: openai, groq, mistral, dashscope, nvidia-nim, local, openrouter
            payload = json.dumps({
                'model': model or 'text-embedding-3-small',
                'input': text[:2000],
            })

        req = urllib.request.Request(url, data=payload.encode(), method='POST')
        req.add_header('Authorization', 'Bearer ' + api_key)
        req.add_header('Content-Type', 'application/json')

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        # Extract vector per provider
        if provider == 'cohere':
            vec = data.get('embeddings', [[]])
            vec = vec[0] if vec else None
        else:
            items = data.get('data', [{}])
            vec = items[0].get('embedding') if items else None

        return vec

    def _log_error(provider, url, model, e):
        err_type = type(e).__name__
        err_detail = str(e)[:300]
        print(f"[daemon] Embedding error ({err_type}): {err_detail}", file=sys.stderr)
        print(f"[daemon]   provider={provider} url={url} model={model}", file=sys.stderr)
        if 'scheme' in err_detail.lower() or 'Missing scheme' in err_detail:
            print(f"[daemon]   HINT: URL must include https:// prefix. Current: '{url}'", file=sys.stderr)
        elif 'Unauthorized' in err_detail or '401' in err_detail or '403' in err_detail:
            print(f"[daemon]   HINT: Check EMBEDDING_API_KEY / COHERE_API_KEY is set and valid", file=sys.stderr)
        elif 'model' in err_detail.lower() and ('not found' in err_detail.lower() or 'invalid' in err_detail.lower()):
            print(f"[daemon]   HINT: Model name may be wrong. Current: '{model}'", file=sys.stderr)

    try:
        vec = _do_fetch(_embedding_provider, _embedding_model, _embedding_url, _embedding_api_key)
    except Exception as e:
        _log_error(_embedding_provider, _embedding_url, _embedding_model, e)
        # Fallback: if configured and not yet active (or still within active window)
        if (_fallback_embedding_url and _fallback_embedding_api_key and
                (not _fallback_embedding_active or
                 (time.time() - _fallback_activation_time) < _fallback_duration)):
            _fallback_embedding_active = True
            _fallback_activation_time = time.time()
            try:
                vec = _do_fetch(_fallback_embedding_provider, _fallback_embedding_model,
                                _fallback_embedding_url, _fallback_embedding_api_key)
            except Exception as e2:
                _log_error(_fallback_embedding_provider, _fallback_embedding_url,
                           _fallback_embedding_model, e2)
                return None
        else:
            return None

    if vec and isinstance(vec, list):
        # Evict if cache too large
        if len(_embedding_cache) >= _embedding_cache_max:
            keys = list(_embedding_cache.keys())
            for k in keys[:len(keys) // 2]:
                del _embedding_cache[k]
        _embedding_cache[cache_key] = vec
        return vec

    return None

def cosine_similarity(a, b):
    """Cosine similarity between two vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)

# =============================================================================
# Tool-call danger check
# =============================================================================

def check_line(entry):
    """Returns list of danger descriptions, or ['safe']."""
    msg = entry.get('message', {})
    if msg.get('role') != 'assistant':
        return ['safe']

    content = msg.get('content', [])
    if not isinstance(content, list):
        return ['safe']

    dangers = []
    for item in content:
        if not isinstance(item, dict) or item.get('type') != 'toolCall':
            continue

        name = item.get('name', '')
        args = item.get('arguments', {})

        if name == 'exec':
            cmd = args.get('command', '')
            if isinstance(cmd, str):
                for pat, desc in COMPILED_EXEC:
                    if pat.search(cmd):
                        dangers.append(f'exec:{desc}: {cmd[:100]}')

        elif name in ('edit', 'write'):
            path = args.get('path', args.get('file_path', args.get('filePath', '')))
            if isinstance(path, str):
                for dp in DANGEROUS_PATHS:
                    if dp in path:
                        dangers.append(f'{name}:editing {path}')

        elif name == 'gateway':
            action = args.get('action', '')
            if action in ('restart', 'config.apply', 'config.patch', 'update.run'):
                dangers.append(f'gateway:{action}')

        elif name == 'sessions_spawn':
            agent_id = args.get('agentId', '')
            task = str(args.get('task', ''))[:100]
            dangers.append(
                f'sessions_spawn:agent={agent_id} task={task}. '
                'Check existing sessions before spawning.'
            )

        elif name == 'subagents':
            action = args.get('action', '')
            target = args.get('target', '')
            if action == 'kill':
                dangers.append(
                    f'subagents:kill on {target}. '
                    'Consider using sessions_send to resume instead.'
                )

    return dangers if dangers else ['safe']

# =============================================================================
# Session filtering
# =============================================================================

def session_matches_filter(session_file, session_id, metadata=None):
    """
    Returns True if session should be MONITORED.
    Applies whitelist/blacklist filtering based on config.
    """
    agent = ''
    parts = session_file.replace('\\', '/').split('/')
    try:
        agents_idx = parts.index('agents')
        if agents_idx + 1 < len(parts):
            agent = parts[agents_idx + 1]
    except ValueError:
        pass

    provider = (metadata.get('provider', '') if metadata else '').lower()
    model = (metadata.get('model', '') if metadata else '').lower()
    agent_lower = agent.lower()

    matched = False
    checks = []
    if _filter_providers:
        checks.append(provider in _filter_providers)
    if _filter_agents:
        checks.append(agent_lower in _filter_agents)
    if _filter_model_patterns:
        checks.append(any(p in model for p in _filter_model_patterns))

    if not checks:
        matched = (_filter_mode != 'whitelist')
    else:
        matched = any(checks)

    if _filter_mode == 'whitelist':
        return matched
    else:
        return not matched

# =============================================================================
# Layer 1 — Similarity loop detection
# =============================================================================

def check_similarity(session_file, threshold, lookback):
    try:
        with open(session_file, 'r') as f:
            lines = f.readlines()
        lines = lines[-50:]
    except Exception:
        return 'OK:0.0'

    texts = []
    for raw in reversed(lines):
        try:
            entry = json.loads(raw.strip())
            msg = entry.get('message', {})
            if msg.get('role') != 'assistant':
                continue
            content = msg.get('content', [])
            if not isinstance(content, list):
                continue
            # Extract text from both type:text and type:thinking
            joined = '\n'.join(
                c.get('text', '') or c.get('thinking', '') for c in content
                if isinstance(c, dict) and c.get('type') in ('text', 'thinking')
            )
            if joined and len(joined) > 10:
                texts.append(joined[:500])
            if len(texts) >= lookback:
                break
        except Exception:
            pass

    if len(texts) < 2:
        return 'OK:0.0'

    # --- Embedding-based similarity (semantic) ---
    if _embedding_enabled and _embedding_api_key:
        vectors = []
        for t in texts:
            vec = get_embedding(t)
            if vec is None:
                break
            vectors.append(vec)

        if len(vectors) == len(texts):
            scores = [cosine_similarity(vectors[0], vectors[i]) for i in range(1, len(vectors))]
            avg = sum(scores) / len(scores)
            max_score = max(scores)

            if max_score >= threshold:
                return f'LOOP:{max_score:.2f}'
            return f'OK:{avg:.2f}'

    # Embedding failed — return OK without fallback
    return 'OK:0.0'

# =============================================================================
# Layer 3 — Exact-match loop detection
# =============================================================================

def check_exact(session_file, threshold):
    try:
        with open(session_file, 'r') as f:
            lines = f.readlines()
    except Exception:
        return 'OK'

    tool_parts = []
    for raw in reversed(lines):
        try:
            entry = json.loads(raw.strip())
            msg = entry.get('message', {})
            if msg.get('role') != 'assistant':
                continue
            content = msg.get('content', [])
            if not isinstance(content, list):
                continue
            # Extract toolCall info
            for c in content:
                if isinstance(c, dict) and c.get('type') == 'toolCall':
                    name = c.get('name', '')
                    args = c.get('arguments', {})
                    args_str = json.dumps(args, sort_keys=True, ensure_ascii=False)
                    tool_parts.append(f"{name}:{args_str}")
            if len(tool_parts) >= threshold * 2:
                break
        except Exception:
            pass

    if len(tool_parts) < threshold:
        return 'OK'

    max_repeat = 1
    current_repeat = 1
    for i in range(1, len(tool_parts)):
        if tool_parts[i - 1][:100] == tool_parts[i][:100]:
            current_repeat += 1
            max_repeat = max(max_repeat, current_repeat)
        else:
            current_repeat = 1

    if max_repeat >= threshold:
        return f'LOOP:{max_repeat}'
    return 'OK'

# =============================================================================
# Context extraction
# =============================================================================

def _extract_content_items(content, include_types=None):
    """
    Extract and format items from a message content list.
    Returns a formatted string.
    include_types: set of types to include. None = include all non-thinking types.
    """
    if not isinstance(content, list):
        return ''

    parts = []
    for item in content:
        if not isinstance(item, dict):
            continue
        item_type = item.get('type', '')

        if include_types and item_type not in include_types:
            continue

        if item_type == 'thinking':
            continue  # Never include internal reasoning

        if item_type == 'text':
            text = item.get('text', '')
            # Strip file attachment blocks injected by the platform:
            #   <mimo-files>{...}</mimo-files> or similar JSON file-list blocks
            # These are huge and irrelevant for safety review.
            text = re.sub(r'<mimo-files>\s*\{.*?\}\s*</mimo-files>', '[FILES ATTACHED]', text, flags=re.DOTALL)
            # Also strip base64 / data URI payloads (>200 chars of base64)
            text = re.sub(r'data:[^;]+;base64,[A-Za-z0-9+/=]{200,}', '[BASE64 DATA]', text)
            if text.strip():
                parts.append(text[:1500])

        elif item_type == 'toolCall':
            name = item.get('name', '')
            args = item.get('arguments', {})
            args_str = json.dumps(args, ensure_ascii=False)[:400]
            parts.append(f'[ToolCall: {name}] {args_str}')

        elif item_type == 'file':
            name = item.get('name', '?')
            size = item.get('size', '?')
            parts.append(f'[File: {name} ({size} bytes)]')

        # Unknown types: skip silently

    return '\n'.join(parts)


def extract_context(session_file, trigger_line, context_turns=3):
    try:
        with open(session_file, 'r') as f:
            lines = f.readlines()
    except Exception:
        return ''

    # Extract the trigger tool call (the dangerous one being evaluated)
    tool_info = ''
    idx = trigger_line - 1
    if 0 <= idx < len(lines):
        try:
            entry = json.loads(lines[idx].strip())
            msg = entry.get('message', {})
            content = msg.get('content', [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'toolCall':
                        name = item.get('name', '')
                        args = item.get('arguments', {})
                        tool_info += f"Tool: {name}\nArguments: {json.dumps(args, ensure_ascii=False)[:500]}\n\n"
        except Exception:
            pass

    # Build turns from ALL message roles (user, assistant, toolResult)
    # This gives the safeguard model the full execution context.
    turns = []
    for i, raw in enumerate(lines):
        try:
            entry = json.loads(raw.strip())
            msg = entry.get('message', {})
            role = msg.get('role', '')
            content = msg.get('content', '')

            if role == 'user':
                # User messages: text only, skip file attachments
                text = _extract_content_items(content, {'text'})
                if not text or not text.strip():
                    continue
                # Collapse long code blocks / pasted content (keep first+last line)
                # Pattern: ```...``` blocks longer than 10 lines
                def _collapse_code(m):
                    inner = m.group(1)
                    code_lines = inner.strip().split('\n')
                    if len(code_lines) > 10:
                        return f'```\n{code_lines[0]}\n  ... ({len(code_lines)} lines) ...\n{code_lines[-1]}\n```'
                    return m.group(0)
                text = re.sub(r'```[^\n]*\n(.*?)```', _collapse_code, text, flags=re.DOTALL)
                turns.append({'role': 'USER', 'content': text[:1500], 'line': i})

            elif role == 'assistant':
                # Assistant: text + toolCall (skip thinking)
                text = _extract_content_items(content)
                if not text or not text.strip():
                    continue
                turns.append({'role': 'ASSISTANT', 'content': text[:2000], 'line': i})

            elif role == 'toolResult':
                # Tool results: what did the tool actually return?
                tool_name = msg.get('toolName', 'unknown')
                is_error = msg.get('isError', False)
                text = _extract_content_items(content, {'text'})
                if not text:
                    text = '(empty result)'
                # Truncate tool results — they can be massive (file reads, etc.)
                text = text[:600]
                prefix = 'ERROR' if is_error else 'OK'
                turns.append({
                    'role': f'TOOL[{tool_name}]',
                    'content': f'({prefix}) {text}',
                    'line': i,
                })

        except Exception:
            pass

    if not turns:
        return tool_info

    # Find trigger position in turns list
    trigger_idx = None
    for tidx, t in enumerate(turns):
        if t['line'] >= idx:
            trigger_idx = tidx
            break
    if trigger_idx is None:
        trigger_idx = len(turns) - 1

    # Go back context_turns messages (not "pairs" — toolResult is its own turn)
    start = max(0, trigger_idx - context_turns)
    ctx = turns[start:trigger_idx]

    output = "## Recent Conversation History\n\n"
    for t in ctx:
        output += f"### {t['role']}:\n{t['content']}\n\n"
    output += f"## Agent's Tool Call (requires approval)\n\n{tool_info}"
    return output

# =============================================================================
# Decision parsing
# =============================================================================

def parse_decision(response_text):
    try:
        r = json.loads(response_text)
        if 'error' in r:
            err_msg = r['error'].get('message', 'unknown') if isinstance(r['error'], dict) else str(r['error'])
            return ('ERROR', 'None', f'API error: {err_msg}', '')

        content = r.get('choices', [{}])[0].get('message', {}).get('content', '')
        if not content:
            return ('ERROR', 'None', 'Empty response from safeguard model', '')

        # Strip markdown code fences (some models wrap JSON in ```json ... ```)
        content = content.strip()
        if content.startswith('```'):
            lines = content.split('\n')
            # Remove first line (```json or ```) and last line (```)
            if len(lines) > 2:
                content = '\n'.join(lines[1:-1]).strip()
            elif len(lines) == 2:
                content = lines[1].strip()

        # Try to find JSON object in the content if it's mixed with other text
        json_match = re.search(r'\{[^{}]*"decision"\s*:\s*"[^"]+"[^{}]*\}', content, re.DOTALL)
        if json_match:
            content = json_match.group(0)

        d = json.loads(content)
        # Normalize decision values (model may return Safe/Rejected instead of APPROVE/REJECT)
        raw_decision = d.get('decision', 'ERROR')
        decision_upper = raw_decision.upper()
        if decision_upper in ('APPROVE', 'SAFE', 'ALLOW', 'PERMIT', 'OK'):
            decision = 'APPROVE'
        elif decision_upper in ('REJECT', 'REJECTED', 'DENY', 'DENIED', 'BLOCK'):
            decision = 'REJECT'
        else:
            # Unrecognized decision — default to REJECT for safety.
            # Previously returned raw_decision unchanged (e.g. 'ERROR'), which
            # could be treated as APPROVE downstream.
            decision = 'REJECT'
        return (
            decision,
            d.get('violation_type', 'None'),
            d.get('feedback_to_agent', ''),
            d.get('reasoning', ''),
        )
    except Exception as e:
        return ('ERROR', 'None', f'Parse error: {e}', '')

# =============================================================================
# Batch tool-call scanning
# =============================================================================

def handle_tool_scan(req):
    file_path = req['file']
    start_offset = req['start']
    end_offset = req['end']

    results = []
    try:
        with open(file_path, 'rb') as f:
            f.seek(start_offset)
            raw = f.read(end_offset - start_offset)
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

    # Maintain a running line count so we can report the actual line number
    # for each dangerous call. line_num is 1-based.
    # First, count newlines from file start to start_offset for correct base
    try:
        with open(file_path, 'rb') as f:
            raw_prefix = f.read(start_offset)
        line_num = raw_prefix.count(b'\n') + 1
    except Exception:
        line_num = 1
    byte_pos = start_offset
    for line_str in raw.split(b'\n'):
        if not line_str:
            byte_pos += 1
            line_num += 1
            continue
        try:
            entry = json.loads(line_str.decode('utf-8'))
        except Exception:
            byte_pos += len(line_str) + 1
            line_num += 1
            continue

        dangers = check_line(entry)
        if dangers != ['safe']:
            results.append({
                'offset': byte_pos,
                'line_num': line_num,  # actual 1-based line number
                'dangers': dangers,
                'line_preview': line_str[:200].decode('utf-8', errors='replace'),
            })
        byte_pos += len(line_str) + 1
        line_num += 1

    return {'status': 'ok', 'dangerous': results}

# =============================================================================
# Request dispatcher
# =============================================================================

def handle_request(req):
    action = req.get('action', '')

    if action == 'tool_scan':
        return handle_tool_scan(req)

    elif action == 'loop_check':
        file_path = req['file']
        sim_threshold = float(req.get('sim_threshold', 0.85))
        sim_lookback = int(req.get('sim_lookback', 5))
        exact_threshold = int(req.get('exact_threshold', 5))
        check_layer = req.get('layer', 'all')

        result = {'status': 'ok'}
        if check_layer in ('similarity', 'all'):
            result['similarity'] = check_similarity(file_path, sim_threshold, sim_lookback)
        if check_layer in ('exact', 'all'):
            result['exact'] = check_exact(file_path, exact_threshold)
        return result

    elif action == 'extract_context':
        file_path = req['file']
        trigger_line = int(req.get('trigger_line', 1))
        context_turns = int(req.get('context_turns', 3))
        ctx = extract_context(file_path, trigger_line, context_turns)
        return {'status': 'ok', 'context': ctx}

    elif action == 'parse_decision':
        response_text = req.get('response', '')
        decision, violation_type, feedback, reasoning = parse_decision(response_text)
        return {
            'status': 'ok',
            'decision': decision,
            'violation_type': violation_type,
            'feedback': feedback,
            'reasoning': reasoning,
        }

    elif action == 'check_file_changed':
        file_path = req['file']
        changed = file_changed(file_path)
        rotated = file_rotated(file_path) if changed else False
        return {'status': 'ok', 'changed': changed, 'rotated': rotated}

    elif action == 'init_file':
        file_path = req['file']
        file_init(file_path)
        return {'status': 'ok'}

    elif action == 'filter_check':
        file_path = req.get('file', '')
        session_id = req.get('session_id', '')
        metadata = req.get('metadata', {})
        should_monitor = session_matches_filter(file_path, session_id, metadata)
        return {'status': 'ok', 'monitor': should_monitor}

    elif action == 'update_config':
        global _filter_mode, _filter_providers, _filter_agents, _filter_model_patterns
        global _emergency_threshold, _emergency_window
        global _embedding_provider, _embedding_model, _embedding_url, _embedding_enabled
        global _fallback_embedding_provider, _fallback_embedding_model
        global _fallback_embedding_url, _fallback_embedding_api_key, _fallback_duration

        if 'filter_mode' in req:
            _filter_mode = req['filter_mode']
        if 'filter_providers' in req:
            _filter_providers = set(p.lower() for p in req['filter_providers'])
        if 'filter_agents' in req:
            _filter_agents = set(a.lower() for a in req['filter_agents'])
        if 'filter_model_patterns' in req:
            _filter_model_patterns = [p.lower() for p in req['filter_model_patterns']]
        if 'emergency_threshold' in req:
            _emergency_threshold = int(req['emergency_threshold'])
        if 'emergency_window' in req:
            _emergency_window = int(req['emergency_window'])
        if 'embedding_provider' in req:
            _embedding_provider = req['embedding_provider']
        if 'embedding_model' in req:
            _embedding_model = req['embedding_model']
        if 'embedding_url' in req:
            _embedding_url = req['embedding_url']
        if 'embedding_enabled' in req:
            _embedding_enabled = bool(req['embedding_enabled'])
        if 'fallback_embedding_provider' in req:
            _fallback_embedding_provider = req['fallback_embedding_provider']
        if 'fallback_embedding_model' in req:
            _fallback_embedding_model = req['fallback_embedding_model']
        if 'fallback_embedding_url' in req:
            _fallback_embedding_url = req['fallback_embedding_url']
        if 'fallback_embedding_api_key' in req:
            _fallback_embedding_api_key = req['fallback_embedding_api_key']
        if 'fallback_duration' in req:
            _fallback_duration = int(req['fallback_duration'])
        # Resolve defaults from provider name
        _embedding_provider_defaults()

        return {'status': 'ok', 'config': {
            'filter_mode': _filter_mode,
            'filter_providers': list(_filter_providers),
            'filter_agents': list(_filter_agents),
            'filter_model_patterns': _filter_model_patterns,
            'emergency_threshold': _emergency_threshold,
            'emergency_window': _emergency_window,
            'embedding_enabled': _embedding_enabled,
            'embedding_provider': _embedding_provider,
            'embedding_model': _embedding_model,
            'embedding_url': _embedding_url,
            'fallback_embedding_provider': _fallback_embedding_provider,
            'fallback_embedding_model': _fallback_embedding_model,
            'fallback_embedding_url': _fallback_embedding_url,
            'fallback_duration': _fallback_duration,
        }}

    elif action == 'record_abort':
        count = record_abort()
        emergency = check_emergency()
        return {'status': 'ok', 'abort_count': count, 'emergency': emergency}

    elif action == 'abort_status':
        count = get_abort_count()
        emergency = check_emergency()
        return {'status': 'ok', 'abort_count': count, 'emergency': emergency}

    elif action == 'ping':
        return {'status': 'ok', 'pong': True}

    else:
        return {'status': 'error', 'error': f'unknown action: {action}'}

# =============================================================================
# Main loop — read JSON-line requests from stdin, write responses to stdout
# =============================================================================

def main():
    global _embedding_api_key

    # Read embedding API key from environment (set by watchdog.sh before daemon start)
    _embedding_api_key = os.environ.get('EMBEDDING_API_KEY', '')
    # Also check provider-specific env vars as fallback
    if not _embedding_api_key:
        for var in ('OPENAI_API_KEY', 'COHERE_API_KEY', 'GROQ_API_KEY',
                     'MISTRAL_API_KEY', 'DASHSCOPE_API_KEY', 'NIM_API_KEY'):
            _embedding_api_key = os.environ.get(var, '')
            if _embedding_api_key:
                break

    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, line_buffering=True)

    while True:
        try:
            line = sys.stdin.readline()
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            break

        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            resp = {'status': 'error', 'error': 'invalid JSON'}
            sys.stdout.write(json.dumps(resp) + '\n')
            sys.stdout.flush()
            continue

        resp = handle_request(req)
        req_id = req.get('_req_id')
        if req_id:
            resp['_req_id'] = req_id
        sys.stdout.write(json.dumps(resp) + '\n')
        sys.stdout.flush()

    sys.exit(0)


if __name__ == '__main__':
    main()
