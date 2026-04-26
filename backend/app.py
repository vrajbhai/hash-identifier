"""
VRAJBHAI Hash Identifier - Backend
Original hash-identifier.py by Zion3R / Blackploit
"""
import os
import re
import sys
import time
import hashlib
import logging
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from typing import Tuple, List, Dict, Optional, Union

from flask import Flask, request, jsonify
from flask_cors import CORS

# ── App setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)

ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*').split(',')
CORS(app, origins=ALLOWED_ORIGINS)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

HASH_IDENTIFIER_SCRIPT = os.path.join(os.path.dirname(__file__), 'hash-identifier.py')

# ── Configuration ──────────────────────────────────────────────────────────────
SCRIPT_TIMEOUT = int(os.environ.get('SCRIPT_TIMEOUT', 120))   # seconds; 0 = no timeout
CACHE_TTL = int(os.environ.get('CACHE_TTL', 300))
MAX_HASH_LENGTH = 512
MAX_BULK_ITEMS = 20
CACHE_MAX_SIZE = 500

# ── In‑memory cache ────────────────────────────────────────────────────────────
_cache: Dict[str, Dict] = {}
_cache_lock = threading.Lock()


def _cache_get(key: str) -> Optional[Dict]:
    with _cache_lock:
        entry = _cache.get(key)
        if entry and time.time() - entry['ts'] < CACHE_TTL:
            return entry['data']
        if entry:
            del _cache[key]
    return None


def _cache_set(key: str, data: Dict):
    with _cache_lock:
        cutoff = time.time() - CACHE_TTL
        stale = [k for k, v in _cache.items() if v['ts'] < cutoff]
        for k in stale:
            del _cache[k]
        if len(_cache) >= CACHE_MAX_SIZE:
            sorted_items = sorted(_cache.items(), key=lambda x: x[1]['ts'])
            for k, _ in sorted_items[:len(_cache) - CACHE_MAX_SIZE + 1]:
                del _cache[k]
        _cache[key] = {'data': data, 'ts': time.time()}


# ── Validation ─────────────────────────────────────────────────────────────────
_SAFE_HASH_RE = re.compile(
    r'^[\w\$\./\+\-\*\@\!\#\%\&\(\)\[\]\{\}\<\>\:\;\,\=\~\^`]{4,512}$'
)

def validate_hash(h: str) -> Tuple[bool, str]:
    h = h.strip()
    if not h:
        return False, 'Empty hash'
    if len(h) > MAX_HASH_LENGTH:
        return False, f'Hash exceeds maximum length of {MAX_HASH_LENGTH}'
    if len(h) < 4:
        return False, 'Hash is too short'
    if not _SAFE_HASH_RE.match(h):
        return False, 'Hash contains invalid characters'
    return True, ''


# ── Quick pattern‑based check (no subprocess) ──────────────────────────────────
_QUICK_RULES: List[Tuple] = [
    # (length, hex_only, prefix, possible_types)
    (32,  True,  None,    ['MD5', 'NTLM', 'MD4', 'LM', 'Domain Cached Credentials']),
    (40,  True,  None,    ['SHA-1', 'MySQL5 - SHA-1(SHA-1($pass))', 'Haval-160']),
    (56,  True,  None,    ['SHA-224', 'Haval-224']),
    (64,  True,  None,    ['SHA-256', 'RIPEMD-256', 'Haval-256', 'Snefru-256', 'GOST R 34.11-94']),
    (96,  True,  None,    ['SHA-384']),
    (128, True,  None,    ['SHA-512', 'Whirlpool', 'Salsa10']),
    (16,  True,  None,    ['MySQL < 4.1', 'DES(Unix)', 'CRC-64']),
    (8,   True,  None,    ['CRC-32', 'Adler-32']),
    (4,   True,  None,    ['CRC-16']),
    # Prefix‑based
    (None, False, '$1$',    ['MD5(Unix)']),
    (None, False, '$5$',    ['SHA-256(Unix)']),
    (None, False, '$6$',    ['SHA-512(Unix)']),
    (None, False, '$2a$',   ['bcrypt']),
    (None, False, '$2b$',   ['bcrypt']),
    (None, False, '$2y$',   ['bcrypt']),
    (None, False, '$apr1$', ['Apache MD5 (APR)']),
    (None, False, '{SHA}',  ['SHA-1 Base64']),
    (None, False, '$P$',    ['phpass (WordPress / phpBB3)']),
    (None, False, '$H$',    ['phpass (phpBB3)']),
    (None, False, 'sha1$',  ['Django SHA-1']),
    (None, False, 'sha256$',['Django SHA-256']),
    (None, False, 'pbkdf2_sha256$', ['Django PBKDF2-SHA256']),
    (None, False, '$s1$',    ['scrypt']),
    (None, False, '$scrypt$',['scrypt']),
    (None, False, '$argon2', ['Argon2']),
    (None, False, '$7$',     ['yescrypt']),
    (None, False, '*',       ['MySQL 4.1+']),
    (None, False, '0x',      ['Keccak-256 (Ethereum)']),
]

def quick_hash_check(h: str) -> List[str]:
    hl = h.lower()
    is_hex = all(c in '0123456789abcdef' for c in hl)
    results = []
    for length, hex_only, prefix, types in _QUICK_RULES:
        if hex_only and not is_hex:
            continue
        if prefix and not h.startswith(prefix):
            continue
        if length is not None and len(h) != length:
            continue
        for t in types:
            if t not in results:
                results.append(t)
        if len(results) >= 8:
            break
    return results[:8]


# ── Core script invocation ─────────────────────────────────────────────────────
def _run_script(hash_input: str) -> Dict:
    cache_key = hashlib.sha256(hash_input.encode()).hexdigest()
    cached = _cache_get(cache_key)
    if cached:
        logger.info('Cache hit (len=%d)', len(hash_input))
        result = dict(cached)
        result['from_cache'] = True
        return result

    quick = quick_hash_check(hash_input)
    t_start = time.time()

    if not os.path.isfile(HASH_IDENTIFIER_SCRIPT):
        logger.error('Script not found: %s', HASH_IDENTIFIER_SCRIPT)
        return {
            'possible_types': quick,
            'least_possible': [],
            'raw_output': '',
            'error': 'hash-identifier.py is missing on the server.',
            'elapsed_ms': int((time.time() - t_start) * 1000),
        }

    timeout = None if SCRIPT_TIMEOUT == 0 else SCRIPT_TIMEOUT
    try:
        proc = subprocess.run(
            [sys.executable, HASH_IDENTIFIER_SCRIPT, hash_input],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, 'PYTHONUNBUFFERED': '1'},
        )
        output = proc.stdout
    except subprocess.TimeoutExpired:
        logger.warning('Script timed out for hash (len=%d)', len(hash_input))
        result = {
            'possible_types': quick,
            'least_possible': [],
            'timed_out': True,
            'raw_output': '',
            'elapsed_ms': SCRIPT_TIMEOUT * 1000,
        }
        _cache_set(cache_key, result)
        return result
    except Exception as exc:
        logger.exception('Unexpected error running script')
        return {
            'possible_types': quick,
            'least_possible': [],
            'error': f'Script execution failed: {str(exc)}',
            'elapsed_ms': int((time.time() - t_start) * 1000),
        }

    possible, least = _parse_output(output)
    for t in quick:
        if t not in possible:
            possible.insert(0, t)

    elapsed = int((time.time() - t_start) * 1000)
    result = {
        'possible_types': possible,
        'least_possible': least,
        'raw_output': output[:1500],
        'timed_out': False,
        'elapsed_ms': elapsed,
    }
    _cache_set(cache_key, result)
    logger.info('Identified hash (len=%d) in %d ms', len(hash_input), elapsed)
    return result


def _parse_output(output: str) -> Tuple[List[str], List[str]]:
    possible, least = [], []
    in_possible = in_least = False
    for line in output.split('\n'):
        stripped = line.strip()
        if 'Possible Hashs:' in stripped:
            in_possible, in_least = True, False
            continue
        if 'Least Possible Hashs:' in stripped:
            in_possible, in_least = False, True
            continue
        if stripped.startswith('[+]'):
            ht = stripped[4:].strip()
            if not ht:
                continue
            if in_possible and ht not in possible:
                possible.append(ht)
            elif in_least and ht not in least:
                least.append(ht)
    return possible, least


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route('/identify-hash', methods=['POST'])
def identify_hash():
    data = request.get_json(silent=True) or {}
    hash_input = str(data.get('hash', '')).strip()

    ok, err = validate_hash(hash_input)
    if not ok:
        return jsonify({'error': err}), 400

    result = _run_script(hash_input)
    return jsonify({'hash': hash_input, **result})


@app.route('/bulk-identify', methods=['POST'])
def bulk_identify():
    data = request.get_json(silent=True) or {}
    hashes = data.get('hashes', [])

    if not isinstance(hashes, list):
        return jsonify({'error': 'hashes must be a list'}), 400
    if len(hashes) > MAX_BULK_ITEMS:
        return jsonify({'error': f'Maximum {MAX_BULK_ITEMS} hashes per request'}), 400

    results = []
    overall_timeout = (SCRIPT_TIMEOUT + 5) * len(hashes) if SCRIPT_TIMEOUT > 0 else None

    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_hash = {executor.submit(_process_single_hash, h): h for h in hashes}
        try:
            for future in as_completed(future_to_hash, timeout=overall_timeout):
                try:
                    results.append(future.result())
                except Exception as exc:
                    h = future_to_hash[future]
                    results.append({'hash': h, 'error': f'Unexpected error: {exc}'})
        except FuturesTimeoutError:
            logger.error('Bulk request timed out')
            for future in future_to_hash:
                if future.done() and not future.exception():
                    results.append(future.result())
            for future, h in future_to_hash.items():
                if not future.done():
                    results.append({'hash': h, 'error': 'Request timed out'})

    result_map = {r['hash']: r for r in results}
    ordered = [result_map.get(h, {'hash': h, 'error': 'Unknown'}) for h in hashes]
    return jsonify({'results': ordered, 'count': len(ordered)})


def _process_single_hash(h: str) -> Dict:
    ok, err = validate_hash(str(h))
    if not ok:
        return {'hash': h, 'error': err}
    r = _run_script(str(h).strip())
    r['hash'] = h
    return r


@app.route('/quick-check', methods=['POST'])
def quick_check():
    data = request.get_json(silent=True) or {}
    hash_input = str(data.get('hash', '')).strip()
    ok, err = validate_hash(hash_input)
    if not ok:
        return jsonify({'error': err}), 400
    types = quick_hash_check(hash_input)
    return jsonify({'hash': hash_input, 'possible_types': types, 'quick': True})


@app.route('/health', methods=['GET'])
def health():
    script_ok = os.path.exists(HASH_IDENTIFIER_SCRIPT)
    with _cache_lock:
        cache_size = len(_cache)
    return jsonify({
        'status': 'healthy',
        'script_present': script_ok,
        'cache_entries': cache_size,
        'version': '2.1.0',
    })


@app.route('/config', methods=['GET'])
def config():
    return jsonify({
        'script_timeout_seconds': SCRIPT_TIMEOUT,
        'timeout_disabled': SCRIPT_TIMEOUT == 0,
        'cache_ttl_seconds': CACHE_TTL,
        'max_bulk_items': MAX_BULK_ITEMS,
    })


@app.route('/cache/clear', methods=['POST'])
def clear_cache():
    secret = os.environ.get('ADMIN_SECRET', '')
    if secret and request.headers.get('X-Admin-Secret') != secret:
        return jsonify({'error': 'Unauthorized'}), 401
    with _cache_lock:
        count = len(_cache)
        _cache.clear()
    return jsonify({'cleared': count})


@app.errorhandler(404)
def not_found(_):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(e):
    logger.exception('Unhandled error')
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5500))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    logger.info('Starting VRAJBHAI Hash Identifier v2.2 on port %d', port)
    app.run(host='0.0.0.0', port=port, debug=debug)
