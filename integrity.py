import os, json, time, hmac, hashlib, threading

# Integrity chain always ON (no toggle)
INTEGRITY_LOG_PATH = os.getenv("INTEGRITY_LOG_PATH", "./integrity_log.jsonl")

# Derive key from SECRET_BUNDLE or override
_secret_bundle = os.getenv("SECRET_BUNDLE")
_override_key = os.getenv("OVERRIDE_INTEGRITY_KEY")

def _derive_integrity_key():
    if _override_key:
        try:
            return bytes.fromhex(_override_key)
        except ValueError:
            return hashlib.sha256(_override_key.encode()).digest()
    if _secret_bundle:
        seed = hashlib.sha256((_secret_bundle + "|integrity").encode()).digest()
    else:
        seed = hashlib.sha256(os.urandom(64)).digest()
    return hashlib.sha256(seed + b"integrity").digest()

_KEY = _derive_integrity_key()

_lock = threading.Lock()
_prev_hash = ""
_seq = 0

def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",",":")).encode()

def _h(seq, ts, event, data_hash, prev_hash):
    msg = f"{seq}|{ts}|{event}|{data_hash}|{prev_hash}".encode()
    return hmac.new(_KEY, msg, hashlib.sha256).hexdigest()

def log_event(event: str, payload: dict):
    global _seq, _prev_hash
    with _lock:
        _seq += 1
        ts = int(time.time())
        data_hash = hashlib.sha256(_canon(payload)).hexdigest()
        mac = _h(_seq, ts, event, data_hash, _prev_hash)
        entry = {
            "seq": _seq,
            "ts": ts,
            "event": event,
            "data_hash": data_hash,
            "prev_hash": _prev_hash,
            "hmac": mac
        }
        try:
            with open(INTEGRITY_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",",":")) + "\n")
        except Exception:
            pass
        _prev_hash = mac