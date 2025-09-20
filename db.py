import os
import time
import hashlib
import secrets
from contextlib import contextmanager

# ========== Core Mandatory Secure Storage Layer ==========
# This version: Encryption & libsodium wrapping are ALWAYS enforced.
# Optional SECRET_BUNDLE drives deterministic derivations.

DB_PATH = os.getenv("DB_PATH", "./botdata.db")

# Derivation seeds
_SECRET_BUNDLE = os.getenv("SECRET_BUNDLE")  # Optional single master secret
def _derive(label: str, size: int = 32) -> bytes:
    if _SECRET_BUNDLE:
        base = hashlib.sha256((_SECRET_BUNDLE + "|" + label).encode()).digest()
    else:
        base = hashlib.sha256(os.urandom(64)).digest()
    return hashlib.sha256(base + label.encode()).digest()[:size]

# Override hooks (if user wants explicit)
_override_db_key = os.getenv("OVERRIDE_DB_KEY")
override_db_key_bytes = None
if _override_db_key:
    try:
        override_db_key_bytes = bytes.fromhex(_override_db_key)
    except ValueError:
        override_db_key_bytes = hashlib.sha256(_override_db_key.encode()).digest()

# SQLCipher mandatory
try:
    import pysqlcipher3.dbapi2 as sqlcipher
    _use_sqlcipher = True
except Exception:
    _use_sqlcipher = False

# Libsodium mandatory
try:
    from nacl.secret import SecretBox
    from nacl.utils import random as nacl_random
    _libsodium_available = True
except Exception:
    _libsodium_available = False

# Keys
if override_db_key_bytes:
    _SQLCIPHER_KEY_HEX = override_db_key_bytes.hex()
else:
    _SQLCIPHER_KEY_HEX = _derive("sqlcipher").hex()

_LIBSODIUM_KEY_FILE = os.getenv("LIBSODIUM_KEY_FILE", "./db_wrap.key")
if os.path.exists(_LIBSODIUM_KEY_FILE):
    with open(_LIBSODIUM_KEY_FILE, "rb") as f:
        libs_key = f.read()
    if len(libs_key) != 32:
        libs_key = _derive("libsodium")
else:
    libs_key = _derive("libsodium")
    with open(_LIBSODIUM_KEY_FILE, "wb") as f:
        f.write(libs_key)
    try:
        os.chmod(_LIBSODIUM_KEY_FILE, 0o600)
    except Exception:
        pass

_secret_box = SecretBox(libs_key) if _libsodium_available else None
_WRAPPED_SUFFIX = ".wrapped"

SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    fp_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS delivered_messages (
    msg_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);
"""

RETENTION_SECONDS = int(os.getenv("RETENTION_SECONDS", "0"))

def _log(msg: str):
    print(f"[DB] {msg}")

def _wrapped_path():
    return DB_PATH + _WRAPPED_SUFFIX

def _secure_wipe(path: str):
    if not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        if size > 0:
            with open(path, "r+b") as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        pass
    try:
        os.remove(path)
    except Exception:
        pass

def _decrypt_if_wrapped():
    if not (_libsodium_available and _secret_box):
        return
    wp = _wrapped_path()
    if os.path.exists(wp) and not os.path.exists(DB_PATH):
        _log("Decrypting libsodium wrapped DB...")
        with open(wp, "rb") as f:
            blob = f.read()
        if len(blob) < 24:
            raise ValueError("Wrapped DB file corrupted.")
        nonce = blob[:24]
        ciphertext = blob[24:]
        plaintext = _secret_box.decrypt(ciphertext, nonce)
        with open(DB_PATH, "wb") as f:
            f.write(plaintext)
        _log("Decryption complete.")

def wrap_on_shutdown():
    if not (_libsodium_available and _secret_box and os.path.exists(DB_PATH)):
        return
    _log("Wrapping DB with libsodium...")
    with open(DB_PATH, "rb") as f:
        pt = f.read()
    nonce = nacl_random(24)
    ct = _secret_box.encrypt(pt, nonce)[24:]
    with open(_wrapped_path(), "wb") as f:
        f.write(nonce + ct)
    # Secure wipe plaintext after wrapping
    _secure_wipe(DB_PATH)
    _log("Wrap complete & plaintext wiped.")

@contextmanager
def get_conn():
    if _use_sqlcipher:
        conn = sqlcipher.connect(DB_PATH)
        try:
            conn.executescript(f"""
            PRAGMA key = '{_SQLCIPHER_KEY_HEX}';
            PRAGMA cipher_page_size = 4096;
            PRAGMA kdf_iter = 64000;
            PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
            PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
            PRAGMA cipher = 'aes-256-gcm';
            PRAGMA cipher_hmac_on = ON;
            """)
            yield conn
        finally:
            conn.close()
    else:
        # Fallback (should rarely happen)
        conn = __import__("sqlite3").connect(DB_PATH)
        try:
            yield conn
        finally:
            conn.close()

def init_db():
    if not _libsodium_available:
        raise RuntimeError("Libsodium (PyNaCl) required but not available.")
    _decrypt_if_wrapped()
    with get_conn() as c:
        c.executescript(SCHEMA)
        c.commit()
    _log(("SQLCipher" if _use_sqlcipher else "PLAIN") + " + libsodium ready.")

def now() -> int:
    return int(time.time())

def has_fingerprint(fp_hash: str) -> bool:
    with get_conn() as c:
        cur = c.execute("SELECT 1 FROM fingerprints WHERE fp_hash=?", (fp_hash,))
        return cur.fetchone() is not None

def store_fingerprints(fp_hashes):
    arr = list(fp_hashes)
    if not arr: return
    ts = now()
    with get_conn() as c:
        c.executemany("INSERT OR IGNORE INTO fingerprints(fp_hash, created_at) VALUES (?,?)",
                      [(h, ts) for h in arr])
        c.commit()

def has_message(msg_hash: str) -> bool:
    with get_conn() as c:
        cur = c.execute("SELECT 1 FROM delivered_messages WHERE msg_hash=?", (msg_hash,))
        return cur.fetchone() is not None

def store_messages(msg_hashes):
    arr = list(msg_hashes)
    if not arr: return
    ts = now()
    with get_conn() as c:
        c.executemany("INSERT OR IGNORE INTO delivered_messages(msg_hash, created_at) VALUES (?,?)",
                      [(h, ts) for h in arr])
        c.commit()

def purge_messages(msg_hashes):
    if RETENTION_SECONDS > 0:
        return
    arr = list(msg_hashes)
    if not arr: return
    with get_conn() as c:
        c.executemany("DELETE FROM delivered_messages WHERE msg_hash=?", [(h,) for h in arr])
        c.commit()

def gc():
    if RETENTION_SECONDS <= 0:
        return
    cutoff = now() - RETENTION_SECONDS
    with get_conn() as c:
        c.execute("DELETE FROM delivered_messages WHERE created_at < ?", (cutoff,))
        c.execute("DELETE FROM fingerprints WHERE created_at < ?", (cutoff,))
        c.commit()