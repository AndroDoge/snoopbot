# 🛰️ Telegram Passive Intelligence & Secure Monitoring Bot  
**Encrypted • Salted • Ephemeral • Integrity‑Chained • Adaptive • Auto‑Scaling**

> A zero‑trust, privacy‑preserving passive monitor for public Telegram broadcast content.  
> Built for resilience, stealth, and verifiable integrity — fully autonomous after a single DM.  

---

## ✨ Value Proposition

| Goal | How It’s Achieved |
|------|-------------------|
| Minimize footprint | Adaptive polling + ID probing reduce API and web load |
| Resist forensic exposure | SQLCipher + libsodium wrap + salted one-way hashes + ephemeral purge |
| Prevent tampering | HMAC‑chained append‑only integrity log |
| Avoid spam & duplicates | Multi‑salt fingerprint dedupe with grace during SALT rotation |
| Simple operation | Just send a link → reply “yes” → monitoring starts |
| Scale gracefully | Automatic interval scaling as monitor count grows |

---

## 🧩 Core Feature Categories

### 🔐 Security & Privacy
- Mandatory SQLCipher encryption (page-level)  
- Mandatory libsodium SecretBox file wrapping (encrypts DB on shutdown; decrypts at startup)  
- One-way salted hashing (no plaintext usernames, IDs, or full messages persisted)  
- Ephemeral delivered message records (default purge immediately after send)  
- Automatic SALT rotation (startup + every 24h by default) with grace period  
- No responses to any user except the single controller UID  
- Integrity chain (HMAC SHA-256) for every probe, rotation, delivery, error, shutdown event  

### 🤖 Adaptive Intelligence
- Source-based activation: only uses methods that returned data in probe (history / web / message_link)  
- Dynamic interval scaling as number of active monitors increases  
- Poll interval shrinks gently on activity and grows safely on silence  
- Warmup phase to prevent early aggressiveness  
- Random jitter to obfuscate timing signature  

### ⚙️ Data Handling & Efficiency
- ID probing (full or stride) to avoid unnecessary history calls  
- HTML (t.me/s/…) fallback only after inactivity threshold  
- HEAD (ETag/Content-Length) gating before full HTML fetch  
- Automatic interval clamping per channel count  
- Batch reporting with configurable per-round cap  

### 📷 Media & Content
- Media prioritized before plain text  
- Concise metadata summary: type, mime, dimensions, duration, truncated filename  
- Optional forwarding (off by default; summaries always shown)  

### 🧾 Integrity & Compliance
- Append-only JSONL integrity log with chained HMAC  
- Deterministic derivation from a single SECRET_BUNDLE (or random ephemeral keys if not provided)  
- Forensic transparency: each batch delivery & rotation event logged  
- Tamper-evident structure: sequence, previous hash, data hash, event HMAC  

### 🛡️ Resilience & Reliability
- FloodWait-aware backoff & termination on excessive wait  
- Error tolerance with max consecutive error threshold  
- Graceful shutdown securing database (wrap + wipe plaintext)  
- Auto key generation if missing → still “just runs”  

### 🚀 Scalability & Performance
- Interval scaling formula (soft multiplicative growth)  
- Idle channels escalate to max interval; active channels converge toward min bounds  
- Predictable bounded resource usage per additional channel  

### 👩‍💻 Developer Experience
- Minimal configuration (.env can be only 3 lines)  
- Single SECRET_BUNDLE optional secret orchestrates all cryptographic materials  
- Reproducible determinism if secrets preserved; ephemeral privacy if not  

### 🧪 Observability Building Blocks
- Integrity log usable for external verifiers  
- Easy extension point for metrics (not included by default to minimize surface)  

---

## 🔄 SALT Rotation Strategy

| Parameter | Default | Description |
|-----------|---------|-------------|
| Interval | 24h | Auto-rotate SALT every 24 hours |
| Startup Rotate | Enabled | Fresh SALT at first boot (optional) |
| Grace Retention | 1 previous SALT | Prevents instant duplicate spam after rotation |
| Persistence of Old SALTs | None | Old salts kept only in memory (privacy > perfect dedupe) |

Rotation events appear in integrity log: `salt_rotation`.

---

## 🧬 Integrity Chain Format

Each line (JSONL):
```
{
  "seq": N,
  "ts": UNIX_SECONDS,
  "event": "...",
  "data_hash": SHA256(payload),
  "prev_hash": HMAC_OF_PREVIOUS,
  "hmac": HMAC(seq|ts|event|data_hash|prev_hash)
}
```
Breaks in the chain (missing lines, hash mismatch) reveal tampering.

---

## 🗂️ Minimal .env (Short Form)

You only *need*:
```
TELEGRAM_API_ID=123456
TELEGRAM_API_HASH=your_api_hash
CONTROLLER_UID=999999999
# Optional:
# SESSION_NAME=probe_session
# SECRET_BUNDLE=long_random_master_secret
```

Everything else is auto‑generated:
- If `SECRET_BUNDLE` absent → random high-entropy ephemeral salts & keys (dedupe resets on restart).
- Provide `SECRET_BUNDLE` to make behavior deterministic across restarts.

Need explicit fixed components? (Advanced)
```
OVERRIDE_HASH_SALT=hex
OVERRIDE_DB_KEY=hex
OVERRIDE_INTEGRITY_KEY=hex
```

---

## ⚙️ Automatic Defaults (Hardcoded Baselines)

| Aspect | Baseline | Auto-Scaling |
|--------|----------|--------------|
| Min Interval | 120s | +5% per additional monitor |
| Base Interval | 180s | +6% per additional monitor |
| Max Interval | 1200s | +4% per channel beyond 5 |
| Empty Threshold | 3 empties | Triggers web fallback |
| ID Probe Span | 25 (full) | Stride optional via code change |
| Jitter | 0–10s | Constant |
| Warmup Rounds | 2 | Fixed |
| Flood Behavior | Wait <=60s / stop >60s | Fixed |
| SALT Rotation | 24h + startup | Fixed (override via code if needed) |

---

## 🛠️ Local Run (Virtualenv)

```bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env   # edit essentials
python bot.py
```

## 🐳 Docker

```bash
docker build -t tg-secure-passive-bot .
docker run --name tg-secure-passive-bot \
  --env-file .env \
  -v $(pwd)/session_data:/app \
  -v $(pwd)/botdata:/app \
  tg-secure-passive-bot
```

Compose:
```bash
docker compose up -d --build
```

---

## 🧪 Usage

1. DM the bot (runs as your own user session) with a link:
   - `https://t.me/channelname`
   - `t.me/channelname/1234`
   - `https://t.me/joinchat/<invite>` (metadata only)
2. Bot probes & reports accessible sources.
3. Reply `yes` to start monitoring or `no` to skip.
4. Receive adaptive update batches.

Commands:
```
help
list
stop <username>
stopall
yes / no
```

---

## 📦 Output Example

```
[MONITOR] examplechannel new_raw=5 sent=3 interval=172s sources=['history','web']
  2301:MessageMediaDocument:Release notes... | DOCUMENT application/pdf  report.pdf
  2302:MessageMediaPhoto:[MessageMediaPhoto] | PHOTO
  2303:Minor patch rollout...
  (+2 omitted)
```

---

## 🔒 Security Model (Layered)

| Layer | Purpose |
|-------|---------|
| SQLCipher | At-rest page encryption |
| Libsodium Wrap | Envelope encryption + secure wipe cycle |
| Salted Hashing | Non-reversible indexing & dedupe |
| Ephemeral Records | No growth of delivered message table |
| Integrity Chain | Tamper evidence |
| SALT Rotation + Grace | Forward secrecy style dedupe weakening |
| Jitter & Adaptive | Traffic pattern camouflage |
| Single Controller UID | Eliminate unsolicited interaction |

---

## 🛡️ Hardening Tips

| Goal | Action |
|------|--------|
| Protect secrets | Provide SECRET_BUNDLE via secret manager |
| Forensic minimization | Keep RETENTION at 0 (default) |
| High-scale monitoring | Accept larger intervals (natural auto-scaling helps) |
| External audit | Periodically export integrity log & verify chain |
| Compromise response | Rotate SECRET_BUNDLE ⇒ all hashes change; prior linkage severed |

---

## 🔮 Future Extensibility (Suggested)
- Metrics (Prometheus) bridge
- Integrity log verifier CLI
- Encrypted off-site snapshot of fingerprint table
- Optional TLS tunnel or proxy rotation
- Multi-controller quorum authorization

---

## ❗ Limitations
| Limitation | Reason |
|------------|--------|
| Cannot read private/supergroup history | Telegram server ACL |
| Web fallback depends on HTML structure | May break on layout changes |
| SALT rotation grace not persisted | Design choice (privacy over perfect continuity) |
| No “real-time” push | Passive polling only |

---

## ✅ License & Ethics
Use only for lawful monitoring of publicly accessible broadcast information. Does not circumvent Telegram access controls.

---

## 🧡 Final Note
“Set three values, send a link, reply yes — everything else is self-governing.”

Happy secure snooping!  
Made with Love and Linux only for educational purposes.
