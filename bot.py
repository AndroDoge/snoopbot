import os, re, asyncio, logging, time, httpx, hashlib, signal, random
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from telethon import TelegramClient, events, functions, types, errors
from telethon.tl.types import InputMessageID, DocumentAttributeVideo, DocumentAttributeAudio, DocumentAttributeFilename

import db
import integrity

# Minimal essential ENV
TELEGRAM_API_ID = int(os.getenv("TELEGRAM_API_ID", "0"))
TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "")
CONTROLLER_UID = int(os.getenv("CONTROLLER_UID", "0"))
SESSION_NAME = os.getenv("SESSION_NAME", "probe_session")

SECRET_BUNDLE = os.getenv("SECRET_BUNDLE")
_OVERRIDE_HASH_SALT = os.getenv("OVERRIDE_HASH_SALT")

def _derive(label: str, size: int = 32) -> str:
    if SECRET_BUNDLE:
        seed = hashlib.sha256((SECRET_BUNDLE + "|" + label).encode()).digest()
    else:
        seed = hashlib.sha256(os.urandom(64)).digest()
    return hashlib.sha256(seed + label.encode()).hexdigest()[:size*2]

HASH_SALT = _OVERRIDE_HASH_SALT or _derive("hash_salt")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
log = logging.getLogger("bot")

# Adaptive baseline constants (conservative)
BASE_MIN_INTERVAL = 120
BASE_BASE_INTERVAL = 180
BASE_MAX_INTERVAL = 1200
INCREASE_FACTOR = 1.2
DECREASE_FACTOR = 0.9
EMPTY_THRESHOLD = 3
MAX_MESSAGES_PER_POLL = 10
ID_PROBE_SPAN = 25
ID_PROBE_MODE = "full"
WARMUP_ROUNDS = 2
JITTER_SECONDS = 10
MAX_CONSEC_ERRORS = 5

# ========== Adaptive scaling based on monitor count ==========
def scale_intervals(n: int):
    # n = active monitor count (>=1)
    factor = 1 + 0.06 * (n - 1)
    factor_min = 1 + 0.05 * (n - 1)
    base = min(int(BASE_BASE_INTERVAL * factor), BASE_MAX_INTERVAL)
    minv = min(int(BASE_MIN_INTERVAL * factor_min), base)
    maxv = int(BASE_MAX_INTERVAL * (1 + 0.04 * max(0, n - 5)))
    return minv, base, maxv

# ========== Link parsing ==========
INVITE_RE = re.compile(r"^(?:https?://)?t\.me/(?:joinchat/|\+)(?P<hash>[A-Za-z0-9_\-]+)$")
USERNAME_RE = re.compile(r"^(?:https?://)?t\.me/(?P<username>[A-Za-z0-9_]{3,32})(?:/)?$")
MESSAGE_LINK_RE = re.compile(r"^(?:https?://)?t\.me/(?:(?P<username>[A-Za-z0-9_]{3,32})|c/(?P<cid>\d+))/(?P<msg_id>\d+)$")

class ParsedLink:
    def __init__(self, raw, type_, invite_hash=None, username=None, channel_id=None, message_id=None):
        self.raw = raw
        self.type = type_
        self.invite_hash = invite_hash
        self.username = username
        self.channel_id = channel_id
        self.message_id = message_id

def parse_link(text: str) -> ParsedLink:
    t = text.strip()
    if m := INVITE_RE.match(t):
        return ParsedLink(t, "invite", invite_hash=m.group("hash"))
    if m := MESSAGE_LINK_RE.match(t):
        cid = m.group("cid")
        return ParsedLink(t, "message_link", username=m.group("username"),
                          channel_id=int(cid) if cid else None,
                          message_id=int(m.group("msg_id")))
    if m := USERNAME_RE.match(t):
        return ParsedLink(t, "username", username=m.group("username"))
    return ParsedLink(t, "unknown")

# ========== Hashing & dedupe with rotation support ==========
ACTIVE_SALTS: List[str] = [HASH_SALT]
PREV_SALTS: List[str] = []
LAST_ROT_TS = time.time()
ROT_INTERVAL_HOURS = 24
ROTATE_ON_START = True
ROT_GRACE = 1

def _generate_new_salt():
    return hashlib.sha256(os.urandom(64)).hexdigest()

def rotate_salt(force=False):
    global HASH_SALT, ACTIVE_SALTS, PREV_SALTS, LAST_ROT_TS
    now = time.time()
    if not force and (now - LAST_ROT_TS)/3600.0 < ROT_INTERVAL_HOURS:
        return
    old = HASH_SALT
    HASH_SALT = _generate_new_salt()
    PREV_SALTS.insert(0, old)
    PREV_SALTS = PREV_SALTS[:ROT_GRACE]
    ACTIVE_SALTS = [HASH_SALT] + PREV_SALTS
    LAST_ROT_TS = now
    integrity.log_event("salt_rotation", {"active": len(ACTIVE_SALTS)})

async def salt_rotation_scheduler():
    await asyncio.sleep(5)
    if ROTATE_ON_START:
        rotate_salt(force=True)
    while True:
        await asyncio.sleep(300)
        rotate_salt()

def _msg_hash(salt: str, username: str, mid: int) -> str:
    raw = f"{salt}msg{username.lower()}:{mid}"
    return hashlib.sha256(raw.encode()).hexdigest()

def any_fingerprint_exists(message, username: str) -> bool:
    for salt in ACTIVE_SALTS:
        fp = _fingerprint_with_salt(message, salt)
        if db.has_fingerprint(fp):
            return True
    return False

def _fingerprint_with_salt(message, salt: str) -> str:
    media_type = "text"
    if getattr(message, "media", None):
        media_type = type(message.media).__name__
    txt = (getattr(message, "message", "") or "")[:80]
    base = f"{salt}fp|{message.id}|{media_type}|{hashlib.sha1(txt.encode()).hexdigest()}"
    return hashlib.sha256(base.encode()).hexdigest()

def store_current_fingerprint(message):
    fp = _fingerprint_with_salt(message, HASH_SALT)
    db.store_fingerprints([fp])

def make_current_msg_hash(username: str, mid: int) -> str:
    return _msg_hash(HASH_SALT, username, mid)

# ========== Probes ==========
async def probe_history(client, username, limit):
    try:
        r = await client(functions.messages.GetHistoryRequest(
            peer=username, offset_id=0, offset_date=None, add_offset=0,
            limit=limit, max_id=0, min_id=0, hash=0
        ))
        msgs = [m for m in r.messages if getattr(m, "message", None) or getattr(m, "media", None)]
        return True, msgs
    except errors.ChannelPrivateError:
        return False, []
    except Exception:
        return False, []

async def probe_message_link(client, username, msg_id):
    try:
        r = await client(functions.messages.GetMessagesRequest(
            id=[InputMessageID(id=msg_id)]
        ))
        return len(r.messages) > 0
    except Exception:
        return False

async def probe_web(username, limit):
    url = f"https://t.me/s/{username}"
    try:
        async with httpx.AsyncClient(timeout=15, headers={"User-Agent":"Mozilla/5.0"}) as hc:
            r = await hc.get(url)
        if r.status_code != 200:
            return False, []
        ids = re.findall(r'data-post="[^"/]+/(\d+)"', r.text)
        return len(ids) > 0, [int(i) for i in ids[:limit]]
    except Exception:
        return False, []

# ========== Monitoring ==========
class MonitorState:
    def __init__(self, username: str, last_id: int, sources: List[str]):
        self.username = username
        self.last_id = last_id
        self.sources = sources
        self.min_interval, self.current_interval, self.max_interval = scale_intervals(
            len(monitor_manager.monitors)+1
        )
        self.empty_streak = 0
        self.warmup_done = 0
        self.running = True
        self.task: Optional[asyncio.Task] = None
        self.consecutive_errors = 0
        self.allowed_history = "history" in sources
        self.allowed_web = "web" in sources
        self.allowed_msglink = "message_link" in sources
        self.etag = None
        self.content_length = None

class MonitorManager:
    def __init__(self, client, send_fn):
        self.client = client
        self.send_fn = send_fn
        self.monitors: Dict[str, MonitorState] = {}

    def list_monitors(self):
        return list(self.monitors.values())

    async def start_monitor(self, username: str, last_id: int, sources: List[str]):
        uname = username.lower()
        if uname in self.monitors:
            await self.send_fn(f"[MONITOR] {username} already running.")
            return
        st = MonitorState(username, last_id, sources)
        self.monitors[uname] = st
        st.task = asyncio.create_task(self._run(st))
        msg = f"[MONITOR] Started {username} last_id={last_id} sources={sources} min={st.min_interval}s base={st.current_interval}s max={st.max_interval}s"
        await self.send_fn(msg)
        integrity.log_event("monitor_start", {"username":username,"sources":sources,"last_id":last_id})
        self._rebalance_intervals()

    async def stop_monitor(self, username: str):
        uname = username.lower()
        st = self.monitors.get(uname)
        if not st:
            await self.send_fn(f"[MONITOR] {username} not active.")
            return
        st.running = False
        if st.task:
            st.task.cancel()
        del self.monitors[uname]
        await self.send_fn(f"[MONITOR] Stopped {username}.")
        integrity.log_event("monitor_stop", {"username":username})
        self._rebalance_intervals()

    async def stop_all(self):
        for uname in list(self.monitors.keys()):
            await self.stop_monitor(uname)

    def _rebalance_intervals(self):
        n = len(self.monitors)
        if n == 0:
            return
        for st in self.monitors.values():
            minv, base, maxv = scale_intervals(n)
            st.min_interval, st.max_interval = minv, maxv
            # keep current within bounds
            st.current_interval = max(minv, min(st.current_interval, maxv))

    async def _run(self, st: MonitorState):
        while st.running:
            try:
                if JITTER_SECONDS > 0:
                    await asyncio.sleep(random.uniform(0, JITTER_SECONDS))
                got = await self._poll_once(st)
                st.warmup_done += 1
                st.consecutive_errors = 0
                if st.warmup_done < WARMUP_ROUNDS:
                    st.current_interval = min(st.current_interval * 1.05, st.max_interval)
                else:
                    if got:
                        st.current_interval = max(st.min_interval, int(st.current_interval * DECREASE_FACTOR))
                        st.empty_streak = 0
                    else:
                        st.empty_streak += 1
                        st.current_interval = min(st.max_interval, int(st.current_interval * INCREASE_FACTOR))
                        trigger_web = False
                        if st.allowed_web:
                            trigger_web = st.empty_streak >= EMPTY_THRESHOLD
                        elif (not st.allowed_history and st.allowed_msglink):
                            trigger_web = st.empty_streak >= EMPTY_THRESHOLD + 1
                            if trigger_web:
                                st.allowed_web = True
                        if trigger_web and st.allowed_web:
                            changed = await self._web_head_change(st)
                            if changed:
                                web_got = await self._web_scrape(st)
                                if web_got:
                                    st.empty_streak = 0
                await asyncio.sleep(st.current_interval)
            except asyncio.CancelledError:
                break
            except errors.FloodWaitError as fw:
                st.consecutive_errors += 1
                if fw.seconds <= 60:
                    await self.send_fn(f"[MONITOR] FloodWait {fw.seconds}s {st.username}, waiting.")
                    await asyncio.sleep(fw.seconds + 1)
                else:
                    await self.send_fn(f"[MONITOR] FloodWait {fw.seconds}s -> stopping {st.username}")
                    st.running = False
            except Exception as e:
                st.consecutive_errors += 1
                await self.send_fn(f"[MONITOR] Error {st.username}: {e}")
                if st.consecutive_errors >= MAX_CONSEC_ERRORS:
                    await self.send_fn(f"[MONITOR] Too many errors -> stopping {st.username}")
                    st.running = False
                else:
                    await asyncio.sleep(min(120, st.current_interval))

    async def _poll_once(self, st: MonitorState) -> bool:
        gathered = []
        if st.allowed_history:
            try:
                ok, msgs = await probe_history(self.client, st.username, 50)
                if ok and msgs:
                    # new since last_id
                    new_msgs = [m for m in msgs if getattr(m, "id", 0) > st.last_id]
                    new_msgs.sort(key=lambda m: m.id)
                    if new_msgs:
                        gathered.extend(new_msgs)
                    elif ID_PROBE_SPAN > 0:
                        probe_found = await self._id_probe(st)
                        if probe_found:
                            gathered.extend(probe_found)
                elif not ok:
                    pass
            except Exception as e:
                await self.send_fn(f"[MONITOR] History error {st.username}: {e}")

        if not st.allowed_history and st.allowed_msglink and not gathered and ID_PROBE_SPAN > 0:
            probe_found = await self._id_probe(st, conservative=True)
            if probe_found:
                gathered.extend(probe_found)

        if not gathered:
            return False

        media = [m for m in gathered if getattr(m, "media", None)]
        texts = [m for m in gathered if not getattr(m, "media", None)]
        ordered = media + texts
        selected = []
        delivered_hashes = []
        for m in ordered:
            if any_fingerprint_exists(m, st.username):
                continue
            store_current_fingerprint(m)
            selected.append(m)
            delivered_hashes.append(make_current_msg_hash(st.username, m.id))
            if len(selected) >= MAX_MESSAGES_PER_POLL:
                break
        db.store_messages(delivered_hashes)

        if selected:
            lines = [f"[MONITOR] {st.username} new_raw={len(gathered)} sent={len(selected)} interval={int(st.current_interval)}s sources={st.sources}"]
            for m in selected:
                line = f"  {self._preview(m)}"
                if getattr(m, "media", None):
                    line += f" | {self._media_summary(m)}"
                lines.append(line)
            overflow = len(ordered) - len(selected)
            if overflow > 0:
                lines.append(f"  (+{overflow} omitted)")
            await self.send_fn("\n".join(lines))
            integrity.log_event("deliver_batch", {
                "username": st.username,
                "count": len(selected),
                "last_id_before": st.last_id,
                "last_id_after": max(m.id for m in gathered)
            })
        db.purge_messages(delivered_hashes)
        st.last_id = max(st.last_id, max(m.id for m in gathered))
        db.gc()
        return bool(selected)

    async def _id_probe(self, st: MonitorState, conservative=False):
        if conservative:
            candidates = [st.last_id + 1, st.last_id + 2, st.last_id + 3]
        else:
            if ID_PROBE_MODE == "stride":
                candidates = [st.last_id + 1, st.last_id + 5, st.last_id + 10]
            else:
                candidates = [st.last_id + i for i in range(1, ID_PROBE_SPAN + 1)]
        try:
            r = await self.client(functions.messages.GetMessagesRequest(
                id=[InputMessageID(id=i) for i in candidates]
            ))
        except Exception:
            return []
        found = [m for m in r.messages if getattr(m, "id", 0) > st.last_id]
        found.sort(key=lambda m: m.id)
        if found:
            await self.send_fn(f"[MONITOR][IDPROBE] {st.username} found {len(found)}.")
        return found

    async def _web_head_change(self, st: MonitorState) -> bool:
        url = f"https://t.me/s/{st.username}"
        try:
            async with httpx.AsyncClient(timeout=15) as hc:
                r = await hc.head(url)
            if r.status_code != 200:
                return True
            et = r.headers.get("ETag")
            clen = r.headers.get("Content-Length")
            changed = False
            if et and et != st.etag:
                changed = True
            if clen and clen != st.content_length:
                changed = True
            st.etag = et or st.etag
            st.content_length = clen or st.content_length
            return changed
        except Exception:
            return True

    async def _web_scrape(self, st: MonitorState):
        url = f"https://t.me/s/{st.username}"
        try:
            async with httpx.AsyncClient(timeout=15, headers={"User-Agent":"Mozilla/5.0"}) as hc:
                r = await hc.get(url)
            if r.status_code != 200:
                return False
            ids = re.findall(r'data-post="[^"/]+/(\d+)"', r.text)
            newer = sorted([int(i) for i in ids if int(i) > st.last_id])
            if not newer:
                return False
            lines = [f"[MONITOR][WEB] {st.username} html_new={len(newer)} id>{st.last_id}"]
            for mid in newer[:MAX_MESSAGES_PER_POLL]:
                lines.append(f"  {mid}: [html]")
            if len(newer) > MAX_MESSAGES_PER_POLL:
                lines.append(f"  (+{len(newer)-MAX_MESSAGES_PER_POLL} omitted)")
            await self.send_fn("\n".join(lines))
            st.last_id = max(st.last_id, max(newer))
            integrity.log_event("web_fallback", {"username":st.username,"added":len(newer)})
            return True
        except Exception:
            return False

    def _preview(self, m):
        media_type = None
        if getattr(m, "media", None):
            media_type = type(m.media).__name__
        text = getattr(m, "message", "") or ""
        text = text.replace("\n", " ")
        if len(text) > 160:
            text = text[:157] + "..."
        if media_type and not text:
            text = f"[{media_type}]"
        return f"{m.id}:{media_type}:{text}" if media_type else f"{m.id}:{text}"

    def _media_summary(self, m):
        if not getattr(m, "media", None):
            return "TEXT"
        med = m.media
        if isinstance(med, types.MessageMediaPhoto):
            return "PHOTO"
        if isinstance(med, types.MessageMediaDocument):
            doc = med.document
            mime = getattr(doc,"mime_type",None)
            dims = None
            duration = None
            fname = None
            for attr in getattr(doc,"attributes",[]):
                if isinstance(attr, DocumentAttributeFilename):
                    fname = attr.file_name
                if isinstance(attr, DocumentAttributeVideo):
                    dims = f"{attr.w}x{attr.h}"
                    duration = attr.duration
                if isinstance(attr, DocumentAttributeAudio):
                    duration = attr.duration
            parts = ["DOCUMENT"]
            if mime: parts.append(mime)
            if dims: parts.append(dims)
            if duration: parts.append(f"{duration}s")
            if fname: parts.append(fname[:40])
            return " ".join(parts)
        return type(med).__name__.upper()

monitor_manager = MonitorManager(
    TelegramClient(SESSION_NAME, TELEGRAM_API_ID, TELEGRAM_API_HASH),
    lambda msg: monitor_manager.client.send_message(CONTROLLER_UID, msg) if hasattr(monitor_manager, "client") else None
)

client = monitor_manager.client
pending_confirmation = None

HELP_TEXT = (
    "Commands:\n"
    "  help\n"
    "  list\n"
    "  stop <username>\n"
    "  stopall\n"
    "Send link (invite / @username / message link). Then yes/no to start monitoring."
)

@client.on(events.NewMessage)
async def dispatcher(event):
    if event.sender_id != CONTROLLER_UID:
        return
    await controller(event)

async def controller(event):
    global pending_confirmation
    text = (event.raw_text or "").strip()

    if text in ("yes","no") and pending_confirmation:
        if text == "yes":
            data = pending_confirmation
            await monitor_manager.start_monitor(data['username'], data['last_id'], data['sources'])
            await event.reply(f"Monitoring started: {data['username']}")
        else:
            await event.reply("Monitoring not activated.")
        pending_confirmation = None
        return

    parts = text.split()
    if parts:
        cmd = parts[0].lower()
        if cmd == "help":
            await event.reply(HELP_TEXT); return
        if cmd == "list":
            mons = monitor_manager.list_monitors()
            if not mons:
                await event.reply("No active monitors.")
            else:
                lines = ["Active monitors:"]
                for m in mons:
                    lines.append(f"  {m.username} interval={int(m.current_interval)} last_id={m.last_id}")
                await event.reply("\n".join(lines))
            return
        if cmd == "stop" and len(parts) == 2:
            await monitor_manager.stop_monitor(parts[1]); return
        if cmd == "stopall":
            await monitor_manager.stop_all(); await event.reply("All monitors stopped."); return

    parsed = parse_link(text)
    if parsed.type == "unknown":
        await event.reply("Unrecognized link. Provide invite / @username / message link.\nhelp for usage.")
        return
    await event.reply(f"Link recognized type={parsed.type}. Probing...")

    try:
        # Run probes
        history_ok, history_msgs = await probe_history(client, parsed.username, 10) if parsed.username else (False, [])
        web_ok, web_ids = (await probe_web(parsed.username, 10)) if parsed.username else (False, [])
        msg_link_ok = False
        if parsed.type == "message_link" and parsed.username:
            msg_link_ok = await probe_message_link(client, parsed.username, parsed.message_id)

        positives = []
        if history_ok and history_msgs: positives.append("history")
        if web_ok and web_ids: positives.append("web")
        if msg_link_ok: positives.append("message_link")

        report_lines = ["=== Probe Report ===",
                        f"Positive: {len(positives)>0} (sources: {', '.join(positives) or '-'})"]
        if history_ok:
            report_lines.append(f"[history] ok={bool(history_msgs)} sample_count={len(history_msgs[:3])}")
        if web_ok:
            report_lines.append(f"[web] ok={bool(web_ids)} sample_ids={web_ids[:3]}")
        if msg_link_ok:
            report_lines.append("[message_link] ok=True")
        await client.send_message(CONTROLLER_UID, "\n".join(report_lines))
        integrity.log_event("probe_result", {
            "username": parsed.username,
            "sources": positives,
            "monitorable": bool(positives)
        })

        last_id = 0
        if history_msgs:
            last_id = max(m.id for m in history_msgs)
        elif web_ids:
            last_id = max(web_ids)

        if positives:
            pending_confirmation = {
                "username": parsed.username,
                "last_id": last_id,
                "sources": positives
            }
            await event.reply(f"Monitorable sources={positives} last_id={last_id}. Start? yes/no.")
        else:
            if history_ok is False and web_ok is False and not msg_link_ok:
                await event.reply("Cannot monitor (likely private/supergroup or empty).")
            else:
                await event.reply("Insufficient data for monitoring.")
    except Exception as e:
        log.exception("Probe failure")
        integrity.log_event("probe_error", {"error": repr(e)})
        await event.reply(f"Probe failed: {e}")

_stop = asyncio.Event()
def _sig(sig, frame):
    log.info(f"Signal {sig} received, shutting down...")
    _stop.set()

for s in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(s, _sig)
    except Exception:
        pass

async def main():
    await client.start()
    me = await client.get_me()
    log.info(f"Bot started as {me.id} (@{me.username}) controller={CONTROLLER_UID}")
    integrity.log_event("startup", {
        "user_id": me.id,
        "encryption": True,
        "libsodium_wrap": True,
        "integrity_chain": True
    })
    asyncio.create_task(salt_rotation_scheduler())
    await _stop.wait()
    await client.disconnect()
    db.wrap_on_shutdown()
    integrity.log_event("shutdown", {"reason":"signal"})
    log.info("Shutdown complete.")

if __name__ == "__main__":
    asyncio.run(main())