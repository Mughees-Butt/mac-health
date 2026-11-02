#!/usr/bin/python3
"""Mac Health local server, started only by Mac Health.app.

The app sends a one-time token through stdin, so the token never touches disk or the command line.
The server stops when the app closes that pipe, and stores its data in ~/.mac-health.

To run from source for testing, with no special access, hold a pipe open and send a token of 32 or more characters:
    (openssl rand -hex 32; sleep 600) | HOME=/tmp/some-folder /usr/bin/python3 -I -B src/backend/server.py
It prints "PORT n". Open http://127.0.0.1:n/#<token> in a browser. Without the temporary HOME, scans overwrite real results.
"""
import base64
import hashlib
import hmac
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import secrets
import tempfile
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The app verifies this code, then passes the exact bytes in memory, so nothing is read from disk after that check.
PAYLOAD = globals().get("MAC_HEALTH_PAYLOAD")
if PAYLOAD is None:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # running from source for testing, with no special access

import scanners  # noqa: E402

DATA_DIR = os.path.join(scanners.HOME, ".mac-health")
TECH_DIR = os.path.join(DATA_DIR, "technical")
REMOVED_DIR = os.path.join(DATA_DIR, "removed")
PLAIN_FILE = os.path.join(DATA_DIR, "latest.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.jsonl")
ACTIONS_FILE = os.path.join(DATA_DIR, "actions.jsonl")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
FIRST_SEEN_FILE = os.path.join(DATA_DIR, "first_seen.json")
MOVED_COPIES_FILE = os.path.join(DATA_DIR, "moved_copies.json")

DAY = 86400
HISTORY_RETENTION_DAYS = 90
ACTIONS_RETENTION_DAYS = 30
TTL_CHOICES = (1, 3, 7, 14, 30)
DEFAULT_TTL_DAYS = 7
JOB_LOG_LIMIT = 40000
SCAN_VALID_SECONDS = 3600  # changes need a recent scan, because an app can be reinstalled or a file reused since

TOKEN = None
PORT = None
# Held in the app's keychain item and passed in memory. Without it, nothing saved survives a restart.
DATA_KEY = PAYLOAD["data_key"].encode() if PAYLOAD and PAYLOAD.get("data_key") else secrets.token_bytes(32)
SEALED_MARK = "MHS1:"
# Without the app's key (for example a keychain prompt that went unanswered), saved files are left exactly as they
# are and nothing new is saved. Running from source uses a throwaway key instead.
HAS_KEY = bool(PAYLOAD.get("data_key")) if PAYLOAD else True
INDEX_HTML = b""
HOME = scanners.HOME
# Folders that must never be moved to Trash as a whole, even if a scan result names them.
PROTECTED = {os.path.join(HOME, n).rstrip("/") for n in (
    "", "Library", "Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures", "Applications",
    "Library/Caches", "Library/Logs", "Library/Preferences", "Library/Application Support",
    "Library/LaunchAgents", "Library/Containers", "Library/Group Containers")}
SYSTEM_REMOVABLE_DIRS = {"/Library/LaunchAgents": ".plist", "/Library/LaunchDaemons": ".plist", "/Library/PrivilegedHelperTools": "",
                         "/Library/Audio/Plug-Ins/HAL": ".driver"}
SETTINGS_PANES = {
    "fda": "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
    "firewall": "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall",
    "filevault": "x-apple.systempreferences:com.apple.preference.security?FileVault",
    "login_items": "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
    "updates": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
    "airdrop": "x-apple.systempreferences:com.apple.AirDrop-Handoff-Settings.extension",
    "battery": "x-apple.systempreferences:com.apple.Battery-Settings.extension",
}

# Checks again, inside the same process that moves it, that this is the exact file and folder that were approved.
# A folder swapped for a link in the meantime would otherwise send something else to Trash.
TRASH_SCRIPT = """
function run(argv) {
  ObjC.import('Foundation');
  const url = $.NSURL.fileURLWithPath(argv[0]);
  const parent = url.URLByDeletingLastPathComponent.URLByResolvingSymlinksInPath.path.js;
  const attributes = $.NSFileManager.defaultManager.attributesOfItemAtPathError(argv[0], null);
  if (parent !== argv[1] || attributes.isNil() || String(ObjC.unwrap(attributes.objectForKey('NSFileSystemFileNumber'))) !== argv[2]) return 'changed';
  const error = Ref();
  const ok = $.NSFileManager.defaultManager.trashItemAtURLResultingItemURLError(url, null, error);
  return ok ? 'ok' : 'blocked';  // reading the error object can crash osascript
}
"""
# macOS shows its own password dialog, so this app never sees the password.
ADMIN_SCRIPT = """
on run argv
  return do shell script (item 1 of argv) with administrator privileges
end run
"""

state_lock = threading.Lock()
state = {"scanning": False, "stage": None, "percent": 0, "error": None, "report": None, "tech": {}, "system_tech": None,
         "acting": False, "tech_expires": None, "actionable": {}, "revealable": {}, "system_items": {}, "admin_network": None, "brew_ids": set(), "reinstall": {}, "scanned_at": None, "key_changed": False,
         "job": {"name": None, "running": False, "log": "", "ok": None, "summary": None}}


# ---------- Storage ----------

# Scans, actions and page requests all write from different threads. Taken after state_lock, never before it.
storage_lock = threading.RLock()


def write_private(path, text, mode=0o600):
    with storage_lock:
        fd, temp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".tmp-")
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temp, path)


def open_private(path):
    """Opens only a real file. Another program could replace one with a link into a protected folder or a pipe."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise OSError("Not a regular, unshared file")
    return os.fdopen(fd, encoding="utf-8")


def reject_constant(name):
    raise ValueError(name)


def finite_float(text):
    value = float(text)
    if value in (float("inf"), float("-inf")):
        raise ValueError(text)
    return value


def sealing_keys():
    derive = lambda purpose: hashlib.blake2b(DATA_KEY, digest_size=32, person=purpose).digest()
    return derive(b"mac-health-enc"), derive(b"mac-health-mac")


def keystream_xor(key, nonce, data):
    # The standard library has no AES, so this is keyed BLAKE2b in counter mode, then a separate keyed tag.
    output = bytearray(len(data))
    for block in range(0, len(data), 64):
        stream = hashlib.blake2b(nonce + (block // 64).to_bytes(8, "big"), key=key, digest_size=64).digest()
        chunk = data[block:block + 64]
        output[block:block + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, stream))
    return bytes(output)


def seal(text, context):
    """Encrypts results that name your files, so other programs running as you can't read them. context ties it to its use."""
    enc_key, mac_key = sealing_keys()
    nonce = secrets.token_bytes(16)
    body = keystream_xor(enc_key, nonce, text.encode("utf-8"))
    tag = hashlib.blake2b(context.encode() + nonce + body, key=mac_key, digest_size=32).digest()
    return SEALED_MARK + base64.b64encode(nonce + tag + body).decode("ascii")


def unseal(text, context):
    """Returns the text, or None if it was changed, sealed with another key, or isn't sealed at all."""
    if not text.startswith(SEALED_MARK):
        return None
    try:
        raw = base64.b64decode(text[len(SEALED_MARK):], validate=True)
        nonce, tag, body = raw[:16], raw[16:48], raw[48:]
        enc_key, mac_key = sealing_keys()
        expected = hashlib.blake2b(context.encode() + nonce + body, key=mac_key, digest_size=32).digest()
        return keystream_xor(enc_key, nonce, body).decode("utf-8") if hmac.compare_digest(tag, expected) else None
    except ValueError:
        return None


def write_sealed(path, value, context):
    if HAS_KEY:
        write_private(path, seal(to_json(value), context))


def read_sealed(path, fallback, context):
    try:
        with open_private(path) as handle:
            text = unseal(handle.read().strip(), context)
        if text is None:
            return fallback
        value = json.loads(text, parse_constant=reject_constant, parse_float=finite_float)
    except (OSError, ValueError, RecursionError):
        return fallback
    return value if fallback is None or isinstance(value, type(fallback)) else fallback


def encode_row(path, row):
    return seal(to_json(row), "actions") if path == ACTIONS_FILE else to_json(row)


def may_write(path):
    return HAS_KEY or path != ACTIONS_FILE


def to_json(value):
    return json.dumps(value, default=str)  # plist values can be dates or data


def read_jsonl(path):
    rows = []
    try:
        with open_private(path) as handle:
            for line in handle:
                line = line.strip()
                # Any program running as you can append a plain line, so only rows this app sealed count.
                if path == ACTIONS_FILE:
                    line = unseal(line, "actions") or ""
                try:
                    row = json.loads(line, parse_constant=reject_constant, parse_float=finite_float)
                except (ValueError, RecursionError):
                    continue
                if isinstance(row, dict) and isinstance(row.get("t"), (int, float)):
                    rows.append(row)
    except (OSError, ValueError):
        pass
    return rows


def append_jsonl(path, row):
    if not may_write(path):
        return
    with storage_lock:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(fd)
            raise OSError("Not a regular, unshared file")
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(encode_row(path, row) + "\n")


def prune_jsonl(path, retention_days):
    cutoff = time.time() - retention_days * DAY
    with storage_lock:
        rows = read_jsonl(path)
        kept = [r for r in rows if r.get("t", 0) >= cutoff]
        # Lines from before encryption name moved files in plain text. Rewriting keeps only sealed rows.
        stale = path == ACTIONS_FILE and has_unsealed_lines(path)
        if (len(kept) != len(rows) or stale) and may_write(path):
            write_private(path, "".join(encode_row(path, r) + "\n" for r in kept))


def has_unsealed_lines(path):
    try:
        with open_private(path) as handle:
            return any(line.strip() and not line.startswith(SEALED_MARK) for line in handle)
    except (OSError, ValueError):
        return False


def read_json(path, fallback):
    """Anything malformed, or of the wrong type, counts as missing."""
    try:
        with open_private(path) as handle:
            value = json.load(handle, parse_constant=reject_constant, parse_float=finite_float)
    except (OSError, ValueError, RecursionError):
        return fallback
    return value if fallback is None or isinstance(value, type(fallback)) else fallback


def get_ttl_days():
    value = read_json(SETTINGS_FILE, {}).get("technical_ttl_days")
    return value if value in TTL_CHOICES else DEFAULT_TTL_DAYS


def purge_expired():
    """Delete technical summaries past their expiry, and old history and action logs."""
    now = time.time()
    try:
        if not os.path.islink(REMOVED_DIR):
            for name in os.listdir(REMOVED_DIR):
                os.rmdir(os.path.join(REMOVED_DIR, name))  # only succeeds on empty folders
    except OSError:
        pass
    for path in technical_files():
        expires = read_sealed(path, {}, "technical").get("expires_at", 0)
        if not isinstance(expires, (int, float)) or expires <= now:
            try:
                os.remove(path)
            except OSError:
                pass
    with state_lock:
        if state["tech_expires"] and state["tech_expires"] <= now:
            state["tech"], state["system_tech"], state["tech_expires"] = {}, None, None
    prune_jsonl(HISTORY_FILE, HISTORY_RETENTION_DAYS)
    prune_jsonl(ACTIONS_FILE, ACTIONS_RETENTION_DAYS)


def technical_files():
    """Only files this app wrote. This deletes for real, so it never follows a link or touches anything else."""
    if os.path.islink(TECH_DIR):
        return []
    try:
        names = os.listdir(TECH_DIR)
    except OSError:
        return []
    found = []
    for name in sorted(names):
        path = os.path.join(TECH_DIR, name)
        try:
            if scanners.re.fullmatch(r"\d+\.json", name) and stat.S_ISREG(os.lstat(path).st_mode):
                found.append(path)
        except OSError:
            pass
    return found


def delete_all_technical():
    for path in technical_files():
        try:
            os.remove(path)
        except OSError:
            pass
    with state_lock:
        state["tech"], state["system_tech"], state["tech_expires"] = {}, None, None


def valid_report(report):
    """Saved results are readable and writable by any program running as you, so check them before showing them."""
    if not isinstance(report, dict) or not isinstance(report.get("sections"), dict) or not isinstance(report.get("cards"), dict):
        return False
    if not all(isinstance(report["cards"].get(k), dict) for k in ("disk", "memory", "cpu", "security")):
        return False
    if not all(isinstance(report.get(k, []), list) for k in ("limits", "can_do")):
        return False
    if not all(isinstance(report.get(k), (int, float)) for k in ("score", "generated_at")):
        return False
    lists = [report["sections"].get(k) for k in ("alerts", "leftovers", "clutter", "developer", "large", "duplicates", "network", "startup")]
    lists += [report.get(k) for k in ("tips", "coverage", "deductions")]
    if not all(isinstance(rows, list) and all(isinstance(r, dict) for r in rows) for rows in lists):
        return False
    return all(isinstance(c.get("area"), str) for c in report["coverage"])


def load_saved():
    """Restore the last results after a restart. Actions stay off until a fresh scan."""
    saved_report = read_sealed(PLAIN_FILE, None, "report")
    state["report"] = saved_report if valid_report(saved_report) else None
    if not state["report"]:
        return
    files = technical_files()
    if files:
        saved = read_sealed(files[-1], {}, "technical")
        expires = saved.get("expires_at", 0)
        if isinstance(expires, (int, float)) and expires > time.time() and isinstance(saved.get("items"), dict):
            state["tech"] = saved["items"]
            state["system_tech"] = saved.get("system")
            state["tech_expires"] = expires


def remove_unsealed_results():
    """Results from before encryption, or from another key. A new scan replaces them."""
    if not HAS_KEY:
        return
    for path, context in ((PLAIN_FILE, "report"),):
        if os.path.lexists(path) and read_sealed(path, None, context) is None:
            try:
                with open_private(path) as handle:
                    # Sealed results the current key can't open mean the key changed, which you should hear about.
                    state["key_changed"] = handle.read(len(SEALED_MARK)) == SEALED_MARK
            except (OSError, ValueError):
                pass
            try:
                os.remove(path)
            except OSError:
                pass


def secure_subfolders():
    for folder in (TECH_DIR, REMOVED_DIR):
        if os.path.islink(folder):
            os.remove(folder)
        os.makedirs(folder, mode=0o700, exist_ok=True)


def secure_data_folders():
    """A link here would turn this app's own housekeeping into changes inside a protected folder.
    The app then works from inside the folder it checked, so swapping the name later doesn't redirect it."""
    global TECH_DIR, REMOVED_DIR, PLAIN_FILE, HISTORY_FILE, ACTIONS_FILE, SETTINGS_FILE, FIRST_SEEN_FILE, MOVED_COPIES_FILE
    if os.path.islink(DATA_DIR):
        print("~/.mac-health is a link, so Mac Health won't use it.", file=sys.stderr)
        sys.exit(1)
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    fd = os.open(DATA_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    os.fchmod(fd, 0o700)
    os.fchdir(fd)
    os.close(fd)
    TECH_DIR, REMOVED_DIR = "technical", "removed"
    PLAIN_FILE, HISTORY_FILE, ACTIONS_FILE = "latest.json", "history.jsonl", "actions.jsonl"
    SETTINGS_FILE, FIRST_SEEN_FILE, MOVED_COPIES_FILE = "settings.json", "first_seen.json", "moved_copies.json"
    secure_subfolders()


def set_setting(key, value):
    # One lock around read and write, so two saves at once can't each drop the other's change.
    with storage_lock:
        settings = read_json(SETTINGS_FILE, {})
        settings[key] = value
        write_private(SETTINGS_FILE, to_json(settings))


def recalculate(report):
    """Keep the score and next steps true after every action, without a full scan. Caller holds the lock."""
    report["score"], report["deductions"] = scanners.build_score(report["cards"], report["sections"], report.get("coverage"))
    report["tips"] = scanners.build_tips(report["cards"], report["sections"])
    stamp_first_seen(report["tips"])
    write_sealed(PLAIN_FILE, report, "report")


def stamp_first_seen(tips):
    """Remember when each recommendation first appeared, so the dashboard can say how long it's waited."""
    seen = read_json(FIRST_SEEN_FILE, {})
    now = time.time()
    current = {t["key"]: seen[t["key"]] if isinstance(seen.get(t["key"]), (int, float)) else now for t in tips}
    for tip in tips:
        tip["days_waiting"] = int((now - current[tip["key"]]) / DAY)
    write_private(FIRST_SEEN_FILE, to_json(current))


# ---------- Scan ----------

def add_check_command(entry, tech):
    """The command that shows this finding, so any result can be checked by hand."""
    if "command" in tech:
        return
    paths = tech.get("paths") or ([tech["path"]] if tech.get("path") else [])
    shown = " ".join(shlex.quote(p).replace(shlex.quote(HOME), "~", 1) if p == HOME else ("~" + shlex.quote(p[len(HOME):]) if p.startswith(HOME + "/") else shlex.quote(p)) for p in paths[:3])
    category = entry["category"]
    if category == "network":
        tech["command"] = "lsof +c0 -nP -iTCP -sTCP:LISTEN" if entry["severity"] != "info" else "lsof +c0 -nP -iTCP -sTCP:ESTABLISHED"
    elif category == "startup":
        tech["command"] = "sfltool dumpbtm"
    elif category == "alerts" and paths:
        tech["command"] = "codesign -dv --verbose=2 %s" % shown
    elif tech.get("system_items"):
        tech["command"] = "ls -l %s" % " ".join(shlex.quote(i["path"]) for i in tech["system_items"][:3])
    elif paths:
        tech["command"] = "du -sh %s" % shown


def do_scan():
    def progress(stage, percent):
        with state_lock:
            state["stage"], state["percent"] = stage, percent

    try:
        with state_lock:
            last = state["report"]["generated_at"] if state["report"] else None
        report = scanners.full_scan(progress, last_scan=last)
        stamp_first_seen(report["tips"])
        tech, actionable, revealable, system_items, brew_ids, reinstall = {}, {}, {}, {}, set(), {}
        for items in report["sections"].values():
            for entry in items:
                tech[entry["id"]] = entry.pop("technical")
                paths = entry.pop("paths")
                stamp = entry.pop("stamp", None)
                if paths:
                    tech[entry["id"]].setdefault("paths", paths)
                if entry.get("locked"):
                    revealable[entry["id"]] = tech[entry["id"]]["protected_paths"][0]
                if entry["trashable"]:
                    actionable[entry["id"]] = {"paths": paths, "group": entry["group"], "category": entry["category"], "size": entry["size"]}
                    if entry["category"] in ("large", "duplicates"):
                        actionable[entry["id"]]["stamp"] = stamp
                if entry.get("fix") and entry["fix"]["kind"] == "admin_remove":
                    system_items[entry["id"]] = {"system": tech[entry["id"]]["system_items"], "user": tech[entry["id"]].get("user_items", [])}
                if tech[entry["id"]].get("reinstall"):
                    # The app's path is kept too, so the reinstall can check it isn't running.
                    reinstall[entry["id"]] = dict(tech[entry["id"]]["reinstall"], path=tech[entry["id"]].get("path"))
                add_check_command(entry, tech[entry["id"]])
                if entry["category"] == "developer" and ("package" in tech[entry["id"]] or (entry.get("fix") or {}).get("kind") == "brew"):
                    brew_ids.add(entry["id"])
        system = {"cards": report["cards"], "command_output": report["meta"].pop("raw")}
        expires = time.time() + get_ttl_days() * DAY

        secure_subfolders()
        delete_all_technical()
        write_sealed(os.path.join(TECH_DIR, "%d.json" % report["generated_at"]),
                     {"expires_at": expires, "items": tech, "system": system}, "technical")
        write_sealed(PLAIN_FILE, report, "report")

        sizes = lambda name: sum(i["size"] or 0 for i in report["sections"][name])
        append_jsonl(HISTORY_FILE, {
            "t": report["generated_at"], "score": report["score"], "disk_used": report["cards"]["disk"]["used"],
            "disk_total": report["cards"]["disk"]["total"], "full_disk_access": report["access"]["full_disk_access"], "unfinished_checks": len(report["coverage"]),
            "alerts": len(report["sections"]["alerts"]), "leftovers_size": sizes("leftovers"),
            "clutter_size": sizes("clutter"), "developer_size": sizes("developer"),
        })
        purge_expired()
        with state_lock:
            state.update(report=report, tech=tech, system_tech=system, tech_expires=expires, actionable=actionable,
                         revealable=revealable, system_items=system_items, brew_ids=brew_ids, reinstall=reinstall, scanned_at=time.time(), error=None)
    except Exception as error:
        with state_lock:
            state["error"] = "The scan failed: %s" % error
    finally:
        with state_lock:
            state["scanning"], state["stage"], state["percent"] = False, None, 0


# ---------- Trash ----------

def folded(path):
    """macOS treats names as the same regardless of case or accent form, so comparisons must too."""
    return unicodedata.normalize("NFC", path).casefold()


# Never moved, nor anything inside them, even if a scan result names them.
NEVER_MOVED = tuple(folded(os.path.join(HOME, n)) for n in (
    ".ssh", ".gnupg", "Library/Keychains", "Library/Mobile Documents", "Library/Messages", "Library/Mail"))
PROTECTED_FOLDED = {folded(p) for p in PROTECTED}


def path_problem(path):
    """Return why a path may not be moved, or None if it's allowed."""
    clean = os.path.normpath(path)
    if clean != path or not os.path.isabs(path) or path.startswith("//"):
        return "The path isn't valid."
    parent = os.path.realpath(os.path.dirname(path))
    if parent != os.path.dirname(path):
        return "Its folder is now a link, so it wasn't moved."  # links are how a protected folder could be swapped in
    target = os.path.join(parent, os.path.basename(path))
    for candidate in (folded(path), folded(target)):
        if candidate in PROTECTED_FOLDED or any(candidate == n or candidate.startswith(n + "/") for n in NEVER_MOVED) or ".photoslibrary" in candidate:
            return "This is a protected folder."
    if folded(target).startswith(folded(HOME) + "/"):
        return None
    if parent == "/Applications" and target.endswith(".app"):
        return None
    return "This location is outside what the tool may change."


def move_to_trash(path):
    try:
        info = os.lstat(path)
    except OSError:
        return "It's already gone."
    parent = os.path.realpath(os.path.dirname(path))
    code, out = scanners.run(["/usr/bin/osascript", "-l", "JavaScript", "-e", TRASH_SCRIPT, path, parent, str(info.st_ino)], timeout=120)
    if out.strip() == "changed":
        return "It changed after the scan, so it wasn't moved"
    if code == 0 and out.strip() == "ok" and not os.path.lexists(path):
        return None
    return "macOS blocked this move"


def file_stamp(path):
    """Identifies the exact file a scan saw, so an edited or replaced file isn't removed on old information."""
    try:
        info = os.lstat(path)
    except OSError:
        return None
    return scanners.stamp_of(info)


def begin_action():
    """Scans and changes exclude each other, so neither works from the other's stale results."""
    with state_lock:
        if state["scanning"] or state["acting"]:
            return False
        state["acting"] = True
        return True


def end_action():
    with state_lock:
        state["acting"] = False


def scan_too_old():
    with state_lock:
        scanned = state["scanned_at"]
    return not scanned or time.time() - scanned > SCAN_VALID_SECONDS


TOO_OLD = {"error": "This scan is over an hour old. Scan again, then retry."}, 409


def already_moved_copy(entry, path):
    """A rescan can't see copies in Trash, so remember them. Only a large file can lose its duplicate label this way."""
    size = str(entry.get("size"))
    known = read_sealed(MOVED_COPIES_FILE, {}, "copies").get(size)
    if entry["category"] != "large" or not isinstance(known, list):
        return False
    try:
        return scanners.full_hash(path) in known
    except OSError:
        return False


def remember_moved_copy(entry, digest):
    with storage_lock:
        known = read_sealed(MOVED_COPIES_FILE, {}, "copies")
        known.setdefault(str(entry["size"]), [])
        if isinstance(known[str(entry["size"])], list):
            known[str(entry["size"])].append(digest)
        write_sealed(MOVED_COPIES_FILE, known, "copies")


def trash_items(ids, personal_ok=False):
    if scan_too_old():
        return TOO_OLD
    with state_lock:
        actionable = dict(state["actionable"])
    unknown = [i for i in ids if i not in actionable]
    if unknown:
        return {"error": "Some items aren't from your latest scan. Scan again, then retry."}, 409
    # Your own files take a separate confirmation from anything that rebuilds itself.
    if not personal_ok and any(actionable[i]["category"] in ("large", "duplicates") for i in ids):
        return {"error": "Moving your own files needs its own confirmation."}, 400

    # One file can be listed under Large files and Duplicates, so compare paths, not just item ids.
    chosen_paths = {path for item_id in ids for path in actionable[item_id]["paths"]}
    groups = {}
    for key, entry in actionable.items():
        if entry["group"]:
            groups.setdefault(entry["group"], []).append(entry)
    for members in groups.values():
        if chosen_paths & {m["paths"][0] for m in members}:
            survivors = [m for m in members if m["paths"][0] not in chosen_paths and m.get("stamp") and file_stamp(m["paths"][0]) == m["stamp"]]
            if not survivors:
                return {"error": "Keep at least one unchanged copy of each duplicate. Deselect one copy or scan again, then retry."}, 400

    results = []
    for item_id in ids:
        failures = []
        entry = actionable[item_id]
        for path in entry["paths"]:
            if "stamp" in entry and os.path.lexists(path) and file_stamp(path) != entry["stamp"]:
                failures.append({"name": os.path.basename(path), "reason": "It changed after the scan, so it wasn't moved"})
                continue
            if already_moved_copy(entry, path):
                failures.append({"name": os.path.basename(path), "reason": "An identical copy was already moved to Trash, so this may be the last one"})
                continue
            problem = path_problem(path) or move_to_trash(path)
            if problem and problem != "It's already gone.":
                failures.append({"name": os.path.basename(path), "reason": problem})
            elif not problem:
                append_jsonl(ACTIONS_FILE, {"t": time.time(), "action": "moved_to_trash", "path": path})
                if entry["group"]:
                    remember_moved_copy(entry, entry["group"])
        results.append({"id": item_id, "ok": not failures, "failures": failures})

    done_paths = set()
    for result in results:
        if result["ok"]:
            done_paths.update(actionable[result["id"]]["paths"])
    removed = [k for k, v in actionable.items() if set(v["paths"]) <= done_paths]
    drop_items(removed)
    return {"results": results, "removed": removed}, 200


def drop_items(ids):
    with state_lock:
        report = state["report"]
        for key in ids:
            state["actionable"].pop(key, None)
            state["system_items"].pop(key, None)
            state["reinstall"].pop(key, None)
        if not report:
            return
        for name, items in report["sections"].items():
            report["sections"][name] = [i for i in items if i["id"] not in ids]
        # A copy left on its own isn't a duplicate any more, so it leaves the list instead of saying "2 copies".
        left = report["sections"].get("duplicates", [])
        counts = {}
        for entry in left:
            counts[entry["group"]] = counts.get(entry["group"], 0) + 1
        alone = {e["id"] for e in left if counts[e["group"]] < 2}
        report["sections"]["duplicates"] = [e for e in left if e["id"] not in alone]
        for key in alone:
            state["actionable"].pop(key, None)
        recalculate(report)


# ---------- Actions that need the user's password ----------

def run_admin(command):
    """Returns (ok, output). macOS asks for the password, and each use asks again."""
    set_setting("admin_last_used", time.time())
    code, out = scanners.run(["/usr/bin/osascript", "-e", ADMIN_SCRIPT, command], timeout=300)
    if code != 0 and "User canceled" in out:
        return False, "You cancelled the password prompt, so nothing changed."
    return code == 0, out


def system_item_problem(path):
    parent = os.path.dirname(path)
    extension = SYSTEM_REMOVABLE_DIRS.get(parent)
    if extension is None or not path.endswith(extension) or os.path.normpath(path) != path or os.path.realpath(parent) != parent:
        return "This location is outside what the tool may change."
    if not os.path.lexists(path):
        return "It's already gone."
    # Checked again just before the admin prompt: a file your account can change can't be trusted to name what root removes.
    return None if scanners.protected_by_root(path) else "This file isn't protected by macOS, so Mac Health won't remove it."


def remove_system_item(item_id):
    """Unload the startup files, then move them to Trash. A row can hold system files and files of your own."""
    if scan_too_old():
        return TOO_OLD
    with state_lock:
        targets = state["system_items"].get(item_id)
    if not targets:
        return {"error": "This item isn't from your latest scan. Scan again, then retry."}, 409
    uid = os.getuid()
    entries = [e for e in targets["system"] if system_item_problem(e["path"]) != "It's already gone."]
    for entry in entries:
        problem = system_item_problem(entry["path"])
        if problem:
            return {"error": problem}, 400
    note = None
    if entries:
        # Root makes the holding folder itself, so no other program can place anything in it first.
        steps = ["HOLD=$(/usr/bin/mktemp -d /private/tmp/machealth.XXXXXXXX) || exit 1"]
        for entry in entries:
            if entry.get("label"):
                label = shlex.quote(entry["label"])
                # These can fail harmlessly, because the job may not be loaded.
                steps.append("/bin/launchctl bootout system/%s 2>/dev/null" % label)
                steps.append("/bin/launchctl bootout gui/%d/%s 2>/dev/null" % (uid, label))
            steps.append('/bin/mv -n %s "$HOLD"/' % shlex.quote(entry["path"]))
        # A hard link inside could be another root file, so linked files are never handed over.
        # Only each moved item itself is handed over, never what's inside it. Every path here starts with the
        # root-only holding folder, which no other program can change, and that folder is handed over last.
        steps.append('/usr/bin/find "$HOLD" -mindepth 1 -maxdepth 1 \\( -type d -o -links 1 \\) -exec /usr/sbin/chown -h %d {} +' % uid)
        steps.append('/usr/sbin/chown %d "$HOLD"' % uid)
        steps.append('echo "$HOLD"')
        ok, output = run_admin("; ".join(steps))
        if not ok:
            return {"error": output.strip() or "macOS didn't allow this change."}, 400
        lines = output.strip().splitlines()
        hold = lines[-1] if lines else ""
        try:
            confirmed = scanners.re.fullmatch(r"/private/tmp/machealth\.[A-Za-z0-9]+", hold) and os.lstat(hold).st_uid == uid
        except OSError:
            confirmed = False
        if not confirmed:
            return {"error": "macOS didn't confirm this change, so scan again to check."}, 400
        # mv -n keeps each name, so the log can say where the item was, not the temporary folder.
        original = {}
        for entry in entries:
            original.setdefault(os.path.basename(entry["path"]), entry["path"])
        for name in os.listdir(hold):
            path = os.path.join(hold, name)
            append_jsonl(ACTIONS_FILE, {"t": time.time(), "action": "removed_system_item", "path": original.get(name, path)})
            if move_to_trash(path):
                # Temporary folders get cleared, so keep anything Trash refused somewhere it will last.
                kept = tempfile.mkdtemp(dir=REMOVED_DIR)
                try:
                    shutil.move(path, kept)
                    note = "macOS wouldn't move it to Trash, so a copy is in %s." % scanners.pretty_path(kept)
                except OSError:
                    note = "macOS wouldn't move part of this to Trash, so it's still in %s." % hold
        try:
            os.rmdir(hold)
        except OSError:
            pass
        left = [e["path"] for e in entries if os.path.lexists(e["path"])]
        if left:
            return {"error": "These couldn't be removed: %s" % ", ".join(left)}, 400
    # The row stays until every file is gone, so it never says done while one is left behind.
    left = []
    for entry in targets["user"]:
        path = entry["path"]
        if not os.path.lexists(path):
            continue
        if entry.get("label"):
            scanners.run(["/bin/launchctl", "bootout", "gui/%d/%s" % (uid, entry["label"])], timeout=15)
        problem = path_problem(path) or move_to_trash(path)
        if problem and problem != "It's already gone.":
            left.append(path)
        elif not problem:
            append_jsonl(ACTIONS_FILE, {"t": time.time(), "action": "moved_to_trash", "path": path})
    if left:
        return {"error": "These couldn't be removed: %s" % ", ".join(left)}, 400
    drop_items([item_id])
    return {"ok": True, "note": note}, 200


def turn_on_firewall():
    tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    ok, output = run_admin("%s --setglobalstate on" % tool)
    if not ok:
        return {"error": output.strip() or "macOS didn't allow this change."}, 400
    _, status = scanners.run([tool, "--getglobalstate"], timeout=10)
    with state_lock:
        report = state["report"]
        if report and "is enabled" in status.lower():
            report["cards"]["security"]["firewall"] = True
            recalculate(report)
    return {"ok": "is enabled" in status.lower()}, 200


def admin_network_check():
    ok, output = run_admin("/usr/sbin/lsof +c0 -nP -iTCP -sTCP:LISTEN")
    if not ok:
        return {"error": output.strip() or "macOS didn't allow this check."}, 400
    rows = {}
    for line in output.splitlines()[1:]:
        parts = line.split()
        if line.rstrip().endswith("(LISTEN)") and len(parts) >= 3:
            name = scanners.re.match(r"^(.+?)\s+\d+\s", line)
            address = parts[-2]
            if name and address.startswith(("*:", "0.0.0.0:", "[::]:")):
                rows.setdefault(name.group(1).replace("\\x20", " "), set()).add(address.rsplit(":", 1)[-1])
    # Kept in memory only, so it disappears when the app closes.
    result = [{"process": k, "ports": sorted(v, key=lambda p: int(p) if p.isdigit() else 0)} for k, v in sorted(rows.items())]
    with state_lock:
        state["admin_network"] = result
    return {"ok": True}, 200


PACKAGE_NAME = r"[A-Za-z0-9@][A-Za-z0-9@._+-]*"  # a leading dash would read as an option
BREW_ENV = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOMEBREW_NO_ENV_HINTS": "1",
            "NONINTERACTIVE": "1", "HOMEBREW_NO_AUTO_UPDATE": "1"}


def find_brew():
    return shutil.which("brew", path="/opt/homebrew/bin:/usr/local/bin")


def job_log(text):
    with state_lock:
        state["job"]["log"] = (state["job"]["log"] + text)[-JOB_LOG_LIMIT:]


def run_brew_step(brew, args, env):
    """Runs one brew command, streaming to the log. Returns (exit code, output)."""
    job_log("$ brew %s\n" % " ".join(args))
    return scanners.run_outside([brew] + args, timeout=3600, env=env, merge=True, on_output=job_log)


def refresh_brew_item():
    gaps = []
    items = scanners.brew_items(gaps)
    with state_lock:
        report = state["report"]
        if not report:
            return
        report["coverage"] = [c for c in report["coverage"] if c["area"] != "Homebrew"] + gaps
        if gaps:  # keep the rows already shown, because no answer doesn't mean they're done
            recalculate(report)
            return
        fresh = {entry["id"] for entry in items}
        developer = [i for i in report["sections"]["developer"] if not (i["id"] in state["brew_ids"] or i["id"] in fresh or (i.get("fix") or {}).get("kind") == "brew")]
        state["brew_ids"] = set()
        for entry in items:
            state["tech"][entry["id"]] = entry.pop("technical")
            entry.pop("paths")
            state["brew_ids"].add(entry["id"])
            developer.append(entry)
        report["sections"]["developer"] = developer
        recalculate(report)


def run_brew_job():
    summary = None
    ok = False
    try:
        ok, summary = run_brew_steps()
        refresh_brew_item()
    except Exception as error:  # the dialog must always finish, whatever brew does
        job_log("\nThe update stopped unexpectedly: %s\n" % error)
    finally:
        with state_lock:
            state["job"].update(running=False, ok=ok, summary=summary)
            state["acting"] = False


def run_brew_steps():
    brew = find_brew()
    summary = {"updated": 0, "needs_password": [], "failed": [], "disabled": [], "tools_problem": False}
    if not brew:
        job_log("Homebrew wasn't found.\n")
        return False, summary
    env = dict(BREW_ENV)

    def outdated():
        text = run_quiet(brew, ["outdated", "--json=v2"], env)
        if not text:  # no answer isn't "nothing outdated", which would count as every update working
            raise RuntimeError("Homebrew didn't report which packages are outdated.")
        data = json.loads(text)
        return {f["name"] for f in data.get("formulae", [])}, {c["name"] for c in data.get("casks", [])}

    code, output = run_brew_step(brew, ["update"], env)
    summary["tools_problem"] = "Command Line Tools" in output
    before_formulae, before_casks = outdated()
    code, output = run_brew_step(brew, ["upgrade", "--formula"], env)
    summary["tools_problem"] = summary["tools_problem"] or "Command Line Tools" in output
    # Casks run one at a time, so one that needs a password can't stop the rest.
    for cask in sorted(before_casks):
        code, output = run_brew_step(brew, ["upgrade", "--cask", cask], env)
        if "password is required" in output or "a terminal is required" in output or "Operation not permitted" in output:
            summary["needs_password"].append(cask)
        elif "Not upgrading" in output or "is disabled" in output:
            summary["disabled"].append(cask)  # brew exits successfully when it refuses, so read the output
        elif code != 0:
            summary["failed"].append(cask)
    # Count what's really gone from the outdated list, not what brew exited cleanly on.
    after_formulae, after_casks = outdated()
    summary["updated"] = len(before_formulae - after_formulae) + len(before_casks - after_casks)
    if after_formulae:
        info = json.loads(run_quiet(brew, ["info", "--json=v2", "--formula"] + sorted(after_formulae), env) or "{}")
        retired = {f["name"] for f in info.get("formulae", []) if f.get("disabled")}
        summary["disabled"].extend(sorted(retired))
        summary["failed"].extend(sorted(after_formulae - retired))
    return not (summary["failed"] or summary["needs_password"]), summary


def run_quiet(brew, args, env):
    return scanners.run_outside([brew] + args, timeout=120, env=env)[1]


def open_terminal_script(lines):
    path = os.path.join(DATA_DIR, "mac-health-brew.command")
    name = os.path.basename(path) if not os.path.isabs(TECH_DIR) else path  # relative once the app works from inside its folder
    write_private(name, "#!/bin/zsh\n%s\necho\necho 'Done. Go back to Mac Health and scan again.'\nrm -f %s\n" % ("\n".join(lines), shlex.quote(path)), mode=0o700)
    scanners.run(["/usr/bin/open", "-a", "Terminal", path], timeout=10)


def brew_remove_in_terminal(item_id):
    """Only removes a package this scan found unused, and rechecks that just before running."""
    with state_lock:
        tech = state["tech"].get(item_id) or {}
        fresh = item_id in state["brew_ids"]  # saved results stay read-only until a new scan
    if not fresh:
        return {"error": "This can't be removed from here. Scan again."}, 400
    if scan_too_old():
        return TOO_OLD
    name, kind = tech.get("package"), tech.get("kind")
    together = tech.get("remove_with") or []
    packages = together + [name]  # what needs it goes first
    brew = find_brew()
    if not brew or not name or kind not in ("formula", "cask") or (tech.get("needed_by") and not together) or not all(scanners.re.fullmatch(PACKAGE_NAME, str(p)) for p in packages):
        return {"error": "This can't be removed from here. Scan again."}, 400
    for package in packages:
        users = scanners.brew_dependents(brew, kind, package)
        if users is None:
            return {"error": "Couldn't check what needs this, so it wasn't removed. Scan again."}, 400
        if set(users) - set(packages):
            return {"error": "Another package now needs this, so it wasn't removed."}, 400
    open_terminal_script(["%s uninstall --%s %s" % (shlex.quote(brew), kind, " ".join(shlex.quote(p) for p in packages))])
    return {"ok": True}, 200


def brew_reinstall_in_terminal(item_id):
    """Replaces an app this scan found damaged with Homebrew's copy."""
    if scan_too_old():
        return TOO_OLD
    with state_lock:
        cask = state["reinstall"].get(item_id)
    brew = find_brew()
    app = (cask or {}).get("path")
    valid_app = isinstance(app, str) and os.path.isabs(app) and os.path.normpath(app) == app and app.endswith(".app")
    if not brew or not cask or not valid_app or not scanners.re.fullmatch(PACKAGE_NAME, cask["token"]):
        return {"error": "This can't be reinstalled from here. Scan again."}, 400
    # Replacing a running app can break it, so check rather than trust the advice to quit it. pgrep reads a pattern,
    # so the path's special characters are escaped, and only programs inside this app's bundle match.
    pattern = "^" + scanners.re.sub(r"([.\[\](){}*+?|^$\\])", r"\\\1", app) + "/Contents/MacOS/"
    code, _ = scanners.run(["/usr/bin/pgrep", "-f", pattern], timeout=10)
    name = os.path.basename(app)[:-4]
    if code == 0:
        return {"error": "Quit %s first, then try again." % name}, 409
    if code != 1:  # 1 means nothing matched; anything else means it couldn't be checked
        return {"error": "Couldn't check whether %s is running, so nothing was started. Try again." % name}, 409
    # An app that didn't come from Homebrew has to be replaced, which is what --force is for.
    verb = "reinstall --cask" if cask["installed"] else "install --cask --force"
    open_terminal_script(["%s %s %s" % (shlex.quote(brew), verb, shlex.quote(cask["token"]))])
    return {"ok": True}, 200


def brew_finish_in_terminal():
    """Terminal can ask for the password. The script is built here and only names packages brew reported."""
    if scan_too_old():
        return TOO_OLD
    with state_lock:
        names = list((state["job"].get("summary") or {}).get("needs_password") or [])
    brew = find_brew()
    if not brew or not names or not all(scanners.re.fullmatch(PACKAGE_NAME, n) for n in names):
        return {"error": "There's nothing to finish in Terminal."}, 400
    open_terminal_script(["%s upgrade --cask %s" % (shlex.quote(brew), " ".join(shlex.quote(n) for n in names))])
    return {"ok": True}, 200


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    server_version = "MacHealth"
    timeout = 15  # an idle connection can't hold a thread forever
    sys_version = ""

    def log_message(self, *args):
        pass

    def send_body(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, code=200):
        self.send_body(code, to_json(data).encode("utf-8"))

    def allowed(self):
        # The Host and Origin checks block other websites. The token blocks local programs and other accounts.
        expected = "127.0.0.1:%d" % PORT
        origin = self.headers.get("Origin")
        origin_ok = origin is None or origin == "http://" + expected
        token_ok = secrets.compare_digest(self.headers.get("X-Token", "").encode("utf-8", "replace"), TOKEN.encode())
        return self.headers.get("Host") == expected and origin_ok and token_ok

    def exclusive(self, action, *args):
        """Runs something that changes the Mac, unless a scan or another change is running."""
        if not begin_action():
            return self.send_json({"error": "Wait for the scan or current action to finish."}, 409)
        try:
            data, code = action(*args)
        finally:
            end_action()
        return self.send_json(data, code)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self.send_body(200, INDEX_HTML, "text/html; charset=utf-8")
        if not self.allowed():
            return self.send_json({"error": "Not allowed."}, 403)
        if path == "/api/status":
            with state_lock:
                data = {"scanning": state["scanning"], "stage": state["stage"], "percent": state["percent"], "error": state["error"]}
            return self.send_json(data)
        if path == "/api/report":
            purge_expired()
            # Disk checks and sending happen outside the lock, so one slow request can't stall the others.
            ttl_days, access, admin_used = get_ttl_days(), scanners.full_disk_access(), read_json(SETTINGS_FILE, {}).get("admin_last_used")
            with state_lock:
                data = {"report": state["report"], "technical": state["tech"], "system": state["system_tech"],
                        "technical_expires_at": state["tech_expires"], "ttl_days": ttl_days,
                        "ttl_choices": TTL_CHOICES, "actionable": list(state["actionable"].keys()),
                        "revealable": list(state["revealable"].keys()),
                        "system_items": list(state["system_items"].keys()), "brew_ready": list(state["brew_ids"]), "reinstall_ready": list(state["reinstall"].keys()),
                        "admin_network": state["admin_network"], "app_path": os.environ.get("MAC_HEALTH_APP"),
                        "full_disk_access": access, "admin_last_used": admin_used, "fresh_scan": state["scanned_at"] is not None,
                        "sealed_storage": bool(PAYLOAD and PAYLOAD.get("data_key")), "key_changed": state["key_changed"]}
                body = to_json(data).encode("utf-8")
            return self.send_body(200, body)
        if path == "/api/history":
            return self.send_json({"history": read_jsonl(HISTORY_FILE), "retention_days": HISTORY_RETENTION_DAYS})
        if path == "/api/job":
            with state_lock:
                data = dict(state["job"])
            return self.send_json(data)
        self.send_json({"error": "Not found."}, 404)

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length < 0 or length > 2 * 1024 * 1024:
                return None
            return json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, RecursionError):
            return None

    def do_POST(self):
        if not self.allowed():
            return self.send_json({"error": "Not allowed."}, 403)
        body = self.read_body()
        if not isinstance(body, dict):
            return self.send_json({"error": "Invalid request."}, 400)
        if self.path == "/api/scan":
            with state_lock:
                if state["scanning"]:
                    return self.send_json({"started": False})
                if state["acting"]:
                    return self.send_json({"error": "Wait for the current action to finish."}, 409)
                state.update(scanning=True, stage="Starting", percent=1, error=None)
            threading.Thread(target=do_scan, daemon=True).start()
            return self.send_json({"started": True})
        if self.path == "/api/trash":
            ids = body.get("ids")
            if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
                return self.send_json({"error": "Nothing selected."}, 400)
            return self.exclusive(trash_items, ids, body.get("confirm_personal") is True)
        if self.path == "/api/reveal":
            with state_lock:
                path = state["revealable"].get(str(body.get("id")))
            if not path or not os.path.exists(path):
                return self.send_json({"error": "This item is no longer there. Scan again."}, 404)
            scanners.run(["/usr/bin/open", "-R", path], timeout=10)
            return self.send_json({"ok": True})
        if self.path == "/api/open-settings":
            url = SETTINGS_PANES.get(str(body.get("pane")))
            if not url:
                return self.send_json({"error": "Unknown settings page."}, 400)
            scanners.run(["/usr/bin/open", url], timeout=10)
            return self.send_json({"ok": True})
        if self.path == "/api/reveal-app":
            app_path = os.environ.get("MAC_HEALTH_APP")
            if app_path:
                scanners.run(["/usr/bin/open", "-R", app_path], timeout=10)
            return self.send_json({"ok": True})
        if self.path == "/api/remove-system":
            return self.exclusive(remove_system_item, str(body.get("id")))
        if self.path == "/api/firewall-on":
            return self.exclusive(turn_on_firewall)
        if self.path == "/api/admin-network":
            return self.exclusive(admin_network_check)
        if self.path == "/api/brew-upgrade":
            with state_lock:
                old = not state["scanned_at"] or time.time() - state["scanned_at"] > SCAN_VALID_SECONDS
                if old or not state["brew_ids"]:  # saved results stay read-only until a new scan
                    return self.send_json({"error": "Scan again, then retry."}, 409)
                if state["job"]["running"]:
                    return self.send_json({"error": "An update is already running."}, 409)
                if state["scanning"] or state["acting"]:
                    return self.send_json({"error": "Wait for the scan or current action to finish."}, 409)
                state["acting"] = True  # released when the update finishes
                state["job"] = {"name": "brew", "running": True, "log": "", "ok": None, "summary": None}
            threading.Thread(target=run_brew_job, daemon=True).start()
            return self.send_json({"started": True})
        if self.path == "/api/brew-remove":
            return self.exclusive(brew_remove_in_terminal, str(body.get("id")))
        if self.path == "/api/brew-reinstall":
            return self.exclusive(brew_reinstall_in_terminal, str(body.get("id")))
        if self.path == "/api/brew-terminal":
            return self.exclusive(brew_finish_in_terminal)
        if self.path == "/api/settings":
            days = body.get("technical_ttl_days")
            if days not in TTL_CHOICES:
                return self.send_json({"error": "Invalid choice."}, 400)
            set_setting("technical_ttl_days", days)
            # Apply the new limit to the summary already stored.
            payload = None
            with state_lock:
                report = state["report"]
                if state["tech_expires"] and report:
                    state["tech_expires"] = report["generated_at"] + days * DAY
                    payload = {"expires_at": state["tech_expires"], "items": state["tech"], "system": state["system_tech"]}
                    stamp = int(report["generated_at"])
            if payload:
                write_sealed(os.path.join(TECH_DIR, "%d.json" % stamp), payload, "technical")
                purge_expired()
            return self.send_json({"ok": True})
        if self.path == "/api/technical/delete":
            delete_all_technical()
            return self.send_json({"ok": True})
        self.send_json({"error": "Not found."}, 404)


def housekeeping():
    while True:
        time.sleep(600)
        try:
            purge_expired()
        except Exception:
            pass


def exit_when_app_closes():
    sys.stdin.buffer.read()
    os._exit(0)


def main():
    global TOKEN, PORT, INDEX_HTML
    if PAYLOAD:
        TOKEN = PAYLOAD["token"]
        INDEX_HTML = PAYLOAD["files"]["index.html"].encode("utf-8")
    else:
        TOKEN = sys.stdin.buffer.readline().decode("utf-8", "replace").strip()
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ui", "index.html"), "rb") as handle:
            INDEX_HTML = handle.read()
    if len(TOKEN) < 32:
        print("Open Mac Health.app to start Mac Health.", file=sys.stderr)
        sys.exit(1)
    os.umask(0o077)
    secure_data_folders()
    os.nice(10)  # scans run behind whatever you're doing
    try:
        os.remove(os.path.join(DATA_DIR, "server.json"))  # from older versions, which stored the token
    except OSError:
        pass
    try:
        scanners.clear_leftover_jobs()
        remove_unsealed_results()
        purge_expired()
        load_saved()
    except Exception:  # damaged saved data must never stop the app from opening
        state["report"] = None
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    PORT = server.server_address[1]
    threading.Thread(target=housekeeping, daemon=True).start()
    threading.Thread(target=exit_when_app_closes, daemon=True).start()
    print("PORT %d" % PORT, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
