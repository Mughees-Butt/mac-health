"""Read-only system scanners for Mac Health. Nothing in this file changes the system."""
import hashlib
import json
import os
import plistlib
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HOME = os.path.expanduser("~")
LIB = os.path.join(HOME, "Library")
DAY = 86400
MB = 1024 ** 2
GB = 1024 ** 3

SIZE_LARGE_FILE = 500 * MB
SIZE_DUPLICATE_MIN = 20 * MB
SIZE_CACHE_MIN = 50 * MB
SIZE_LOG_MIN = 20 * MB
WALK_BUDGET_SECONDS = 180
HASH_BUDGET_SECONDS = 120

PACKAGE_EXTS = (".app", ".photoslibrary", ".musiclibrary", ".fcpbundle", ".tvlibrary", ".imovielibrary", ".logicx", ".band")
SKIP_WALK_DIRS = {".Trash", ".git"}
SKIP_HOME_DIRS = {"Library", "Applications"}  # only in the home folder itself: a project can have its own "Library"
DNS_ID = re.compile(r"^(com|org|net|io|ai|co|de|app|dev|me|us|uk|jp|cn|ru|fr|tv|info)\.[\w-]+\.", re.I)
SUSPICIOUS_DIRS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/", os.path.join(HOME, "Downloads") + "/")
SCRIPT_RUNNERS = {"bash", "sh", "zsh", "python", "python3", "perl", "ruby", "osascript", "curl", "node"}
# Plain-named Application Support folders that macOS or common tools own.
KNOWN_SUPPORT_NAMES = {
    "addressbook", "callhistorydb", "callhistorytransactions", "cloudDocs".lower(), "crashreporter", "dock",
    "dmd", "familycircle", "fileprovider", "icdd", "icloud", "icloudbackup", "knowledge", "mobilesync",
    "networkserviceproxy", "quicklook", "syncservices", "ubiquity", "videoconversionservice", "accounts",
    "animoji", "contacts", "calendar", "maps", "photos", "safari", "siri", "stickers", "tipsd", "wallpaper",
    "google", "microsoft", "adobe", "firefox", "code", "claude", "cursor", "cloudkit", "appstore", "default",
    "containers", "caches", "plugins", "shared", "assistant", "languagemodeling", "homeenergyd", "replayd",
    "differentialprivacy", "app store", "bluetooth", "clouddocs", "corespotlight", "duetexpertcenter", "icloudmailagent",
    "motion", "networkquality", "podcasts", "news", "stocks", "weather", "reminders", "notes", "voicememos", "findmy",
}


def run(cmd, timeout=30, env=None, merge_stderr=True):
    """Run a command with no shell. Returns (exit code, output); never raises. Exit code -1 means it didn't finish."""
    try:
        full_env = dict(os.environ, **env) if env else None
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL, timeout=timeout,
                                env=full_env, stdin=subprocess.DEVNULL)
        return result.returncode, result.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return -1, ""


# Programs your account can overwrite, like brew, must never run inside this app's process tree, where they
# would inherit Full Disk Access. launchd starts them as a separate job that doesn't have it.
OUTSIDE_JOB = """
if [ -e "$1/done" ]; then exec /bin/sleep 3600; fi
d=$1; merge=$2; shift 2
if [ "$merge" = 1 ]; then "$@" >"$d/out" 2>&1 </dev/null; else "$@" >"$d/out" 2>/dev/null </dev/null; fi
echo $? >"$d/rc"; : >"$d/done"
exec /bin/sleep 3600
"""
outside_verified = False
JOB_PREFIX = "local.machealth.job."
JOB_OUTPUT_LIMIT = 32 * MB


def spawn_outside(cmd, timeout, env, merge, on_output):
    """Returns (exit code, output). Exit code -1 means it didn't finish. launchd restarts a submitted job
    when it exits, so the job waits after running once until it's removed here."""
    folder = tempfile.mkdtemp(prefix="machealth-job-")
    label = JOB_PREFIX + secrets.token_hex(8)
    settings = ["%s=%s" % pair for pair in sorted((env or {}).items())]
    code = -1
    output = b""
    folder_fd = None
    try:
        folder_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        started = run(["/bin/launchctl", "submit", "-l", label, "--", "/bin/sh", "-c", OUTSIDE_JOB, "sh", folder, "1" if merge else "0",
                       "/usr/bin/env", "-i", "HOME=%s" % HOME, "LANG=en_US.UTF-8"] + settings + list(cmd), timeout=10)
        if started[0] != 0:
            return -1, ""
        deadline = time.time() + timeout
        while True:
            done = read_job_file(folder_fd, "done") is not None
            fresh = (read_job_file(folder_fd, "out") or b"")[len(output):]
            if fresh:
                output += fresh
                if on_output:
                    on_output(fresh.decode("utf-8", "replace"))
            if done:
                code = int((read_job_file(folder_fd, "rc") or b"-1").strip() or -1)
                break
            if time.time() > deadline:
                break
            time.sleep(0.1)
    except (OSError, ValueError):
        code = -1
    finally:
        if folder_fd is not None:
            os.close(folder_fd)
        run(["/bin/launchctl", "remove", label], timeout=10)
        shutil.rmtree(folder, ignore_errors=True)
    return code, output.decode("utf-8", "replace")


def read_job_file(folder_fd, name):
    """The job could be a hostile program, and this process has Full Disk Access. So only a real, unshared file
    it owns is ever read: a link or hard link here could point into a protected folder."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder_fd)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            return None
        return os.read(fd, JOB_OUTPUT_LIMIT)
    except OSError:
        return None
    finally:
        os.close(fd)


def clear_leftover_jobs():
    """Quitting mid-job can leave one waiting. Clear them when the app next opens."""
    _, listed = run(["/bin/launchctl", "list"], timeout=10)
    for label in re.findall(r"(%s[0-9a-f]+)\s*$" % re.escape(JOB_PREFIX), listed, re.M):
        run(["/bin/launchctl", "remove", label], timeout=10)
    root = tempfile.gettempdir()
    for name in os.listdir(root):
        path = os.path.join(root, name)
        if name.startswith("machealth-job-") and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)


def outside_is_isolated():
    """Proves a separate job lacks Full Disk Access, by having one fail to read a folder this app can read."""
    global outside_verified
    if outside_verified:
        return True
    access = full_disk_access()
    if access is False:
        return True  # nothing to inherit, and checked again next time in case access is granted
    folders = [f for f in (os.path.join(LIB, "Safari"), os.path.join(LIB, "Cookies")) if os.path.lexists(f)]
    if access is not True or not folders:
        return False
    for folder in folders:
        code, out = spawn_outside(["/bin/ls", folder], 15, None, True, None)
        if code != 1 or "Operation not permitted" not in out:
            return False
    outside_verified = True
    return True


def run_outside(cmd, timeout=60, env=None, merge=False, on_output=None):
    """Runs a program your account can overwrite, without this app's access. Refuses if that can't be proven."""
    if not outside_is_isolated():
        return -1, ""
    return spawn_outside(cmd, timeout, env, merge, on_output)


def du_bytes(path, timeout=45):
    code, out = run(["/usr/bin/du", "-sk", path], timeout=timeout)
    for line in out.splitlines():
        match = re.match(r"^(\d+)\s", line)
        if match:
            return int(match.group(1)) * 1024
    return None


def fmt_size(num):
    if num is None:
        return "unknown size"
    value = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return "%.0f %s" % (value, unit) if unit in ("B", "KB") else "%.1f %s" % (value, unit)
        value /= 1024
    return "%.1f TB" % value


def age_days(path):
    try:
        return (time.time() - os.lstat(path).st_mtime) / DAY
    except OSError:
        return None


def newest_change_age(path, skip=(), budget=3.0, limit=50000):
    """Days since anything inside changed. A folder's own date misses edits to the files within it.
    Returns 0 if the search runs out of budget, because an unfinished search can't call something abandoned."""
    started = time.time()
    try:
        info = os.lstat(path)
    except OSError:
        return None
    newest = info.st_mtime
    stack = [path] if stat.S_ISDIR(info.st_mode) else []
    seen = 0
    while stack:
        try:
            entries = list(os.scandir(stack.pop()))
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > limit or time.time() - started > budget:
                return 0
            try:
                details = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            newest = max(newest, details.st_mtime)
            if stat.S_ISDIR(details.st_mode) and entry.name not in skip:
                stack.append(entry.path)
    return (time.time() - newest) / DAY


def stamp_of(info):
    """Identifies the exact file seen, so an edited or replaced one isn't acted on with old information."""
    return [info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino]


def full_hash(path):
    hasher = hashlib.blake2b(digest_size=20)
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(4 * MB), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def real_folder(path):
    """A link here could make your own files look like cache or leftovers."""
    return not os.path.islink(path) and os.path.realpath(path) == path


def pretty_path(path):
    return path.replace(HOME, "~", 1) if path.startswith(HOME) else path


def norm(text):
    return re.sub(r"[^a-z0-9]", "", text.lower())


def item(category, title, plain, severity="info", confidence=None, size=None, paths=None, trashable=False,
         action=None, technical=None, group=None, key=None, fix=None):
    paths = paths or []
    seed = "|".join([category, key or title] + paths)
    return {
        "id": hashlib.sha1(seed.encode("utf-8", "replace")).hexdigest()[:16],
        "category": category, "title": title, "plain": plain, "severity": severity,
        "confidence": confidence, "size": size, "trashable": bool(trashable and paths), "action": action,
        "group": group, "paths": paths, "technical": technical or {}, "fix": fix,
    }


# ---------- Health ----------

def _sysctl(name):
    code, out = run(["/usr/sbin/sysctl", "-n", name], timeout=5)
    return out.strip() if code == 0 else ""


CPU_EXPLAIN = {
    "mds": "Spotlight is indexing your files, which is normal after a macOS update or lots of file changes",
    "mds_stores": "Spotlight is indexing your files, which is normal after a macOS update or lots of file changes",
    "mdworker_shared": "Spotlight is indexing your files",
    "syspolicyd": "macOS is checking app signatures",
    "WindowServer": "macOS is drawing what's on your screen",
    "kernel_task": "macOS is managing temperature or hardware",
    "photoanalysisd": "Photos is analysing your library",
    "backupd": "Time Machine is backing up",
}
RECENT_SCAN_SECONDS = 900


def check_software_updates():
    code, out = run(["/usr/sbin/softwareupdate", "-l"], timeout=90)
    return re.findall(r"^\s*\* Label: (.+)$", out, re.M) if code == 0 else None


def scan_health(check_updates=True, last_scan=None):
    cards, raw = {}, {}

    usage = shutil.disk_usage("/System/Volumes/Data")
    used_pct = round(usage.used / usage.total * 100, 1)
    cards["disk"] = {"total": usage.total, "used": usage.used, "free": usage.free, "used_pct": used_pct}

    _, pressure = run(["/usr/bin/memory_pressure", "-Q"], timeout=10)
    match = re.search(r"free percentage:\s*(\d+)%", pressure)
    swap_match = re.search(r"used = ([\d.]+)M", _sysctl("vm.swapusage"))
    cards["memory"] = {
        "total": int(_sysctl("hw.memsize") or 0),
        "free_pct": int(match.group(1)) if match else None,
        "swap_used": int(float(swap_match.group(1)) * MB) if swap_match else 0,
    }

    cores = int(_sysctl("hw.ncpu") or 1)
    load1, load5, load15 = os.getloadavg()
    # Sampled before the scan's heavy work. Load averages would also count earlier scans.
    _, top_sample = run(["/usr/bin/top", "-l", "4", "-n", "0", "-s", "1"], timeout=20)
    idle = [float(v) for v in re.findall(r"([\d.]+)% idle", top_sample)[1:]]
    busy = round(100 - sum(idle) / len(idle)) if idle else None
    _, top_out = run(["/bin/ps", "-Aceo", "pid=,pcpu=,pmem=,comm=", "-r"], timeout=10)
    top = []
    for line in top_out.splitlines()[:8]:
        parts = line.split(None, 3)
        if len(parts) == 4:
            top.append({"pid": parts[0], "cpu": float(parts[1]), "mem": float(parts[2]), "name": parts[3]})
    busiest = top[0]["name"] if top else None
    cards["cpu"] = {"cores": cores, "busy_pct": busy, "load1": round(load1, 2), "load5": round(load5, 2), "load15": round(load15, 2),
                    "recent_scan": bool(last_scan and time.time() - last_scan < RECENT_SCAN_SECONDS),
                    "busiest": busiest, "explanation": CPU_EXPLAIN.get(busiest), "top": top}

    boot = re.search(r"sec = (\d+)", _sysctl("kern.boottime"))
    cards["uptime_days"] = round((time.time() - int(boot.group(1))) / DAY, 1) if boot else None

    battery = None
    _, power = run(["/usr/sbin/system_profiler", "SPPowerDataType", "-json"], timeout=20)
    try:
        for entry in json.loads(power).get("SPPowerDataType", []):
            info = entry.get("sppower_battery_health_info")
            if info:
                charge = entry.get("sppower_battery_charge_info", {})
                battery = {"condition": info.get("sppower_battery_health"),
                           "max_capacity": info.get("sppower_battery_health_maximum_capacity"),
                           "cycles": info.get("sppower_battery_cycle_count"),
                           "charge_pct": charge.get("sppower_battery_state_of_charge")}
    except ValueError:
        pass
    cards["battery"] = battery

    def state(cmd, on_word, off_word):
        _, out = run(cmd, timeout=10)
        low = out.lower()
        raw[" ".join(cmd)] = out.strip()
        if on_word in low:
            return True
        return False if off_word in low else None

    cards["security"] = {
        "filevault": state(["/usr/bin/fdesetup", "status"], "filevault is on", "filevault is off"),
        "gatekeeper": state(["/usr/sbin/spctl", "--status"], "assessments enabled", "assessments disabled"),
        "sip": state(["/usr/bin/csrutil", "status"], "enabled", "disabled"),
        "firewall": state(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], "is enabled", "is disabled"),
    }

    cards["updates"] = check_software_updates() if check_updates else None

    code, version = run(["/usr/bin/sw_vers", "-productVersion"], timeout=5)
    cards["macos"] = version.strip()
    return cards, raw


# ---------- Apps ----------

def find_apps(coverage):
    found = set()
    for root in ("/Applications", os.path.join(HOME, "Applications"), "/System/Applications"):
        for current, dirs, _ in os.walk(root):
            for name in list(dirs):
                if name.endswith(".app"):
                    found.add(os.path.join(current, name))
                    dirs.remove(name)
    code, out = run(["/usr/bin/mdfind", "kMDItemContentType == 'com.apple.application-bundle'"], timeout=30)
    if code != 0:
        coverage.append({"area": "App list", "status": "partial", "fix": "rescan", "note": "Spotlight didn't answer, so apps outside Applications may look uninstalled."})
    for line in out.splitlines():
        if line.endswith(".app") and ".app/" not in line and os.path.isdir(line):
            found.add(line)
    # Helpers bundled inside a project's dependencies aren't installed apps.
    return sorted(p for p in found if "/node_modules/" not in p and "/Library/Application Scripts/" not in p)


def app_info(path):
    info = {"path": path, "name": os.path.basename(path)[:-4], "bundle_id": None, "version": None}
    try:
        with open(os.path.join(path, "Contents", "Info.plist"), "rb") as handle:
            data = plistlib.load(handle)
        # Values come from the app's own files, so don't trust their types.
        info["bundle_id"] = data["CFBundleIdentifier"] if isinstance(data.get("CFBundleIdentifier"), str) else None
        info["version"] = data["CFBundleShortVersionString"] if isinstance(data.get("CFBundleShortVersionString"), str) else None
    except (OSError, ValueError, plistlib.InvalidFileException, Exception):
        pass
    return info


def signature_info(path):
    """Summarise who signed a file or app and whether Gatekeeper accepts it."""
    _, out = run(["/usr/bin/codesign", "-dv", "--verbose=2", path], timeout=25)
    authority = re.search(r"^Authority=(.+)$", out, re.M)
    team = re.search(r"^TeamIdentifier=(.+)$", out, re.M)
    if "not signed at all" in out:
        status = "unsigned"
    elif "Signature=adhoc" in out:
        status = "adhoc"
    elif authority:
        status = "signed"
    else:
        status = "unknown"
    return {"status": status, "authority": authority.group(1) if authority else None,
            "team": team.group(1) if team else None}


def gatekeeper_verdict(path):
    """accepted is True or False on a clear verdict. reason explains a damaged bundle."""
    # Read the verdict only from where spctl puts it, right after the path, so a name containing
    # ": accepted" can't stand in for it. The exit code must agree.
    code, out = run(["/usr/sbin/spctl", "-a", "-vv", "-t", "exec", path], timeout=45)
    lines = out.strip().splitlines()
    first = lines[0] if lines else ""
    verdict = first[len(path) + 2:].strip() if first.startswith(path + ": ") else ""
    source = next((line[len("source="):].strip() for line in lines[1:] if line.startswith("source=")), None)
    if verdict == "accepted" and code == 0:
        return {"accepted": True, "source": source}
    if verdict == "rejected" and code != 0:
        return {"accepted": False, "source": source}
    return {"accepted": None, "source": None, "reason": verdict or None}


def last_used_days(path):
    _, out = run(["/usr/bin/mdls", "-raw", "-name", "kMDItemLastUsedDate", path], timeout=10)
    match = re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", out.strip())
    if not match:
        return None
    return (time.time() - time.mktime(time.strptime(match.group(1), "%Y-%m-%d %H:%M:%S"))) / DAY


def launcher_target(path):
    """Some tools build a small wrapper app whose program is a link to a signed tool elsewhere.
    macOS can't validate the wrapper as a bundle, which isn't damage. Returns the real program, or None."""
    try:
        with open(os.path.join(path, "Contents", "Info.plist"), "rb") as handle:
            program = os.path.join(path, "Contents", "MacOS", plistlib.load(handle)["CFBundleExecutable"])
    except Exception:
        return None
    if not os.path.islink(program):
        return None
    target = os.path.realpath(program)
    return target if os.path.isfile(target) and not target.startswith(os.path.realpath(path) + "/") else None


def cask_for_app(path):
    """The Homebrew package that provides exactly this app, or None."""
    brew = shutil.which("brew", path="/opt/homebrew/bin:/usr/local/bin")
    bundle = os.path.basename(path)
    token = bundle[:-4].lower().replace(" ", "-")
    if not brew or not re.fullmatch(r"[a-z0-9@._+-]+", token):
        return None
    data = brew_json(brew, ["info", "--json=v2", "--cask", token]) or {}
    for cask in data.get("casks", []):
        names = [str(a) for art in cask.get("artifacts", []) if isinstance(art, dict) for a in art.get("app", [])[:1]]
        if bundle in names and not cask.get("disabled"):
            return {"token": cask["token"], "installed": bool(cask.get("installed"))}
    return None


def scan_apps(apps, coverage):
    results = []
    third_party = [a for a in apps if not a["path"].startswith("/System/")
                   and not (a["bundle_id"] or "").startswith(("com.apple.", "local.machealth."))]

    def inspect(app):
        return app, signature_info(app["path"]), gatekeeper_verdict(app["path"]), last_used_days(app["path"])

    with ThreadPoolExecutor(max_workers=3) as pool:
        inspected = list(pool.map(inspect, third_party))
    inconclusive = [a["name"] for a, sig, gate, _ in inspected if sig["status"] == "unknown" or (gate["accepted"] is None and not gate.get("reason"))]
    if inconclusive:
        coverage.append({"area": "Gatekeeper check", "status": "partial",
                         "fix": "rescan",
                         "note": "macOS was too busy to answer for: %s. Scan again when your Mac is quieter." % ", ".join(inconclusive[:8])})

    usual = ("/Applications/", os.path.join(HOME, "Applications") + "/")
    # Build products and package-manager copies are expected outside /Applications.
    expected = ("/Library/", "/opt/homebrew/", "/usr/local/", os.path.join(HOME, "Library") + "/")
    unused = []
    for app, sig, gate, used in inspected:
        path = app["path"]
        tech = {"path": path, "bundle_id": app["bundle_id"], "version": app["version"], "signature": sig,
                "gatekeeper": gate, "last_used_days": round(used) if used is not None else None}
        trash_ok = path.startswith(usual)
        if sig["status"] == "unsigned":
            results.append(item("alerts", "%s has no developer signature" % app["name"],
                                "Nothing confirms who made this app or that it hasn't been changed. If you don't recognise it, remove it.",
                                "high", "high", paths=[path], trashable=trash_ok, technical=tech,
                                action="If you installed it deliberately, re-download it from the developer's site and check whether it's signed."))
        elif sig["status"] == "adhoc" and "/Chrome Apps.localized/" not in path:
            results.append(item("alerts", "%s has only a local signature" % app["name"],
                                "It isn't tied to an identified developer. This is normal for apps you built or some open-source tools, but unusual otherwise.",
                                "medium", "medium", paths=[path], trashable=trash_ok, technical=tech,
                                action="Keep it if you know where it came from. Otherwise, remove it."))
        elif gate["accepted"] is False and sig["status"] == "signed":
            results.append(item("alerts", "%s was not approved by Gatekeeper" % app["name"],
                                "It's signed, but macOS's check didn't accept it. It may not be notarized by Apple, or it may have been modified or revoked.",
                                "medium", "medium", paths=[path], trashable=trash_ok, technical=tech,
                                action="Update it from the developer's official site, then scan again."))
        elif gate.get("reason") and sig["status"] == "signed":
            target = launcher_target(path)
            if not (target and run(["/usr/bin/codesign", "--verify", "--strict", target], timeout=25)[0] == 0):
                cask = cask_for_app(path)
                fix = None
                action = "Reinstall it from the developer's official site. That usually clears this."
                if cask:
                    tech["reinstall"] = cask
                    action = "Homebrew has a fresh copy. Your settings are kept. Quit the app first, and scan again afterwards."
                    fix = {"kind": "brew_reinstall", "label": "Reinstall in Terminal",
                           "detail": "Terminal opens with one command that replaces %s with Homebrew's latest copy. It may ask for your password." % app["name"]}
                results.append(item("alerts", "%s has a damaged signature" % app["name"],
                                    "It was signed by %s, but macOS says the app's contents no longer match that signature's expected structure. Common causes are a damaged update or a modified app. It doesn't prove malware." % (sig["authority"] or "a developer"),
                                    "low", "high", paths=[path], trashable=trash_ok, technical=tech, action=action, fix=fix))
        if not path.startswith(usual) and not path.startswith(expected) and "/DerivedData/" not in path:
            results.append(item("alerts", "%s is outside the Applications folder" % app["name"],
                                "It's an app stored somewhere unusual: %s. It may just be a download you never moved or deleted." % pretty_path(os.path.dirname(path)),
                                "low", "medium", paths=[path], trashable=path.startswith(HOME), technical=tech,
                                action="Move it to Applications if you use it. Remove it if you don't.", key="outside"))
        if used is not None and used > 365 and path.startswith(usual):
            unused.append((app, used, tech))

    for app, used, tech in sorted(unused, key=lambda row: -row[1])[:25]:
        size = du_bytes(app["path"])
        results.append(item("clutter", "%s (not opened in %d months)" % (app["name"], used / 30),
                            "You haven't opened this app for over a year. Uninstalling it would recover %s, and any data it left behind would show as leftovers on a later scan." % fmt_size(size),
                            "info", "review", size=size, paths=[app["path"]], trashable=True, technical=tech,
                            action="Remove it only if you don't need it. Check that you can reinstall it first."))
    return results, len(third_party)


def launchd_state(label):
    """What launchd knows about a job: is it loaded, how often it ran, and how it last ended."""
    for domain in ("system/%s" % label, "gui/%d/%s" % (os.getuid(), label)):
        code, out = run(["/bin/launchctl", "print", domain], timeout=8)
        if code == 0:
            state = re.search(r"^\s*state = (.+)$", out, re.M)
            runs = re.search(r"^\s*runs = (\d+)$", out, re.M)
            exit_code = re.search(r"^\s*last exit code = (.+)$", out, re.M)
            return {"loaded": True, "state": state.group(1) if state else None, "runs": int(runs.group(1)) if runs else 0,
                    "last_exit": exit_code.group(1) if exit_code else None}
    return {"loaded": False}


def scan_launch_items(apps):
    results = []
    installed_bundles = {os.path.basename(a["path"]).lower() for a in apps}
    vendors = {vendor_of(a["bundle_id"]) for a in apps if a["bundle_id"]}
    orphans, helper_keys = {}, set()
    roots = [(os.path.join(LIB, "LaunchAgents"), True), ("/Library/LaunchAgents", False), ("/Library/LaunchDaemons", False)]
    for root, user_owned in roots:
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            if not name.endswith(".plist"):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as handle:
                    data = plistlib.load(handle)
            except Exception:
                results.append(item("alerts", "Unreadable startup item: %s" % name,
                                    "This startup file can't be read, so it may be damaged.", "low", "medium",
                                    paths=[path], trashable=user_owned, technical={"path": path}))
                continue
            args = data.get("ProgramArguments") if isinstance(data, dict) else None
            args = args if isinstance(args, list) else []
            program = (data.get("Program") or (args[0] if args else None)) if isinstance(data, dict) else 0
            label = data.get("Label", name[:-6]) if isinstance(data, dict) else name[:-6]
            # A malformed file must not stop the files after it from being checked.
            if (program and not isinstance(program, str)) or not isinstance(label, str) or not isinstance(data, dict):
                results.append(item("alerts", "Malformed startup item: %s" % name,
                                    "This startup file doesn't have the structure macOS expects, which is unusual, so check that you recognise it.", "medium", "medium",
                                    paths=[path], trashable=user_owned, technical={"path": path}))
                continue
            if not program:
                # Nothing to diagnose: macOS or the vendor resolves these in its own way, so stay out.
                continue
            expanded = os.path.expanduser(program)
            # launchd finds bare names on its own path, and an unplugged drive doesn't mean an app is gone.
            if expanded.startswith("/") and not expanded.startswith("/Volumes/") and not os.path.exists(expanded):
                bundle = re.search(r"/([^/]+\.app)/", program + "/")
                app_name = bundle.group(1) if bundle else None
                if app_name and app_name.lower() in installed_bundles:
                    continue  # the app moved but still exists, so it isn't a leftover
                key = app_name or label
                orphans.setdefault(key, []).append({"path": path, "label": label, "program": program,
                                                    "user_owned": user_owned, "launchd": launchd_state(label)})
                continue
            owners = data.get("AssociatedBundleIdentifiers") or []
            owners = [owners] if isinstance(owners, str) else owners
            owned_by_installed = any(isinstance(o, str) and vendor_of(o) in vendors for o in owners) if isinstance(owners, list) else False
            # Only a root-owned file can claim a root helper. Otherwise any program could aim the admin prompt at one.
            if not user_owned and program.startswith("/Library/PrivilegedHelperTools/") and vendor_of(label) not in vendors and not owned_by_installed:
                state = launchd_state(label)
                key = label.split(".")[1] if "." in label else label
                helper_keys.add(key)  # a vendor match is weaker evidence than a missing program
                orphans.setdefault(key, []).extend([
                    {"path": path, "label": label, "program": program, "user_owned": False, "launchd": state},
                    {"path": program, "label": None, "program": program, "user_owned": False, "launchd": state}])
                continue
            system_program = program.startswith(("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/System/"))
            sig = None if system_program or not expanded.startswith("/") else signature_info(expanded)
            tech = {"path": path, "label": label, "program": program, "arguments": args[:8], "signature": sig,
                    "run_at_load": data.get("RunAtLoad"), "keep_alive": data.get("KeepAlive")}
            hint = None if user_owned else "This is a system-level file, so use the developer's uninstaller if you no longer want it."
            base = os.path.basename(program)
            if program.startswith(SUSPICIOUS_DIRS) or "/." in program:
                results.append(item("alerts", "Startup item runs from an unusual location: %s" % label,
                                    "It starts automatically from %s. Legitimate software rarely runs from there, so check that you recognise it." % pretty_path(os.path.dirname(program)),
                                    "high", "medium", paths=[path], trashable=user_owned, technical=tech,
                                    action=hint or "Search for the name online. Remove it if you can't identify it."))
            elif base in SCRIPT_RUNNERS:
                results.append(item("alerts", "Startup item runs a script: %s" % label,
                                    "A script runs automatically through %s. Many tools do this, but malware does too, so it's worth checking that you recognise it." % base,
                                    "medium", "low", paths=[path], trashable=user_owned, technical=tech,
                                    action=hint or "Open the technical details to see the command it runs."))
            elif sig and sig["status"] == "unsigned":
                results.append(item("alerts", "Startup item with no developer signature: %s" % label,
                                    "A program that starts automatically doesn't have a developer signature. Homebrew and other open-source tools often look like this.",
                                    "medium", "low", paths=[path], trashable=user_owned, technical=tech,
                                    action=hint or "Keep it if you recognise the tool. Otherwise, remove it."))

    for key, entries in sorted(orphans.items()):
        name = key[:-4] if key.endswith(".app") else key
        count = len(entries)
        running = any(e["launchd"].get("state") == "running" for e in entries)
        plain = "No matching app is installed, but %d startup file%s remain%s. %s." % (
            count, "" if count == 1 else "s", "s" if count == 1 else "", "One is running" if running else "None are running")
        system = [e for e in entries if not e["user_owned"]]
        user = [e["path"] for e in entries if e["user_owned"]]
        fix = None
        if system:
            fix = {"kind": "admin_remove", "label": "Remove startup file%s" % ("" if len(system) == 1 else "s"),
                   "detail": "macOS will ask for your password because these are system-level files."}
        results.append(item("leftovers", "%s: %d orphaned startup file%s" % (name, count, "" if count == 1 else "s"), plain,
                            "medium", "likely" if key in helper_keys else "very likely", paths=user, trashable=bool(user) and not system, key="orphan-" + key,
                            action="Reinstalling %s creates these again if needed." % name,
                            fix=fix, technical={"entries": entries, "system_items": [{"path": e["path"], "label": e["label"]} for e in system],
                                                    "user_items": [{"path": e["path"], "label": e["label"]} for e in entries if e["user_owned"]]}))
    return results


KNOWN_VENDORS = {"microsoft": "Microsoft", "google": "Google", "grammarly": "Grammarly", "spotify": "Spotify", "zoom": "Zoom",
                 "docker": "Docker", "adobe": "Adobe", "apple": "Apple", "anthropic": "Anthropic", "openai": "OpenAI", "dropbox": "Dropbox"}


def describe_startup(name, identifier, kind, developer):
    """Turn macOS's identifier into who made this and what it's for."""
    parts = re.sub(r"^\d+\.", "", identifier or "").split(".")
    token = parts[1].lower() if len(parts) > 1 else ""
    vendor = KNOWN_VENDORS.get(token) or developer or (token.capitalize() if token else "an unknown developer")
    low = name.lower() + " " + (identifier or "").lower()
    if "uninstall" in low:
        purpose = "Helps remove %s software" % vendor
    elif "update" in low:
        purpose = "Keeps %s software up to date" % vendor
    elif "report" in low:
        purpose = "Sends reports to %s" % vendor
    elif kind.startswith("app"):
        purpose = "%s app, allowed to open or run on its own" % vendor
    elif kind.startswith("login item"):
        purpose = "Opens %s software when you log in" % vendor
    else:
        purpose = "Background helper for %s software" % vendor
    return vendor, purpose


def startup_behavior(file_path, name):
    """Read the startup file to say when this actually runs, which is what decides if it matters."""
    behavior = None
    try:
        with open(file_path, "rb") as handle:
            data = plistlib.load(handle)
    except Exception:
        return None
    interval = data.get("StartInterval")
    if data.get("KeepAlive") is True:
        behavior = "Always running, and restarts if it quits."
    elif data.get("WatchPaths"):
        watched = "your Applications folders" if any("Applications" in p for p in data["WatchPaths"]) else "certain files"
        behavior = "Sleeps until %s change, then runs briefly." % watched
    elif interval:
        behavior = "Runs every %s." % (("hour" if interval // 3600 == 1 else "%d hours" % (interval // 3600)) if interval >= 3600 else "%d minutes" % (interval // 60))
    elif data.get("StartCalendarInterval"):
        behavior = "Runs on a schedule."
    elif data.get("RunAtLoad"):
        behavior = "Runs when you log in."
    elif data.get("MachServices"):
        behavior = "Only runs when another app asks for it."
    return behavior


def scan_login_items():
    """Everything macOS has registered to start or run in the background for this user."""
    # This takes 20 seconds even on a quiet Mac, so allow for a busy one.
    _, out = run(["/usr/bin/sfltool", "dumpbtm"], timeout=120)
    results, seen = [], set()
    marker = "Records for UID %d " % os.getuid()
    start = out.find(marker)
    if start < 0:
        return None  # couldn't read the list, which isn't the same as an empty one
    # The current user's records can be repeated, so entries are de-duplicated below.
    next_block = re.search(r"Records for UID (?!%d )" % os.getuid(), out[start + 1:])
    block = out[start:start + 1 + next_block.start()] if next_block else out[start:]
    _, ps_out = run(["/bin/ps", "-Axo", "rss=,comm="], timeout=10)
    processes = []
    for line in ps_out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            processes.append((int(parts[0]) * 1024, parts[1]))
    home_alias = "/Users/%d/" % os.getuid()
    for entry in re.split(r"^\s*#\d+:\s*$", block, flags=re.M)[1:]:
        fields = dict((k.strip(), v.strip()) for k, v in re.findall(r"^\s*([A-Z][A-Za-z ]+): (.*)$", entry, re.M))
        kind = fields.get("Type", "")
        if not kind.startswith(("app", "login item", "legacy", "agent", "daemon", "curated")):
            continue
        identifier = fields.get("Identifier", "")
        name = fields.get("Name") or identifier
        if name == "(null)":
            name = identifier or "Unknown"
        # Different programs can share a name, so only the same identifier counts as a repeat.
        record = re.sub(r"^\d+\.", "", identifier) or name
        if record in seen:
            continue
        seen.add(record)
        enabled = "[enabled" in fields.get("Disposition", "")
        program = fields.get("Executable Path")
        if program in (None, "(null)"):
            program = None
        # macOS records your home folder as /Users/<uid>, and bundled items relative to their app.
        if program and program.startswith(home_alias):
            program = os.path.join(HOME, program[len(home_alias):])
        missing = bool(program and program.startswith("/") and not os.path.exists(program))
        developer = fields.get("Developer Name")
        developer = None if developer in (None, "(null)") else developer
        vendor, purpose = describe_startup(name, identifier, kind, developer)
        startup_file = fields.get("URL") or ""
        if startup_file.startswith(home_alias):
            startup_file = os.path.join(HOME, startup_file[len(home_alias):])
        behavior = startup_behavior(startup_file, name) if startup_file.startswith("/") else None
        low_name = name.lower()
        if "uninstall" in low_name:
            purpose = "Cleans up %s's files if you delete the app" % vendor
            advice = "Harmless. Leave it unless you're removing %s." % vendor
        elif "update" in low_name:
            advice = "Worth keeping while you use %s, for security updates." % vendor
        else:
            advice = None
        memory = None
        if program and program.startswith("/"):
            memory = sum(rss for rss, comm in processes if comm == program) or None
        if memory is None:
            memory = sum(rss for rss, comm in processes if os.path.basename(comm) == name) or None
        title = name
        if name == os.path.basename(name) and name.lower().startswith(("com.", "startup")):
            title = "%s %s" % (vendor, "background agent" if name.startswith("com.") else "startup helper")
        result = item("startup", title, purpose + ".", "info", key=identifier or name,
                      technical={"name": name, "type": kind, "identifier": identifier, "file": fields.get("URL"), "program": program})
        result.update(enabled=enabled, missing=missing, memory=memory, vendor=vendor, behavior=behavior, advice=advice)
        results.append(result)
    return sorted(results, key=lambda i: (not i["enabled"], i["missing"], i["title"].lower()))


def scan_audio_drivers(apps):
    """Audio drivers load whenever the Mac runs, so one left by an uninstalled app is still active."""
    results = []
    vendors = {vendor_of(a["bundle_id"]) for a in apps if a["bundle_id"]}
    root = "/Library/Audio/Plug-Ins/HAL"
    try:
        names = os.listdir(root)
    except OSError:
        return results
    for name in sorted(names):
        path = os.path.join(root, name)
        if not name.endswith(".driver"):
            continue
        try:
            with open(os.path.join(path, "Contents", "Info.plist"), "rb") as handle:
                bundle_id = plistlib.load(handle).get("CFBundleIdentifier", "")
        except Exception:
            continue
        if bundle_id and vendor_of(bundle_id) not in vendors and not bundle_id.startswith("com.apple."):
            results.append(item("leftovers", "%s audio driver" % name[:-7],
                                "Its app is gone, but macOS still loads this driver.",
                                "medium", "likely", key="driver-" + name,
                                action="Stops loading after a restart.",
                                fix={"kind": "admin_remove", "label": "Remove driver",
                                     "detail": "macOS will ask for your password because this is a system-level file."},
                                technical={"bundle_id": bundle_id, "system_items": [{"path": path, "label": None}]}))
    return results


# ---------- Leftovers ----------

def clean_support_name(name):
    for suffix in (".savedState", ".plist", ".binarycookies", ".sfl2", ".sfl3"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    name = re.sub(r"^group\.", "", name)
    name = re.sub(r"^[A-Z0-9]{10}\.", "", name)  # team ID prefix on group containers
    return name


def vendor_of(bundle_id):
    return ".".join(bundle_id.lower().split(".")[:2])


def can_modify(folder):
    """macOS can block changes to a folder even when file permissions allow them, so try it."""
    probe = os.path.join(folder, ".mac-health-probe-%d" % os.getpid())
    try:
        os.close(os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        os.remove(probe)
        return True
    except OSError:
        return False


def scan_leftovers(apps, coverage):
    installed = {a["bundle_id"].lower() for a in apps if a["bundle_id"]}
    vendors = {vendor_of(b) for b in installed}
    app_names = {norm(a["name"]) for a in apps}

    known_tools = set()
    for folder in ("/opt/homebrew/bin", "/opt/homebrew/Cellar", "/opt/homebrew/Caskroom", "/usr/local/bin",
                   os.path.join(HOME, ".local", "bin")):
        try:
            known_tools.update(norm(n) for n in os.listdir(folder))
        except OSError:
            pass
    try:
        known_tools.update(norm(n) for n in os.listdir(HOME) if n.startswith("."))
    except OSError:
        pass
    _, processes = run(["/bin/ps", "-Aco", "comm="], timeout=10)
    known_tools.update(norm(p) for p in processes.splitlines())
    known_tools.discard("")

    def matches_something(text):
        value = norm(text)
        if len(value) < 3:
            return True
        if value in known_tools or value in app_names:
            return True
        return any(len(a) >= 4 and (a in value or value in a) for a in app_names)

    locations = ["Application Support", "Caches", "Preferences", "Containers", "Group Containers",
                 "Saved Application State", "HTTPStorages", "WebKit", "Logs", "Cookies"]
    groups = {}
    for location in locations:
        root = os.path.join(LIB, location)
        if os.path.lexists(root) and not real_folder(root):
            coverage.append({"area": "~/Library/%s" % location, "status": "partial", "note": "It's a link to somewhere else, so it was skipped. Check that you set this up."})
            continue
        try:
            names = os.listdir(root)
        except OSError:
            coverage.append({"area": "~/Library/%s" % location, "status": "blocked",
                             "fix": "fda", "note": "macOS denied access. Full Disk Access would include it."})
            continue
        for raw_name in names:
            name = clean_support_name(raw_name)
            if name.startswith(".") or "apple" in name.lower() or name.lower().startswith(("org.cups.", "org.webkit.")):
                continue
            path = os.path.join(root, raw_name)
            if DNS_ID.match(name):
                lower = name.lower()
                if lower in installed or vendor_of(lower) in vendors:
                    continue
                if any(lower.startswith(b + ".") for b in installed):
                    continue
                if matches_something(name.split(".")[-1]) or matches_something(name.split(".")[1]):
                    continue
                app_id = ".".join(name.split(".")[:3])  # one row per app, not one per helper or extension
                groups.setdefault(app_id.lower(), {"name": app_id, "paths": [], "plain_name": False})["paths"].append(path)
            elif location == "Application Support" and os.path.isdir(path):
                if norm(name) in KNOWN_SUPPORT_NAMES or matches_something(name):
                    continue
                groups.setdefault(norm(name), {"name": name, "paths": [], "plain_name": True})["paths"].append(path)

    locked_roots = tuple(os.path.join(LIB, n) + "/" for n in ("Containers", "Group Containers")
                         if os.path.isdir(os.path.join(LIB, n)) and not can_modify(os.path.join(LIB, n)))

    def measure(entry):
        key, group = entry
        ages = [a for a in (newest_change_age(p) for p in group["paths"]) if a is not None]
        newest = min(ages) if ages else 0
        min_age = 180 if group["plain_name"] else 14
        if newest < min_age:  # something still touches it, so it isn't abandoned
            return None
        size = sum(du_bytes(p, timeout=20) or 0 for p in group["paths"])
        if group["plain_name"] and size < MB:
            return None
        if group["plain_name"]:
            confidence = "uncertain"
        else:
            confidence = "very likely" if newest >= 90 else "likely"
        display = group["name"].split(".")[-1] if not group["plain_name"] else group["name"]
        count = len(group["paths"])
        plain = "No installed app or running tool matches this name. It was last changed %d days ago and has %d item%s using %s." % (
            newest, count, "" if count == 1 else "s", fmt_size(size))
        if confidence == "uncertain":
            plain += " The folder name is generic, so check it before removing it."
        movable = [p for p in group["paths"] if not p.startswith(locked_roots)] if locked_roots else group["paths"]
        locked = [p for p in group["paths"] if p not in movable]
        action = "This may be saved data, not just settings. Check the folder first, especially if the app is on an unplugged drive."
        if locked and not movable:
            action = "macOS protects this data, so this tool can't move it. It's safe to leave. To remove it, choose Show in Finder and try dragging it to Trash."
        elif locked:
            action = "Moving this removes the unprotected part only. macOS protects the other %d item%s, so they'll stay and appear here after your next scan." % (len(locked), "" if len(locked) == 1 else "s")
        result = item("leftovers", "%s traces" % display, plain, "low", confidence, size=size, paths=movable,
                      trashable=True, key=key, action=action,
                      technical={"identifier": group["name"], "paths": group["paths"], "protected_paths": locked,
                                 "newest_change_days": round(newest)})
        result["locked"] = bool(locked and not movable)
        return result

    with ThreadPoolExecutor(max_workers=6) as pool:
        found = [r for r in pool.map(measure, list(groups.items())) if r]
    if locked_roots:
        coverage.append({"area": "Protected app data", "status": "partial",
                         "fix": "fda", "note": "macOS blocks changes to ~/Library/Containers and Group Containers, so those leftovers can only be removed from Finder for now."})
    return found


# ---------- Temporary files and developer data ----------

def scan_clutter(coverage):
    results = []

    def sized_children(root, minimum, make):
        if not real_folder(root):
            coverage.append({"area": pretty_path(root), "status": "partial", "note": "It's a link to somewhere else, so it was skipped. Check that you set this up."})
            return
        try:
            names = os.listdir(root)
        except OSError:
            coverage.append({"area": pretty_path(root), "status": "blocked", "fix": "fda", "note": "macOS denied access. Full Disk Access would include it."})
            return
        paths = [os.path.join(root, n) for n in names if "com.apple" not in n and n != "Homebrew"]
        with ThreadPoolExecutor(max_workers=6) as pool:
            sizes = list(pool.map(lambda p: du_bytes(p, timeout=30), paths))
        for path, size in zip(paths, sizes):
            if size and size >= minimum:
                results.append(make(path, size))

    sized_children(os.path.join(LIB, "Caches"), SIZE_CACHE_MIN, lambda p, s: item(
        "clutter", "%s cache" % os.path.basename(p),
        "Temporary data the app can rebuild. Removing it recovers %s, but the app may be slower the next time it opens." % fmt_size(s),
        "info", "safe", size=s, paths=[p], trashable=True, action="Quit that app first. Mac Health has its own window, so it stays open.",
        technical={"path": p}))
    sized_children(os.path.join(LIB, "Logs"), SIZE_LOG_MIN, lambda p, s: item(
        "clutter", "%s logs" % os.path.basename(p),
        "Old activity records, usually only useful for troubleshooting. Removing them recovers %s." % fmt_size(s),
        "info", "safe", size=s, paths=[p], trashable=True, technical={"path": p}))

    downloads = os.path.join(HOME, "Downloads")
    try:
        if not real_folder(downloads):
            raise OSError("link")
        for name in os.listdir(downloads):
            path = os.path.join(downloads, name)
            age = age_days(path)
            if name.lower().endswith((".dmg", ".pkg", ".iso")) and age and age > 30 and os.path.isfile(path) and not os.path.islink(path):
                size = du_bytes(path, timeout=15)
                results.append(item("clutter", name, "An installer in Downloads that's %d days old. You generally don't need it after installing the app." % age,
                                    "info", "review", size=size, paths=[path], trashable=True,
                                    action="Keep it if the app can't easily be downloaded again.", technical={"path": path}))
    except OSError:
        coverage.append({"area": "~/Downloads", "status": "blocked", "fix": "fda", "note": "macOS denied access. Full Disk Access would include it."})

    trash = os.path.join(HOME, ".Trash")
    try:
        os.listdir(trash)
        size = du_bytes(trash)
        if size and size > 100 * MB:
            results.append(item("clutter", "Trash", "Files in Trash still use %s of disk space." % fmt_size(size),
                                "info", "review", size=size, action="Check Trash, then empty it in Finder when you're sure.",
                                technical={"path": trash}))
    except OSError:
        coverage.append({"area": "~/.Trash", "status": "blocked", "fix": "fda", "note": "Reading Trash size needs Full Disk Access."})
    return results


BREW_QUERY_ENV = {"HOMEBREW_NO_AUTO_UPDATE": "1", "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"}


def brew_query(brew, args, timeout=60):
    # Homebrew prints warnings on stderr, and those must not end up inside its JSON.
    return run_outside([brew] + args, timeout=timeout, env=BREW_QUERY_ENV)


def brew_json(brew, args, timeout=60):
    """The parsed answer, or None if Homebrew didn't give one. None is not the same as an empty list."""
    _, out = brew_query(brew, args, timeout)
    try:
        data = json.loads(out)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def brew_dependents(brew, kind, name):
    """What installed packages need this one, or None if that couldn't be checked."""
    if kind == "formula":
        code, out = brew_query(brew, ["uses", "--installed", name])
        return out.split() if code == 0 else None
    code, out = brew_query(brew, ["list", "--cask"], timeout=30)
    if code != 0:
        return None
    if not out.split():
        return []
    data = brew_json(brew, ["info", "--json=v2", "--cask"] + out.split())
    if data is None:
        return None
    return [c["token"] for c in data.get("casks", []) if name in ((c.get("depends_on") or {}).get("cask") or [])]


def brew_items(gaps):
    """Updates that can install, plus one explained row per package Homebrew refuses to update.
    A check Homebrew didn't answer is added to gaps, so it never reads as "nothing to update"."""
    brew = shutil.which("brew", path="/opt/homebrew/bin:/usr/local/bin")
    if not brew:
        return []

    def gap(note):
        gaps.append({"area": "Homebrew", "status": "failed", "fix": "rescan", "note": note})

    data = brew_json(brew, ["outdated", "--json=v2"])
    if data is None:
        gap("Homebrew didn't answer, so updates weren't checked.")
        return []
    formulae = [f["name"] for f in data.get("formulae", [])]
    casks = [c["name"] for c in data.get("casks", [])]
    if not formulae and not casks:
        return []

    def info(flag, names):
        if not names:
            return {}
        parsed = brew_json(brew, ["info", "--json=v2", flag] + names)
        if parsed is None:
            gap("Homebrew didn't give package details, so some updates may not install.")
            return {}
        return parsed

    formula_info = info("--formula", formulae).get("formulae", [])
    cask_info = info("--cask", casks).get("casks", [])

    blocked = {}
    for entry in formula_info:
        if entry.get("disabled"):
            blocked[entry["name"]] = dict(kind="formula", date=entry.get("disable_date"), reason=entry.get("disable_reason"))
    for entry in cask_info:
        if entry.get("disabled"):
            blocked[entry["token"]] = dict(kind="cask", date=entry.get("disable_date"), reason=entry.get("disable_reason"))
    results = []
    for name, details in sorted(blocked.items()):
        users = brew_dependents(brew, details["kind"], name)
        reason = {"fails_gatekeeper_check": "it fails macOS's Gatekeeper check", "versioned_formula": "this old version is retired"}.get(details["reason"], details["reason"] or "it's retired")
        plain = "No update can install: Homebrew stopped updating it on %s because %s." % (details["date"] or "an earlier date", reason)
        fix = None
        remove_with = []
        if users is None:
            action = "Couldn't check what needs it, so scan again before removing it."
        elif users and details["kind"] == "cask":
            remove_with = users
            action = "Nothing to do while you use %s, which needs it. No update is coming, so this can stay as it is." % ", ".join(users)
            names = users + [name]
            fix = {"kind": "brew_remove", "label": "Remove both in Terminal" if len(names) == 2 else "Remove all in Terminal", "names": names,
                   "detail": "Only if you no longer use %s. Terminal opens with one command that removes these. It may ask for your password." % ", ".join(users)}
        elif users:
            action = "Needed by %s, so keep it unless you remove that too." % ", ".join(users)
        else:
            action = "Nothing you've installed needs it, so it's safe to remove."
            fix = {"kind": "brew_remove", "label": "Remove in Terminal", "detail": "Terminal opens with this one command, because removing it may need your password."}
        results.append(item("developer", "%s can't update" % name, plain, "info", key="brew-blocked-" + name, action=action, fix=fix,
                            technical=dict(details, package=name, needed_by=users, remove_with=remove_with, command="brew info --%s %s" % (details["kind"], name))))
    formulae = [n for n in formulae if n not in blocked]
    casks = [n for n in casks if n not in blocked]
    total = len(formulae) + len(casks)
    if total:
        results.insert(0, item("developer", "%d Homebrew update%s" % (total, "" if total == 1 else "s"),
                               "Newer versions, often with security fixes.", "low", key="brew",
                               action="Best between projects, because tool versions can change.",
                               fix={"kind": "brew", "label": "Update packages", "packages": total,
                                    "detail": "This runs brew update, then upgrades each package. Packages that install system-wide will need your password in Terminal."},
                               technical={"formulae": formulae, "casks": casks, "command": "brew outdated --verbose"}))
    return results


def biggest_children(path, limit=6):
    """What's inside a shared folder, so you can judge it without opening it."""
    try:
        names = os.listdir(path)
    except OSError:
        return []
    with ThreadPoolExecutor(max_workers=4) as pool:
        sizes = list(pool.map(lambda n: du_bytes(os.path.join(path, n), timeout=30), names))
    pairs = [(n, b) for n, b in zip(names, sizes) if b]
    return sorted(pairs, key=lambda row: -row[1])[:limit]


def scan_developer(coverage):
    results = []
    known = [
        ("Xcode build data", "Library/Developer/Xcode/DerivedData", "safe", "Xcode rebuilds this automatically, though your next build will take longer."),
        ("iOS device support files", "Library/Developer/Xcode/iOS DeviceSupport", "safe", "Xcode downloads these again when you connect a device."),
        ("Xcode simulator caches", "Library/Developer/CoreSimulator/Caches", "safe", "Simulators rebuild this when needed."),
        ("Xcode archives", "Library/Developer/Xcode/Archives", "review", "These are your packaged app releases and may be needed to debug shipped versions."),
        ("npm download cache", ".npm/_cacache", "safe", "npm downloads packages again when needed."),
        ("Homebrew download cache", "Library/Caches/Homebrew", "safe", "Homebrew downloads packages again when needed."),
        ("pnpm package store", "Library/pnpm/store", "review", "Projects linked to it will need a fresh install."),
        ("Gradle cache", ".gradle/caches", "safe", "Gradle downloads these again on your next build."),
        ("Maven repository", ".m2/repository", "review", "Most of this downloads again, but anything you built with mvn install can't."),
        ("Cargo registry", ".cargo/registry", "safe", "Cargo downloads these again on your next build."),
        ("General tool cache", ".cache", "review", "Shared by several tools, and may hold downloaded models."),
    ]
    def measure(entry):
        title, relative, confidence, note = entry
        path = os.path.join(HOME, relative)
        if not os.path.isdir(path):
            return None
        size = du_bytes(path, timeout=60)
        if not size or size < 100 * MB:
            return None
        inside = biggest_children(path) if confidence == "review" else []
        if inside:
            note = "%s Biggest: %s." % (note, ", ".join("%s (%s)" % (n, fmt_size(b)) for n, b in inside[:3]))
        return item("developer", title, note, "info", confidence, size=size,
                    paths=[path], trashable=True, technical={"path": path, "contains": [{"name": n, "size": fmt_size(b)} for n, b in inside]})
    with ThreadPoolExecutor(max_workers=4) as pool:
        results.extend(r for r in pool.map(measure, known) if r)

    results.extend(brew_items(coverage))

    docker = shutil.which("docker", path="/usr/local/bin:/opt/homebrew/bin")
    if docker:
        code, out = run_outside([docker, "system", "df", "--format", "{{json .}}"], timeout=15)
        rows = []
        for line in out.splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
        if code == 0 and rows:
            summary = ", ".join("%s: %s" % (r.get("Type"), r.get("Size")) for r in rows)
            results.append(item("developer", "Docker storage", "Docker is using: %s. Docker has to clean this up itself, so this tool won't touch it." % summary,
                                "info", key="docker", action="Review first, then run: docker system prune",
                                technical={"docker_system_df": rows}))
    return results


def has_lockfile(project):
    """Without one, an install may not rebuild the same thing."""
    return any(os.path.exists(os.path.join(project, n)) for n in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json"))


def scan_files(coverage):
    """One walk of the home folder for large files, duplicates and node_modules."""
    started = time.time()
    candidates, node_modules = [], []
    truncated = False
    for current, dirs, files in os.walk(HOME):
        if time.time() - started > WALK_BUDGET_SECONDS:
            truncated = True
            break
        kept = []
        for name in dirs:
            if name == "node_modules":
                node_modules.append(os.path.join(current, name))
            elif not (name.startswith(".") or name in SKIP_WALK_DIRS or (current == HOME and name in SKIP_HOME_DIRS) or name.lower().endswith(PACKAGE_EXTS)):
                kept.append(name)
        dirs[:] = kept
        for name in files:
            path = os.path.join(current, name)
            try:
                info = os.lstat(path)
            except OSError:
                continue
            if info.st_size >= SIZE_DUPLICATE_MIN and (info.st_mode & 0o170000) == 0o100000:
                candidates.append((path, info))
    if truncated:
        coverage.append({"area": "Home folder file search", "status": "partial",
                         "note": "Stopped after %d seconds, so some large files or duplicates may be missing." % WALK_BUDGET_SECONDS})

    def is_local(info):
        # iCloud placeholders report a size without using disk. Reading one would download it.
        return info.st_blocks * 512 >= info.st_size * 0.9

    large = []
    biggest = sorted((c for c in candidates if c[1].st_size >= SIZE_LARGE_FILE and is_local(c[1])),
                     key=lambda c: -c[1].st_size)[:30]
    for path, info in biggest:
        large.append(item("large", os.path.basename(path),
                          "%s in %s, last changed %d days ago." % (fmt_size(info.st_size), pretty_path(os.path.dirname(path)), (time.time() - info.st_mtime) / DAY),
                          "info", "review", size=info.st_size, paths=[path], trashable=True,
                          technical={"path": path, "modified": time.strftime("%Y-%m-%d", time.localtime(info.st_mtime))}))
        large[-1]["stamp"] = stamp_of(info)

    seen_infos = dict(candidates)  # taken before hashing, so a change during the scan still shows
    by_size, seen = {}, set()
    for path, info in candidates:
        identity = (info.st_dev, info.st_ino)
        if identity in seen or not is_local(info):
            continue
        seen.add(identity)
        by_size.setdefault(info.st_size, []).append(path)

    hash_start = time.time()

    def digest(path, size, partial):
        hasher = hashlib.blake2b(digest_size=20)
        try:
            with open(path, "rb") as handle:
                if partial:
                    hasher.update(handle.read(MB))
                    handle.seek(max(0, size - MB))
                    hasher.update(handle.read(MB))
                else:
                    for chunk in iter(lambda: handle.read(4 * MB), b""):
                        if time.time() - hash_start > HASH_BUDGET_SECONDS:
                            return None
                        hasher.update(chunk)
        except OSError:
            return None
        return hasher.hexdigest()

    duplicates = []
    for size, paths in sorted(by_size.items(), reverse=True):
        if len(paths) < 2:
            continue
        if time.time() - hash_start > HASH_BUDGET_SECONDS:
            coverage.append({"area": "Duplicate check", "status": "partial",
                             "note": "Stopped after %d seconds and started with the largest files." % HASH_BUDGET_SECONDS})
            break
        partial_groups = {}
        for path in paths:
            key = digest(path, size, True)
            if key:
                partial_groups.setdefault(key, []).append(path)
        for members in partial_groups.values():
            if len(members) < 2:
                continue
            full_groups = {}
            for path in members:
                key = digest(path, size, False)
                if key:
                    full_groups.setdefault(key, []).append(path)
            for key, same in full_groups.items():
                if len(same) < 2:
                    continue
                for path in same:
                    duplicates.append(item("duplicates", os.path.basename(path),
                                           "In %s. Identical copies: %d. Keep at least one." % (pretty_path(os.path.dirname(path)), len(same)),
                                           "info", "exact match", size=size, paths=[path], trashable=True, group=key,
                                           technical={"path": path, "blake2b": key}))
                    duplicates[-1]["stamp"] = stamp_of(seen_infos[path])

    developer = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        sizes = list(pool.map(lambda p: du_bytes(p, timeout=30), node_modules))
    for path, size in zip(node_modules, sizes):
        if not size or size < 50 * MB:
            continue
        age = newest_change_age(os.path.dirname(path), skip=("node_modules", ".git")) or 0
        if age >= 30:
            project = os.path.basename(os.path.dirname(path))
            developer.append(item("developer", "%s dependencies" % project,
                                  "The node_modules folder in a project untouched for %d days uses %s. Your install command can rebuild it." % (age, fmt_size(size)),
                                  "info", "safe" if has_lockfile(os.path.dirname(path)) else "review", size=size, paths=[path], trashable=True,
                                  action="Run your package manager's install command when you return to the project.",
                                  technical={"path": path}))
    return large, duplicates, developer


# ---------- Network ----------

APP_NAME_CLEAN = re.compile(r"( Helper.*| Networking.*|\.helper.*)$")
CONNECTION_NOTES = {
    "browser": "Browsers open several connections per site, so this is normal.",
    "messaging": "Stays connected so messages arrive instantly.",
    "ai": "Talks to its online service while you use it.",
}
APP_KINDS = {"google chrome": "browser", "safari": "browser", "firefox": "browser", "com.apple.webkit": "browser", "brave browser": "browser", "microsoft edge": "browser", "arc": "browser",
             "whatsapp": "messaging", "telegram": "messaging", "slack": "messaging", "signal": "messaging", "discord": "messaging",
             "claude": "ai"}
SERVICE_INFO = {
    "ControlCenter": ("AirPlay Receiver", "Lets other devices play audio or video on this Mac.", "airdrop", "Don't use AirPlay to this Mac? You can turn it off."),
    "rapportd": ("Apple device-to-device features", "Lets your Apple devices use Handoff and Universal Clipboard.", None, None),
    "sharingd": ("AirDrop and sharing", "Lets nearby devices find this Mac.", "airdrop", "You can change this in AirDrop & Handoff settings."),
}


def scan_network(firewall_on):
    results = []
    # lsof exits 1 when it simply finds nothing, so only -1 means the check didn't finish.
    code, listening = run(["/usr/sbin/lsof", "+c0", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=20)
    if code == -1:
        raise RuntimeError("lsof didn't finish")
    # Process names can contain spaces, so read columns from the right: "... TCP addr (LISTEN)".
    exposed_ports, local_only, listening_ports = {}, set(), set()
    for line in listening.splitlines()[1:]:
        match = re.match(r"^(.+?)\s+(\d+)\s+\S+\s+.*TCP\s+(\S+)\s+\(LISTEN\)$", line)
        if not match:
            continue
        command, pid, address = match.group(1).replace("\\x20", " "), match.group(2), match.group(3)
        port = address.rsplit(":", 1)[-1]
        listening_ports.add(port)
        if address.startswith(("*:", "0.0.0.0:", "[::]:")):
            exposed_ports.setdefault(command, {"pid": pid, "ports": set(), "addresses": set()})
            exposed_ports[command]["ports"].add(port)
            exposed_ports[command]["addresses"].add(address)
        else:
            local_only.add((command, port))

    code, established = run(["/usr/sbin/lsof", "+c0", "-nP", "-iTCP", "-sTCP:ESTABLISHED"], timeout=20)
    if code == -1:
        raise RuntimeError("lsof didn't finish")
    active, inbound = {}, {}
    for line in established.splitlines()[1:]:
        match = re.match(r"^(.+?)\s+\d+\s+\S+\s+.*TCP\s+(\S+)->(\S+)\s+\(ESTABLISHED\)$", line)
        if not match:
            continue
        command, local, remote = match.group(1).replace("\\x20", " "), match.group(2), match.group(3)
        if remote.startswith(("127.", "[::1]")):
            continue
        if local.rsplit(":", 1)[-1] in listening_ports:
            inbound.setdefault(command, set()).add(remote)
        else:
            name = APP_NAME_CLEAN.sub("", command)
            active.setdefault(name, {"remotes": set(), "processes": set()})
            active[name]["remotes"].add(remote)
            active[name]["processes"].add(command)

    for command, info in sorted(exposed_ports.items()):
        ports = sorted(info["ports"], key=int)
        service = SERVICE_INFO.get(command)
        connected = len(inbound.get(command, ()))
        direction = "Connected right now: %d." % connected
        if service:
            plain = "%s %s %s" % (service[0] + ".", service[1], direction)
        else:
            plain = "Accepts connections on port%s %s. %s" % ("" if len(ports) == 1 else "s", ", ".join(ports), direction)
        fix = None
        action = "Fine for something you run on purpose, like a dev server. Otherwise, quit it."
        if service:
            action = service[3]
            if service[2]:
                fix = {"kind": "settings", "pane": service[2], "label": "Open AirDrop & Handoff settings"}
        results.append(item("network", "%s is listening for connections" % command, plain,
                            "low" if firewall_on or service else "medium", key=command, action=action, fix=fix,
                            technical={"process": command, "pid": info["pid"], "addresses": sorted(info["addresses"]),
                                       "inbound_now": sorted(inbound.get(command, ()))}))

    counts = sorted(len(v["remotes"]) for v in active.values())
    median = counts[len(counts) // 2] if counts else 0
    for name, info in sorted(active.items(), key=lambda row: -len(row[1]["remotes"])):
        total = len(info["remotes"])
        encrypted = sum(1 for r in info["remotes"] if r.rsplit(":", 1)[-1] in ("443", "5228", "5222", "993"))
        kind = next((k for prefix, k in APP_KINDS.items() if name.lower().startswith(prefix)), None)
        plain = CONNECTION_NOTES[kind] if kind else "This app connected out from your Mac."
        outlier = total >= 5 and total >= 3 * max(median, 1)
        action = None
        if outlier:
            plain = "More than your other apps. " + plain
            action = ("Only act if it feels slow: Chrome > Window > Task Manager shows the busiest tabs."
                      if name.lower().startswith("google chrome") else
                      "If you don't recognise why this app needs this many connections, quit it and see if the number falls.")
        result = item("network", name, plain, "info", key=name + "-active", action=action,
                      technical={"processes": sorted(info["processes"]), "remote_addresses": sorted(info["remotes"])[:40], "encrypted_ports": encrypted})
        result["connections"] = total
        result["outlier"] = outlier
        results.append(result)
    return results, len(local_only)


# ---------- Score and tips ----------

def build_score(cards, sections):
    deductions = []

    def deduct(points, reason):
        deductions.append({"points": points, "reason": reason})

    used = cards["disk"]["used_pct"]
    if used >= 90:
        deduct(20, "Your disk is %.0f%% full" % used)
    elif used >= 80:
        deduct(8, "Your disk is %.0f%% full" % used)
    free_pct = cards["memory"]["free_pct"]
    if free_pct is not None and free_pct < 15:
        deduct(10, "Memory is under pressure")
    # A short busy spell isn't ill health, and a scan must not lower its own score.
    cpu = cards["cpu"]
    if (cpu["busy_pct"] or 0) >= 90 and not cpu["recent_scan"]:
        deduct(3, "The processor was very busy before this scan")
    security = cards["security"]
    if security["filevault"] is False:
        deduct(15, "FileVault disk encryption is off")
    if security["gatekeeper"] is False:
        deduct(15, "Gatekeeper app checks are off")
    if security["sip"] is False:
        deduct(15, "System Integrity Protection is off")
    if security["firewall"] is False:
        deduct(5, "The firewall is off")
    if cards["updates"]:
        deduct(5, "macOS updates are waiting")
    battery = cards.get("battery")
    if battery and battery.get("condition") not in (None, "Good", "Normal"):
        deduct(5, "Battery condition is %s" % battery["condition"])
    if (cards["uptime_days"] or 0) > 30:
        deduct(2, "Your Mac hasn't restarted in over 30 days")
    high = sum(1 for i in sections["alerts"] if i["severity"] == "high")
    medium = sum(1 for i in sections["alerts"] if i["severity"] == "medium")
    if high:
        deduct(min(15, high * 5), "%d high-priority alert%s" % (high, "" if high == 1 else "s"))
    if medium:
        deduct(min(10, medium * 2), "%d medium-priority alert%s" % (medium, "" if medium == 1 else "s"))
    return max(0, 100 - sum(d["points"] for d in deductions)), deductions


def build_tips(cards, sections):
    tips = []

    def tip(key, priority, title, plain, why, how, fix=None):
        tips.append({"key": key, "priority": priority, "title": title, "plain": plain, "why": why, "how": how, "fix": fix})

    security = cards["security"]
    if security["filevault"] is False:
        tip("filevault", "high", "Turn on FileVault", "Your files aren't encrypted.",
            "Without it, anyone holding your Mac could read your files, even without your password.",
            "Store the recovery key somewhere safe when macOS shows it.",
            {"kind": "settings", "pane": "filevault", "label": "Open FileVault settings"})
    if security["gatekeeper"] is False:
        tip("gatekeeper", "high", "Turn Gatekeeper back on", "App checks are switched off.",
            "Gatekeeper is what stops unidentified and known-bad apps from opening.",
            "In Terminal, run: sudo spctl --master-enable")
    if security["sip"] is False:
        tip("sip", "high", "Turn System Integrity Protection back on", "A core macOS protection is off.",
            "It stops software, even with admin rights, from changing protected parts of macOS.",
            "Restart into Recovery, open Terminal, and run: csrutil enable")
    if security["firewall"] is False:
        tip("firewall", "medium", "Turn on the firewall", "Unwanted incoming connections aren't being filtered.",
            "This matters most on public Wi-Fi, where other people's devices share your network.",
            "Apps you've allowed will keep working.",
            {"kind": "admin", "action": "firewall_on", "label": "Turn on firewall", "detail": "macOS will ask for your password."})
    if cards["updates"]:
        count = len(cards["updates"])
        tip("updates", "high", "Install %d waiting update%s" % (count, "" if count == 1 else "s"), ", ".join(cards["updates"][:3]) + ".",
            "Attackers study published fixes, so waiting makes known weaknesses more useful to them. A major macOS upgrade is a bigger change, so back up first.",
            "Save your work first because your Mac may restart.",
            {"kind": "settings", "pane": "updates", "label": "Open Software Update"})
    used = cards["disk"]["used_pct"]
    if used >= 80:
        tip("disk", "high" if used >= 90 else "medium", "Free up disk space", "Your disk is %.0f%% full." % used,
            "macOS needs free space for updates, virtual memory and temporary files, and can slow down without it.",
            "Start with the items that show their size.", {"kind": "tab", "tab": "clutter", "label": "Go to Cleanup"})
    groups = (
        ("caches", "safe caches and logs", [i for i in sections["clutter"] if i["confidence"] == "safe"], "clutter",
         "These rebuild themselves. Apps may just be a little slower the next time they open."),
        ("devdata", "developer data you can rebuild", [i for i in sections["developer"] if i["confidence"] == "safe"], "developer",
         "These come back when you next build or install, so you only pay with a little waiting time."),
        ("leftovers", "likely app leftovers", [i for i in sections["leftovers"] if i["confidence"] in ("very likely", "likely") and i["trashable"]], "leftovers",
         "Apps often leave data behind when you delete them, and it never cleans itself up."),
    )
    for key, label, members, tab, why in groups:
        total = sum(i["size"] or 0 for i in members)
        if total >= 500 * MB:
            tip(key, "medium", "Recover %s from %s" % (fmt_size(total), label),
                "%d item%s found." % (len(members), "" if len(members) == 1 else "s"), why,
                "Everything goes to Trash first, so you can restore it.", {"kind": "tab", "tab": tab, "label": "Review them"})
    orphans = [i for i in sections["leftovers"] if i.get("fix")]
    if orphans:
        tip("orphans", "medium", "Remove %d startup leftover%s" % (len(orphans), "" if len(orphans) == 1 else "s"),
            "Files from removed apps are still registered with macOS.",
            "They use very little, but anything that loads at startup should be something you can explain.",
            "Each one is explained on the Leftovers page.", {"kind": "tab", "tab": "leftovers", "label": "Review them"})
    alerts = sections["alerts"]
    if alerts:
        serious = any(i["severity"] in ("high", "medium") for i in alerts)
        tip("alerts", "high" if serious else "low", "Review %d alert%s" % (len(alerts), "" if len(alerts) == 1 else "s"),
            "Start with %s." % alerts[0]["title"],
            "A flag means unusual, not guilty, but you should be able to explain everything flagged.",
            "If you can't identify an item, search for its exact name.", {"kind": "tab", "tab": "alerts", "label": "Go to Alerts"})
    brew = [i for i in sections["developer"] if i["fix"] and i["fix"].get("kind") == "brew"]
    if brew:
        tip("brew", "medium", brew[0]["title"], "Tools you may have forgotten about.",
            "Updates often include security fixes.",
            "Best between projects.", brew[0]["fix"])
    if (cards["uptime_days"] or 0) > 14:
        tip("restart", "low", "Restart your Mac", "It's been running for %d days." % cards["uptime_days"],
            "A restart finishes pending updates and clears out stuck processes.", "Apple menu > Restart.")
    battery = cards.get("battery")
    if battery and battery.get("condition") not in (None, "Good", "Normal"):
        tip("battery", "medium", "Check your battery", "macOS reports its condition as %s." % battery["condition"],
            "A worn battery can shorten battery life and affect performance.", "Check its service recommendation.",
            {"kind": "settings", "pane": "battery", "label": "Open Battery settings"})
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(tips, key=lambda t: order[t["priority"]])


# ---------- Full scan ----------

CAN_DO = ["Read protected folders during a scan", "Move items you select to Trash",
          "Remove startup leftovers, with your password", "Update Homebrew packages when you ask", "Open the right Settings page"]
LIMITS = ["Prove your Mac is malware-free", "Change core files protected by macOS", "See inside encrypted traffic",
          "Know who owns a network address", "Know which files you still need", "Grant its own permissions", "Check iCloud files that aren't downloaded"]


def full_disk_access():
    """Only an app with Full Disk Access can list these protected folders."""
    for folder in (os.path.join(LIB, "Safari"), os.path.join(LIB, "Cookies")):
        try:
            os.listdir(folder)
            return True
        except FileNotFoundError:
            continue
        except OSError:
            return False
    return None


def full_scan(progress=lambda stage, pct: None, last_scan=None):
    coverage = []
    sections = {k: [] for k in ("alerts", "leftovers", "clutter", "developer", "large", "duplicates", "network", "startup")}

    def guarded(label, fn, fallback=None):
        try:
            return fn()
        except Exception as error:
            coverage.append({"area": label, "status": "failed", "note": "This check failed: %s" % error})
            return fallback

    progress("Checking system health", 3)
    # This can take over a minute online, so it runs alongside everything else.
    updates_pool = ThreadPoolExecutor(max_workers=1)
    updates = updates_pool.submit(check_software_updates)
    login_pool = ThreadPoolExecutor(max_workers=1)
    login_items = login_pool.submit(scan_login_items)
    cards, raw = scan_health(check_updates=False, last_scan=last_scan)

    progress("Listing installed apps", 14)
    paths = guarded("App list", lambda: find_apps(coverage), []) or []
    with ThreadPoolExecutor(max_workers=8) as pool:
        apps = list(pool.map(app_info, paths))

    # An updater left in Application Support doesn't mean its app is still installed.
    installed = [a for a in apps if not a["path"].startswith(os.path.join(LIB, "Application Support") + "/")]

    progress("Checking app signatures", 20)
    app_items, third_party = guarded("App signatures", lambda: scan_apps(apps, coverage), ([], 0))
    for entry in app_items:
        sections[entry["category"]].append(entry)

    progress("Checking startup items", 38)
    for entry in guarded("Startup items", lambda: scan_launch_items(installed), []) or []:
        sections[entry["category"]].append(entry)
    sections["leftovers"].extend(guarded("Audio drivers", lambda: scan_audio_drivers(installed), []) or [])

    progress("Looking for traces of uninstalled apps", 45)
    sections["leftovers"].extend(guarded("App leftovers", lambda: scan_leftovers(installed, coverage), []) or [])

    progress("Measuring caches and temporary files", 58)
    sections["clutter"].extend(guarded("Temporary files", lambda: scan_clutter(coverage), []) or [])

    progress("Measuring developer tools", 66)
    sections["developer"].extend(guarded("Developer tools", lambda: scan_developer(coverage), []) or [])

    progress("Finding large and duplicate files", 74)
    large, duplicates, modules = guarded("File search", lambda: scan_files(coverage), ([], [], []))
    sections["large"], sections["duplicates"] = large, duplicates
    sections["developer"].extend(modules)

    progress("Checking network activity", 94)
    network, local_only = guarded("Network", lambda: scan_network(cards["security"]["firewall"] is True), ([], 0))
    sections["network"] = network

    fda = full_disk_access()

    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sections["alerts"].sort(key=lambda i: rank[i["severity"]])
    sections["leftovers"].sort(key=lambda i: (bool(i.get("locked")), -(i["size"] or 0)))
    for name in ("clutter", "developer", "large", "duplicates"):
        sections[name].sort(key=lambda i: -(i["size"] or 0))

    progress("Preparing your results", 98)
    startup = guarded("Startup list", login_items.result, None)
    login_pool.shutdown()
    sections["startup"] = startup or []
    if startup is None and not any(c["area"] == "Startup list" for c in coverage):
        coverage.append({"area": "Startup list", "status": "failed", "fix": "rescan", "note": "macOS didn't return the list in time."})
    cards["updates"] = updates.result()
    updates_pool.shutdown()
    score, deductions = build_score(cards, sections)
    tips = build_tips(cards, sections)
    return {
        "generated_at": time.time(),
        "score": score,
        "deductions": deductions,
        "cards": cards,
        "sections": sections,
        "tips": tips,
        "coverage": coverage,
        "limits": LIMITS, "can_do": CAN_DO,
        "access": {"full_disk_access": fda},
        "meta": {"apps_total": len(apps), "apps_checked": third_party, "local_only_ports": local_only, "raw": raw},
    }
