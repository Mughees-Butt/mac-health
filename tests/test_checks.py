"""Checks for the behaviour most likely to mislead someone: false all-clears and unsafe removals.
They use a temporary home folder and a fake brew, so they don't touch real results or change the Mac."""
import os
import json
import plistlib
import shutil
import stat
import sys
import tempfile
import time
import unittest

HOME = os.path.realpath(tempfile.mkdtemp())
os.environ["HOME"] = HOME
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "backend"))

import scanners  # noqa: E402
import server  # noqa: E402

BLOCKED = '{"casks":[{"token":"lib","disabled":true,"disable_reason":"fails_gatekeeper_check"}]}'
NEEDS_LIB = '{"casks":[{"token":"app","depends_on":{"cask":["lib"]}}]}'


class FakeBrew(unittest.TestCase):
    """Replaces brew with a script, printing a warning on stderr as the real one can."""

    def setUp(self):
        self.addCleanup(setattr, scanners, "run_outside", scanners.run_outside)
        scanners.run_outside = lambda cmd, timeout=60, env=None, merge=False, on_output=None: scanners.run(cmd, timeout=timeout, merge_stderr=merge)
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        self.brew = os.path.join(folder, "brew")
        self.real_which = shutil.which
        shutil.which = lambda name, path=None: self.brew
        self.addCleanup(setattr, shutil, "which", self.real_which)

    def write(self, dependents=NEEDS_LIB, outdated='{"formulae":[],"casks":[{"name":"lib"}]}'):
        with open(self.brew, "w") as handle:
            handle.write("""#!/bin/zsh
echo "Warning: noise" >&2
case "$*" in
  outdated*) echo '%s' ;;
  "info --json=v2 --cask lib") echo '%s' ;;
  "list --cask") echo "lib app" ;;
  "info --json=v2 --cask lib app") echo '%s' ;;
esac
""" % (outdated, BLOCKED, dependents))
        os.chmod(self.brew, 0o755)


class Homebrew(FakeBrew):
    def test_warning_on_stderr_does_not_break_json(self):
        self.write()
        gaps = []
        rows = scanners.brew_items(gaps)
        self.assertEqual(gaps, [])
        self.assertIn("app", rows[0]["action"])

    def test_needed_cask_is_never_called_safe_to_remove(self):
        self.write()
        row = scanners.brew_items([])[0]
        self.assertNotIn("safe to remove", row["action"])
        self.assertEqual(row["fix"]["names"], ["app", "lib"])

    def test_failed_dependency_check_offers_no_removal(self):
        self.write(dependents="garbage")
        row = scanners.brew_items([])[0]
        self.assertIsNone(row["fix"])
        self.assertIsNone(scanners.brew_dependents(self.brew, "cask", "lib"))

    def test_no_answer_is_a_gap_not_all_clear(self):
        self.write(outdated="garbage")
        gaps = []
        self.assertEqual(scanners.brew_items(gaps), [])
        self.assertEqual(gaps[0]["area"], "Homebrew")


class Ages(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        os.makedirs(self.root + "/a/b")
        self.file = self.root + "/a/b/f"
        open(self.file, "w").close()
        old = time.time() - 90 * scanners.DAY
        for path in (self.file, self.root + "/a/b", self.root + "/a", self.root):
            os.utime(path, (old, old))

    def test_old_tree_is_old(self):
        self.assertGreater(scanners.newest_change_age(self.root), 89)

    def test_nested_edit_counts_as_recent(self):
        os.utime(self.file, None)
        self.assertLess(scanners.newest_change_age(self.root), 1)

    def test_unfinished_search_never_means_abandoned(self):
        self.assertEqual(scanners.newest_change_age(self.root, limit=0), 0)


class LauncherWrapper(unittest.TestCase):
    def build(self, folder, link_inside):
        app = os.path.join(folder, "W.app")
        os.makedirs(app + "/Contents/MacOS")
        with open(app + "/Contents/Info.plist", "wb") as handle:
            plistlib.dump({"CFBundleExecutable": "x"}, handle)
        program = (app + "/Contents/MacOS/real") if link_inside else os.path.join(folder, "tool")
        open(program, "w").close()
        os.symlink(program, app + "/Contents/MacOS/x")
        return app, program

    def test_link_outside_the_bundle_is_a_wrapper(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        app, program = self.build(folder, False)
        self.assertEqual(scanners.launcher_target(app), os.path.realpath(program))

    def test_link_inside_the_bundle_is_not(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        app, _ = self.build(folder, True)
        self.assertIsNone(scanners.launcher_target(app))


class Tips(unittest.TestCase):
    CARDS = {"disk": {"used_pct": 10}, "memory": {"free_pct": 50}, "cpu": {"busy_pct": 1, "recent_scan": False},
             "security": {"filevault": True, "gatekeeper": True, "sip": True, "firewall": True}, "updates": [], "uptime_days": 1}

    def sections(self):
        found = {name: [] for name in ("alerts", "leftovers", "clutter", "developer", "large", "duplicates", "network")}
        found["startup"] = [{"enabled": True}]
        return found

    def test_startup_alone_is_not_a_next_step(self):
        self.assertEqual(scanners.build_tips(self.CARDS, self.sections()), [])

    def test_low_alert_stays_a_low_priority_step(self):
        found = self.sections()
        found["alerts"] = [{"severity": "low", "title": "Example"}]
        self.assertEqual(scanners.build_tips(self.CARDS, found)[0]["priority"], "low")


class Actions(unittest.TestCase):
    def setUp(self):
        os.makedirs(server.REMOVED_DIR, exist_ok=True)
        os.makedirs(server.TECH_DIR, exist_ok=True)
        self.commands = []
        self.dropped = []
        for name, value in (("open_terminal_script", self.commands.append), ("drop_items", self.dropped.append)):
            self.addCleanup(setattr, server, name, getattr(server, name))
            setattr(server, name, value)
        self.addCleanup(setattr, server, "move_to_trash", server.move_to_trash)
        self.addCleanup(setattr, server, "find_brew", server.find_brew)
        server.find_brew = lambda: "/fake/brew"
        self.addCleanup(setattr, scanners, "brew_dependents", scanners.brew_dependents)
        server.state.update(reinstall={}, brew_ids=set(), tech={}, system_items={}, acting=False, scanning=False, scanned_at=time.time())

    def test_reinstall_uses_force_only_for_apps_outside_homebrew(self):
        server.state["reinstall"]["a"] = {"token": "clipy", "installed": False}
        server.state["reinstall"]["b"] = {"token": "clipy", "installed": True}
        server.brew_reinstall_in_terminal("a")
        server.brew_reinstall_in_terminal("b")
        self.assertIn("install --cask --force clipy", self.commands[0][0])
        self.assertIn("reinstall --cask clipy", self.commands[1][0])

    def test_reinstall_refuses_unsafe_names_and_unknown_items(self):
        server.state["reinstall"]["a"] = {"token": "x;rm", "installed": False}
        self.assertEqual(server.brew_reinstall_in_terminal("a")[1], 400)
        self.assertEqual(server.brew_reinstall_in_terminal("missing")[1], 400)
        self.assertEqual(self.commands, [])

    def remove_setup(self):
        server.state["brew_ids"] = {"g"}
        server.state["tech"]["g"] = {"package": "lib", "kind": "cask", "needed_by": ["app"], "remove_with": ["app"]}

    def test_saved_results_cannot_remove(self):
        self.remove_setup()
        server.state["brew_ids"] = set()
        self.assertEqual(server.brew_remove_in_terminal("g")[1], 400)

    def test_removal_lists_the_dependent_first(self):
        self.remove_setup()
        scanners.brew_dependents = lambda brew, kind, name: ["app"] if name == "lib" else []
        self.assertEqual(server.brew_remove_in_terminal("g")[1], 200)
        self.assertIn("uninstall --cask app lib", self.commands[0][0])

    def test_removal_stops_if_something_else_needs_it(self):
        self.remove_setup()
        scanners.brew_dependents = lambda brew, kind, name: ["other"]
        self.assertEqual(server.brew_remove_in_terminal("g")[1], 400)
        self.assertEqual(self.commands, [])

    def test_removal_stops_if_the_check_fails(self):
        self.remove_setup()
        scanners.brew_dependents = lambda brew, kind, name: None
        self.assertEqual(server.brew_remove_in_terminal("g")[1], 400)

    def test_row_stays_until_your_own_files_are_gone(self):
        folder = os.path.join(HOME, "Library", "LaunchAgents")
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, "com.example.plist")
        open(path, "w").close()
        server.state["system_items"]["x"] = {"system": [], "user": [{"path": path, "label": None}]}
        server.move_to_trash = lambda p: "macOS blocked this move"
        self.assertEqual(server.remove_system_item("x")[1], 400)
        self.assertEqual(self.dropped, [])
        server.move_to_trash = lambda p: os.remove(p)
        self.assertEqual(server.remove_system_item("x")[1], 200)
        self.assertEqual(self.dropped, [["x"]])

    def test_changes_refuse_to_overlap(self):
        self.assertTrue(server.begin_action())
        self.assertFalse(server.begin_action())
        server.end_action()


class OutsideJob(unittest.TestCase):
    def test_runs_once_and_reports_exit_code(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        marker = os.path.join(folder, "runs")
        code, out = scanners.spawn_outside(["/bin/sh", "-c", 'echo run >> "$0"; echo hello; echo bad >&2; exit 3', marker], 20, None, False, None)
        time.sleep(1.5)
        self.assertEqual((code, out.strip()), (3, "hello"))
        with open(marker) as handle:
            self.assertEqual(handle.read().count("run"), 1)

    def test_links_and_shared_files_are_never_read(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        secret = os.path.join(folder, "secret")
        with open(secret, "w") as handle:
            handle.write("protected")
        job = os.path.join(folder, "job")
        os.mkdir(job)
        os.symlink(secret, job + "/link")
        os.link(secret, job + "/hard")
        os.mkfifo(job + "/pipe")
        with open(job + "/plain", "w") as handle:
            handle.write("ok")
        fd = os.open(job, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        for name in ("link", "hard", "pipe", "missing"):
            self.assertIsNone(scanners.read_job_file(fd, name), name)
        self.assertEqual(scanners.read_job_file(fd, "plain"), b"ok")

    def test_hostile_job_cannot_swap_its_output_for_a_link(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        secret = os.path.join(folder, "secret")
        with open(secret, "w") as handle:
            handle.write("protected-data")
        script = 'd=$(ls -dt "${TMPDIR:-/tmp}"/machealth-job-* /tmp/machealth-job-* /var/folders/*/*/T/machealth-job-* 2>/dev/null | head -1); ln -sf "$0" "$d/out"; exit 0'
        code, out = scanners.spawn_outside(["/bin/sh", "-c", script, secret], 20, None, False, None)
        self.assertNotIn("protected-data", out)

    def test_no_isolation_means_nothing_runs(self):
        self.addCleanup(setattr, scanners, "outside_verified", scanners.outside_verified)
        self.addCleanup(setattr, scanners, "spawn_outside", scanners.spawn_outside)
        self.addCleanup(setattr, scanners, "full_disk_access", scanners.full_disk_access)
        scanners.outside_verified = False
        scanners.full_disk_access = lambda: True
        calls = []
        scanners.spawn_outside = lambda cmd, *rest: (calls.append(cmd), (0, "listed"))[1]  # the job could read a protected folder
        self.assertEqual(scanners.run_outside(["/opt/homebrew/bin/brew"]), (-1, ""))
        self.assertFalse(any("brew" in c[0] for c in calls))


class SavedData(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder)

    def test_script_in_counts_is_refused(self):
        good = {"score": 1, "generated_at": 1, "cards": {"disk": {}, "memory": {}, "cpu": {}, "security": {}}, "tips": [], "coverage": [], "deductions": [],
                "sections": {k: [] for k in ("alerts", "leftovers", "clutter", "developer", "large", "duplicates", "network", "startup")}}
        self.assertTrue(server.valid_report(good))
        bad = json.loads(json.dumps(good))
        bad["sections"]["leftovers"] = {"length": "<img src=x onerror=alert(1)>"}
        self.assertFalse(server.valid_report(bad))
        self.assertFalse(server.valid_report(["not a report"]))
        missing = json.loads(json.dumps(good))
        missing["cards"] = {}
        self.assertFalse(server.valid_report(missing))

    def test_link_to_protected_file_is_not_read_or_appended(self):
        real = os.path.join(self.folder, "secret")
        with open(real, "w") as handle:
            handle.write('{"t": 1}\n')
        link = os.path.join(self.folder, "link")
        os.symlink(real, link)
        self.assertEqual(server.read_jsonl(link), [])
        self.assertEqual(server.read_json(link, {}), {})
        with self.assertRaises(OSError):
            server.append_jsonl(link, {"t": 2})

    def test_bad_rows_and_types_are_ignored(self):
        path = os.path.join(self.folder, "h.jsonl")
        with open(path, "w") as handle:
            handle.write('5\n{"t":"x"}\n{"t":NaN}\n' + "[" * 100000 + '\n{"t":3}\n')
        self.assertEqual(server.read_jsonl(path), [{"t": 3}])
        with open(path, "w") as handle:
            handle.write("[]")
        self.assertEqual(server.read_json(path, {}), {})

    def test_infinity_is_refused(self):
        path = os.path.join(self.folder, "s.json")
        with open(path, "w") as handle:
            handle.write('{"a": 1e400}')
        self.assertEqual(server.read_json(path, {}), {})

    def test_hard_link_is_not_read(self):
        real = os.path.join(self.folder, "real")
        with open(real, "w") as handle:
            handle.write('{"a": 1}')
        link = os.path.join(self.folder, "hard")
        os.link(real, link)
        self.assertEqual(server.read_json(link, {}), {})

    def test_pipe_cannot_hang_appending(self):
        path = os.path.join(self.folder, "pipe")
        os.mkfifo(path)
        with self.assertRaises(OSError):
            server.append_jsonl(path, {"t": 1})

    def test_plist_dates_do_not_break_saving(self):
        import datetime
        self.assertIn("2020", server.to_json({"keep_alive": datetime.datetime(2020, 1, 1)}))

    def test_housekeeping_only_deletes_its_own_files(self):
        self.addCleanup(setattr, server, "TECH_DIR", server.TECH_DIR)
        target = os.path.join(self.folder, "protected")
        os.mkdir(target)
        victim = os.path.join(target, "1.json")
        open(victim, "w").close()
        link = os.path.join(self.folder, "technical")
        os.symlink(target, link)
        server.TECH_DIR = link
        server.delete_all_technical()
        self.assertTrue(os.path.exists(victim))
        os.remove(link)
        os.mkdir(link)
        other = os.path.join(link, "notes.txt")
        open(other, "w").close()
        server.delete_all_technical()
        self.assertTrue(os.path.exists(other))


class StartupFiles(unittest.TestCase):
    def setUp(self):
        self.folder = os.path.join(HOME, "Library", "LaunchAgents")
        os.makedirs(self.folder, exist_ok=True)
        for name in os.listdir(self.folder):
            os.remove(os.path.join(self.folder, name))

    def write(self, name, data):
        with open(os.path.join(self.folder, name), "wb") as handle:
            plistlib.dump(data, handle)

    def test_your_own_file_cannot_claim_a_root_helper(self):
        self.write("x.plist", {"Label": "com.fake.x", "Program": "/Library/PrivilegedHelperTools/com.example.helper"})
        found = scanners.scan_launch_items([])
        self.assertFalse([i for i in found if i.get("fix") and any(e["path"].endswith("com.example.helper") for e in i["technical"]["system_items"])])

    def test_malformed_file_is_flagged_and_later_files_still_checked(self):
        self.write("a.plist", {"Label": "a", "Program": 5})
        downloads = os.path.join(HOME, "Downloads")
        os.makedirs(downloads, exist_ok=True)
        program = os.path.join(downloads, "evil")
        open(program, "w").close()
        self.write("b.plist", {"Label": "b", "Program": program})
        titles = [i["title"] for i in scanners.scan_launch_items([])]
        self.assertTrue(any("Malformed" in t and "a.plist" in t for t in titles))
        self.assertTrue(any(t.endswith(": b") for t in titles))


class LastCopy(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp(dir=HOME)
        self.addCleanup(shutil.rmtree, self.folder)
        os.makedirs(server.DATA_DIR, exist_ok=True)
        if os.path.exists(server.MOVED_COPIES_FILE):
            os.remove(server.MOVED_COPIES_FILE)
        for name in ("move_to_trash", "recalculate", "drop_items"):
            self.addCleanup(setattr, server, name, getattr(server, name))
        server.move_to_trash = lambda p: os.remove(p)
        server.drop_items = lambda ids: None
        server.state.update(acting=False, scanning=False, scanned_at=time.time())

    def make(self, name, text="same"):
        path = os.path.join(self.folder, name)
        with open(path, "w") as handle:
            handle.write(text)
        return path

    def duplicates(self, paths, group="g"):
        server.state["actionable"] = {p: {"paths": [p], "group": group, "category": "duplicates", "size": 4, "stamp": server.file_stamp(p)} for p in paths}

    def test_personal_files_need_their_own_confirmation(self):
        paths = [self.make("a"), self.make("b")]
        self.duplicates(paths)
        self.assertEqual(server.trash_items(paths[:1])[1], 400)
        self.assertTrue(os.path.exists(paths[0]))

    def test_all_copies_refused_at_once_and_across_requests(self):
        paths = [self.make(n) for n in "abc"]
        self.duplicates(paths)
        self.assertEqual(server.trash_items(paths, True)[1], 400)
        self.assertEqual(server.trash_items(paths[:2], True)[1], 200)
        server.state["actionable"] = {paths[2]: server.state["actionable"][paths[2]]}
        self.assertEqual(server.trash_items(paths[2:], True)[1], 400)
        self.assertTrue(os.path.exists(paths[2]))

    def test_missing_copy_never_counts_as_the_one_kept(self):
        paths = [self.make("a"), self.make("b")]
        self.duplicates(paths)
        server.state["actionable"][paths[1]]["stamp"] = None
        os.remove(paths[1])
        self.assertEqual(server.trash_items(paths[:1], True)[1], 400)
        self.assertTrue(os.path.exists(paths[0]))

    def test_last_copy_stays_protected_after_a_rescan(self):
        paths = [self.make("a"), self.make("b")]
        self.duplicates(paths, group=scanners.full_hash(paths[0]))
        self.assertEqual(server.trash_items(paths[:1], True)[1], 200)
        server.state["actionable"] = {paths[1]: {"paths": [paths[1]], "group": None, "category": "large", "size": 4, "stamp": server.file_stamp(paths[1])}}
        result = server.trash_items(paths[1:], True)[0]
        self.assertIn("last one", result["results"][0]["failures"][0]["reason"])
        self.assertTrue(os.path.exists(paths[1]))

    def test_old_scans_cannot_change_anything(self):
        server.state["scanned_at"] = time.time() - 7200
        self.assertEqual(server.trash_items([], True)[1], 409)


class Paths(unittest.TestCase):
    def test_protected_and_outside_paths_are_refused(self):
        self.assertIsNotNone(server.path_problem(HOME))
        self.assertIsNotNone(server.path_problem(os.path.join(HOME, "Documents")))
        self.assertIsNotNone(server.path_problem("/etc/hosts"))
        self.assertIsNotNone(server.path_problem(HOME + "/a/../b"))
        self.assertIsNone(server.path_problem(os.path.join(HOME, "Library", "Caches", "Example")))

    def test_case_and_sensitive_folders_are_refused(self):
        for tail in ("library", "DOCUMENTS", "Library/keychains/login.keychain-db", ".ssh", ".ssh/id_ed25519", ".gnupg", "Library/Mobile Documents/x",
                     "Library/Messages/chat.db", "Library/Mail/V10", "Pictures/Photos Library.photoslibrary"):
            self.assertIsNotNone(server.path_problem(os.path.join(HOME, tail)), tail)
        self.assertIsNotNone(server.path_problem("/" + HOME + "/Documents"))


class RootCommand(unittest.TestCase):
    def test_hostile_names_are_quoted(self):
        self.addCleanup(setattr, server, "run_admin", server.run_admin)
        self.addCleanup(setattr, server, "system_item_problem", server.system_item_problem)
        commands = []
        server.run_admin = lambda c: (commands.append(c), (False, "stop"))[1]
        server.system_item_problem = lambda p: None
        server.state["scanned_at"] = time.time()
        server.state["system_items"] = {"e": {"system": [{"path": "/Library/LaunchDaemons/a$(id)'b.plist", "label": "l;touch /tmp/x"}], "user": []}}
        server.remove_system_item("e")
        self.assertIn("'l;touch /tmp/x'", commands[0])
        self.assertIn("$(id)", commands[0].split("/bin/mv -n ")[1].split("\"$HOLD\"")[0].split("'")[1])
        self.assertIn("find -d", commands[0])
        self.assertIn("-links 1", commands[0])


class PackageNames(unittest.TestCase):
    def test_option_like_names_are_refused(self):
        self.assertIsNone(server.scanners.re.fullmatch(server.PACKAGE_NAME, "--zap"))
        self.assertIsNotNone(server.scanners.re.fullmatch(server.PACKAGE_NAME, "gstreamer-runtime"))


if __name__ == "__main__":
    unittest.main()
