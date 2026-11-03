"""Checks for server rough edges: reinstalling a running app, the system-item log, settings saves, forged log lines.
They use a temporary home folder and fake commands, so they don't touch real results or change the Mac."""
import os
import json
import secrets
import shutil
import sys
import tempfile
import threading
import time
import unittest

HOME = os.path.realpath(tempfile.mkdtemp())
os.environ["HOME"] = HOME
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "backend"))

import scanners  # noqa: E402
import server  # noqa: E402


def patch(test, owner, name, value):
    test.addCleanup(setattr, owner, name, getattr(owner, name))
    setattr(owner, name, value)


def temp_folder(test):
    folder = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, folder, True)
    return folder


class ReinstallRunningApp(unittest.TestCase):
    def setUp(self):
        self.commands = []
        self.ran = []
        patch(self, server, "open_terminal_script", self.commands.append)
        patch(self, server, "find_brew", lambda: "/fake/brew")
        self.code = 1
        patch(self, scanners, "run", lambda cmd, **k: (self.ran.append(cmd), (self.code, ""))[1])
        self.addCleanup(server.state.update, reinstall=server.state["reinstall"], scanned_at=server.state["scanned_at"])
        server.state.update(reinstall={}, scanned_at=time.time())

    def add(self, path):
        server.state["reinstall"]["a"] = {"token": "clipy", "installed": True, "path": path}

    def test_running_app_is_refused(self):
        self.add("/Applications/Clipy.app")
        self.code = 0
        data, code = server.brew_reinstall_in_terminal("a")
        self.assertEqual(code, 409)
        self.assertEqual(data["error"], "Quit Clipy first, then try again.")
        self.assertEqual(self.commands, [])
        self.assertEqual(self.ran[0][:2], ["/usr/bin/pgrep", "-f"])

    def test_app_not_running_opens_terminal(self):
        self.add("/Applications/Clipy.app")
        self.assertEqual(server.brew_reinstall_in_terminal("a")[1], 200)
        self.assertIn("reinstall --cask clipy", self.commands[0][0])

    def test_failed_check_does_not_open_terminal(self):
        self.add("/Applications/Clipy.app")
        self.code = 2
        self.assertEqual(server.brew_reinstall_in_terminal("a")[1], 409)
        self.assertEqual(self.commands, [])

    def test_pattern_matches_only_this_bundle_literally(self):
        self.add("/Applications/My App (1).app")
        server.brew_reinstall_in_terminal("a")
        self.assertEqual(self.ran[0][2], r"^/Applications/My App \(1\)\.app/Contents/MacOS/")

    def test_missing_or_odd_path_is_refused(self):
        for path in (None, "", "Clipy.app", "/Applications/../tmp/Clipy.app", "/Applications/Clipy", 5):
            self.add(path)
            self.assertEqual(server.brew_reinstall_in_terminal("a")[1], 400, path)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.ran, [])

    def test_real_pgrep_finds_a_running_app(self):
        patch(self, scanners, "run", ReinstallRunningApp.real_run)
        self.add("/System/Library/CoreServices/Finder.app")
        self.assertEqual(server.brew_reinstall_in_terminal("a"), ({"error": "Quit Finder first, then try again."}, 409))
        self.add("/Applications/No Such Mac Health App.app")
        self.assertEqual(server.brew_reinstall_in_terminal("a")[1], 200)


ReinstallRunningApp.real_run = staticmethod(scanners.run)


class ScanKeepsAppPath(unittest.TestCase):
    def test_reinstall_entry_includes_the_app_path(self):
        os.makedirs(server.DATA_DIR, exist_ok=True)
        saved = dict(server.state)
        self.addCleanup(server.state.update, saved)
        sections = {k: [] for k in ("alerts", "leftovers", "clutter", "developer", "large", "duplicates", "network", "startup")}
        sections["alerts"].append({
            "id": "a1", "category": "alerts", "severity": "low", "group": None, "size": None, "trashable": False, "paths": [],
            "technical": {"path": "/Applications/Clipy.app", "reinstall": {"token": "clipy", "installed": False}}})
        report = {"generated_at": int(time.time()), "tips": [], "sections": sections, "coverage": [], "score": 100,
                  "cards": {"disk": {"used": 1, "total": 2}}, "access": {"full_disk_access": True}, "meta": {"raw": ""}}
        patch(self, scanners, "full_scan", lambda progress, last_scan=None: report)
        server.do_scan()
        self.assertIsNone(server.state["error"])
        self.assertEqual(server.state["reinstall"]["a1"], {"token": "clipy", "installed": False, "path": "/Applications/Clipy.app"})


class SystemItemLog(unittest.TestCase):
    def test_log_names_the_original_path(self):
        folder = temp_folder(self)
        patch(self, server, "ACTIONS_FILE", os.path.join(folder, "actions.jsonl"))
        patch(self, server, "system_item_problem", lambda p: None)
        patch(self, server, "move_to_trash", lambda p: os.remove(p))
        patch(self, server, "drop_items", lambda ids: None)
        hold = "/private/tmp/machealth." + secrets.token_hex(6)

        def run_admin(command):
            os.mkdir(hold)
            open(os.path.join(hold, "com.example.test.plist"), "w").close()
            return True, hold + "\n"
        patch(self, server, "run_admin", run_admin)
        self.addCleanup(shutil.rmtree, hold, True)
        self.addCleanup(server.state.update, system_items=server.state["system_items"], scanned_at=server.state["scanned_at"])
        original = "/Library/LaunchDaemons/com.example.test.plist"
        server.state.update(scanned_at=time.time(), system_items={"x": {"system": [{"path": original, "label": None}], "user": []}})
        self.assertEqual(server.remove_system_item("x")[1], 200)
        rows = server.read_jsonl(server.ACTIONS_FILE)
        self.assertEqual([(r["action"], r["path"]) for r in rows], [("removed_system_item", original)])


class SettingsLock(unittest.TestCase):
    def test_concurrent_saves_keep_every_change(self):
        folder = temp_folder(self)
        patch(self, server, "SETTINGS_FILE", os.path.join(folder, "settings.json"))
        real_read = server.read_json

        def slow_read(path, fallback):
            value = real_read(path, fallback)
            time.sleep(0.05)  # widens the gap between reading and writing
            return value
        patch(self, server, "read_json", slow_read)
        threads = [threading.Thread(target=server.set_setting, args=("key%d" % n, n)) for n in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        with open(server.SETTINGS_FILE) as handle:
            self.assertEqual(json.load(handle), {"key%d" % n: n for n in range(5)})


class ForgedActionLines(unittest.TestCase):
    def setUp(self):
        folder = temp_folder(self)
        patch(self, server, "ACTIONS_FILE", os.path.join(folder, "actions.jsonl"))
        self.history = os.path.join(folder, "history.jsonl")

    def test_plain_line_is_ignored(self):
        now = time.time()
        server.append_jsonl(server.ACTIONS_FILE, {"t": now, "path": "/real"})
        with open(server.ACTIONS_FILE, "a") as handle:
            handle.write(json.dumps({"t": now, "path": "/forged"}) + "\n")
            handle.write(server.seal(json.dumps({"t": now, "path": "/other-use"}), "report") + "\n")
        self.assertEqual([r["path"] for r in server.read_jsonl(server.ACTIONS_FILE)], ["/real"])

    def test_prune_never_seals_a_forged_line(self):
        now = time.time()
        server.append_jsonl(server.ACTIONS_FILE, {"t": now - 60 * server.DAY, "path": "/old"})
        server.append_jsonl(server.ACTIONS_FILE, {"t": now, "path": "/real"})
        with open(server.ACTIONS_FILE, "a") as handle:
            handle.write(json.dumps({"t": now, "path": "/forged"}) + "\n")
        server.prune_jsonl(server.ACTIONS_FILE, 30)
        with open(server.ACTIONS_FILE) as handle:
            lines = handle.read().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith(server.SEALED_MARK))
        self.assertEqual([r["path"] for r in server.read_jsonl(server.ACTIONS_FILE)], ["/real"])

    def test_history_still_reads_plain_rows(self):
        server.append_jsonl(self.history, {"t": time.time(), "score": 90})
        self.assertEqual(len(server.read_jsonl(self.history)), 1)

    def test_without_the_key_the_log_is_left_alone(self):
        server.append_jsonl(server.ACTIONS_FILE, {"t": 0, "path": "/expired"})
        with open(server.ACTIONS_FILE) as handle:
            before = handle.read()
        patch(self, server, "HAS_KEY", False)
        server.prune_jsonl(server.ACTIONS_FILE, 30)
        with open(server.ACTIONS_FILE) as handle:
            self.assertEqual(handle.read(), before)



class LastCopyLeavesList(unittest.TestCase):
    def test_copy_left_alone_leaves_the_duplicates_list(self):
        self.addCleanup(setattr, server, "recalculate", server.recalculate)
        server.recalculate = lambda report: None
        dup = lambda i, g: {"id": i, "group": g}
        server.state["report"] = {"sections": {"duplicates": [dup("a", "g1"), dup("b", "g1"), dup("c", "g2"), dup("d", "g2"), dup("e", "g2")]}}
        server.state["actionable"] = {k: {} for k in "abcde"}
        server.drop_items(["a", "c"])
        self.assertEqual([e["id"] for e in server.state["report"]["sections"]["duplicates"]], ["d", "e"])
        self.assertNotIn("b", server.state["actionable"])
        server.state["report"] = None



class RescanFindings(unittest.TestCase):
    """Regression tests for the claude-security rescan of 2026-11-02."""

    def test_only_root_protected_files_count_as_protected(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        mine = os.path.join(folder, "mine.plist")
        open(mine, "w").close()
        self.assertFalse(scanners.protected_by_root(mine))
        self.assertTrue(scanners.protected_by_root("/bin/sh"))
        self.assertFalse(scanners.protected_by_root(os.path.join(folder, "missing")))
        link = os.path.join(folder, "link")
        os.symlink("/bin/sh", link)  # points at a root file, but a link is never trusted
        self.assertFalse(scanners.protected_by_root(link))

    def test_admin_removal_refuses_a_file_your_account_owns(self):
        folder = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder)
        self.addCleanup(setattr, server, "SYSTEM_REMOVABLE_DIRS", server.SYSTEM_REMOVABLE_DIRS)
        server.SYSTEM_REMOVABLE_DIRS = {folder: ".plist"}
        path = os.path.join(folder, "x.plist")
        open(path, "w").close()
        self.assertIn("isn't protected", server.system_item_problem(path))

    def test_old_plain_log_lines_are_rewritten_away(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        self.addCleanup(setattr, server, "ACTIONS_FILE", server.ACTIONS_FILE)
        server.ACTIONS_FILE = os.path.join(folder, "actions.jsonl")
        with open(server.ACTIONS_FILE, "w") as handle:
            handle.write(json.dumps({"t": time.time(), "path": "/old/Secret.mov"}) + "\n")
        server.append_jsonl(server.ACTIONS_FILE, {"t": time.time(), "path": "/new/Secret.mov"})
        server.prune_jsonl(server.ACTIONS_FILE, 30)
        with open(server.ACTIONS_FILE) as handle:
            text = handle.read()
        self.assertNotIn("Secret", text)
        self.assertEqual([r["path"] for r in server.read_jsonl(server.ACTIONS_FILE)], ["/new/Secret.mov"])


if __name__ == "__main__":
    unittest.main()
