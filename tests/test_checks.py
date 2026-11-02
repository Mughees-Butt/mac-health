"""Checks for the behaviour most likely to mislead someone: false all-clears and unsafe removals.
They use a temporary home folder and a fake brew, so they don't touch real results or change the Mac."""
import os
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
        server.state.update(reinstall={}, brew_ids=set(), tech={}, system_items={}, acting=False, scanning=False)

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


class Paths(unittest.TestCase):
    def test_protected_and_outside_paths_are_refused(self):
        self.assertIsNotNone(server.path_problem(HOME))
        self.assertIsNotNone(server.path_problem(os.path.join(HOME, "Documents")))
        self.assertIsNotNone(server.path_problem("/etc/hosts"))
        self.assertIsNotNone(server.path_problem(HOME + "/a/../b"))
        self.assertIsNone(server.path_problem(os.path.join(HOME, "Library", "Caches", "Example")))


if __name__ == "__main__":
    unittest.main()
