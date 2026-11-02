"""Checks for scanner rough edges: unfinished checks in the score, startup wrappers and tool folders,
parallel startup checks, and leftovers from apps on unplugged drives.
They use a temporary home folder and fake system calls, so they don't touch real results or change the Mac."""
import os
import plistlib
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


def healthy_cards():
    return {"disk": {"used_pct": 40}, "memory": {"free_pct": 50}, "cpu": {"busy_pct": 5, "recent_scan": False},
            "security": {"filevault": True, "gatekeeper": True, "sip": True, "firewall": True},
            "updates": [], "battery": None, "uptime_days": 1}


def empty_sections():
    return {"alerts": []}


class Score(unittest.TestCase):
    def test_without_coverage_stays_backward_compatible(self):
        self.assertEqual(scanners.build_score(healthy_cards(), empty_sections())[0], 100)
        self.assertEqual(scanners.build_score(healthy_cards(), empty_sections(), [])[0], 100)

    def test_unfinished_check_stops_full_health(self):
        coverage = [{"area": "App list", "status": "partial"}, {"area": "Network", "status": "failed"}]
        score, deductions = scanners.build_score(healthy_cards(), empty_sections(), coverage)
        self.assertLess(score, 100)
        self.assertTrue(any(d["reason"] == "2 checks didn't finish" for d in deductions))

    def test_deduction_is_capped(self):
        coverage = [{"area": "x%d" % n, "status": "failed"} for n in range(20)]
        score, _ = scanners.build_score(healthy_cards(), empty_sections(), coverage)
        self.assertEqual(score, 90)

    def test_full_disk_access_blocks_count_once(self):
        coverage = [{"area": "~/Library/%s" % n, "status": "blocked", "fix": "fda"} for n in ("Caches", "Cookies", "Logs")]
        coverage.append({"area": "~/Downloads", "status": "blocked", "fix": "fda"})
        score, deductions = scanners.build_score(healthy_cards(), empty_sections(), coverage)
        self.assertEqual(score, 98)
        self.assertTrue(any(d["reason"] == "1 check didn't finish" for d in deductions))

    def test_protected_data_note_is_not_unfinished(self):
        coverage = [{"area": "Protected app data", "status": "partial", "fix": "fda"}]
        self.assertEqual(scanners.build_score(healthy_cards(), empty_sections(), coverage)[0], 100)

    def test_complete_status_is_not_penalised(self):
        coverage = [{"area": "Anything", "status": "ok"}]
        self.assertEqual(scanners.build_score(healthy_cards(), empty_sections(), coverage)[0], 100)


class StartupBase(unittest.TestCase):
    def setUp(self):
        self.folder = os.path.join(HOME, "Library", "LaunchAgents")
        os.makedirs(self.folder, exist_ok=True)
        for name in os.listdir(self.folder):
            os.remove(os.path.join(self.folder, name))
        self.addCleanup(setattr, scanners, "signature_info", scanners.signature_info)
        self.addCleanup(setattr, scanners, "launchd_state", scanners.launchd_state)
        scanners.signature_info = lambda path: {"status": "signed", "authority": None, "team": None}
        scanners.launchd_state = lambda label: {"loaded": False}

    def write(self, name, data):
        with open(os.path.join(self.folder, name), "wb") as handle:
            plistlib.dump(data, handle)

    def program(self, *parts):
        """A real file, so the scan doesn't treat it as a missing program."""
        path = os.path.join(HOME, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").close()
        return path

    def scan(self):
        # Only the user's own folder, so the real /Library files don't change the results.
        return [i for i in scanners.scan_launch_items([]) if any(p.startswith(self.folder) for p in i["paths"]) or
                any(e.get("path", "").startswith(self.folder) for e in i["technical"].get("entries", []))]

    def titles(self):
        return [i["title"] for i in self.scan()]


class Wrappers(StartupBase):
    def test_env_with_options_and_assignments_reaches_the_script_runner(self):
        self.write("a.plist", {"Label": "a", "ProgramArguments": ["/usr/bin/env", "-i", "FOO=1", "BAR=2", "python3", "/opt/x.py"]})
        self.assertIn("Startup item runs a script: a", self.titles())

    def test_env_dash_s_string_reaches_the_script_runner(self):
        self.write("a.plist", {"Label": "a", "ProgramArguments": ["/usr/bin/env", "-S", "perl -w", "/opt/x.pl"]})
        self.assertIn("Startup item runs a script: a", self.titles())

    def test_env_dash_u_takes_a_value(self):
        self.write("a.plist", {"Label": "a", "ProgramArguments": ["/usr/bin/env", "-u", "PATH", "ruby", "/opt/x.rb"]})
        self.assertIn("Startup item runs a script: a", self.titles())

    def test_nohup_and_env_together(self):
        self.write("a.plist", {"Label": "a", "ProgramArguments": ["/usr/bin/nohup", "/usr/bin/env", "node", "/opt/x.js"]})
        self.assertIn("Startup item runs a script: a", self.titles())

    def test_program_key_with_env_uses_arguments(self):
        self.write("a.plist", {"Label": "a", "Program": "/usr/bin/env", "ProgramArguments": ["env", "bash", "/opt/x.sh"]})
        self.assertIn("Startup item runs a script: a", self.titles())

    def test_env_wrapping_a_program_in_downloads_is_unusual(self):
        downloads = os.path.join(HOME, "Downloads")
        os.makedirs(downloads, exist_ok=True)
        program = os.path.join(downloads, "evil")
        open(program, "w").close()
        self.write("a.plist", {"Label": "a", "ProgramArguments": ["/usr/bin/env", "-i", "X=1", program]})
        self.assertIn("Startup item runs from an unusual location: a", self.titles())

    def test_nohup_wrapping_a_hidden_program_is_unusual(self):
        self.write("a.plist", {"Label": "a", "ProgramArguments": ["/usr/bin/nohup", os.path.join(HOME, ".hidden", "agent")]})
        self.assertIn("Startup item runs from an unusual location: a", self.titles())

    def test_sh_dash_c_running_from_tmp_is_unusual(self):
        self.write("a.plist", {"Label": "a", "ProgramArguments": ["/bin/sh", "-c", "/tmp/payload --quiet"]})
        self.assertIn("Startup item runs from an unusual location: a", self.titles())

    def test_sh_dash_c_elsewhere_is_still_a_script(self):
        self.write("a.plist", {"Label": "a", "ProgramArguments": ["/bin/sh", "-c", "/opt/tool --quiet"]})
        self.assertIn("Startup item runs a script: a", self.titles())

    def test_plain_env_tool_is_not_flagged(self):
        self.write("a.plist", {"Label": "a", "ProgramArguments": ["/usr/bin/env", "-i", "/usr/bin/true"]})
        self.assertEqual(self.titles(), [])

    def test_bare_env_does_not_break(self):
        self.write("a.plist", {"Label": "a", "ProgramArguments": ["/usr/bin/env", "-i", "FOO=1"]})
        self.write("b.plist", {"Label": "b", "ProgramArguments": ["/usr/bin/env", 5, "python3"]})
        self.assertIn("Startup item runs a script: b", self.titles())


class ToolFolders(StartupBase):
    def test_known_tool_folders_are_not_unusual(self):
        for n, folder in enumerate((".local/bin", ".cargo/bin", ".nvm/versions/node/v20/bin", ".bun/bin",
                                    ".deno/bin", ".volta/bin", ".npm-global/bin")):
            self.write("t%d.plist" % n, {"Label": "t%d" % n, "Program": self.program(folder, "tool")})
        self.assertFalse([t for t in self.titles() if "unusual location" in t])

    def test_other_hidden_folders_are_still_unusual(self):
        self.write("a.plist", {"Label": "a", "Program": self.program(".config", "x", "agent")})
        self.write("b.plist", {"Label": "b", "Program": self.program(".cargo", "bin", ".sneaky", "agent")})
        self.write("c.plist", {"Label": "c", "Program": self.program(".cargo-evil", "bin", "agent")})
        titles = self.titles()
        for label in ("a", "b", "c"):
            self.assertIn("Startup item runs from an unusual location: %s" % label, titles)

    def test_tool_folder_does_not_hide_an_unsigned_program(self):
        scanners.signature_info = lambda path: {"status": "unsigned", "authority": None, "team": None}
        self.write("a.plist", {"Label": "a", "Program": self.program(".cargo", "bin", "tool")})
        self.assertIn("Startup item with no developer signature: a", self.titles())


class Parallel(StartupBase):
    def test_checks_overlap_and_keep_file_order(self):
        active, peak, lock = [0], [0], threading.Lock()

        def slow_signature(path):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.2)
            with lock:
                active[0] -= 1
            return {"status": "unsigned", "authority": None, "team": None}

        scanners.signature_info = slow_signature
        for n in range(6):
            self.write("p%d.plist" % n, {"Label": "p%d" % n, "Program": self.program("bin", "p%d" % n)})
        self.write("p2x.plist", {"Label": "bad", "Program": 5})
        titles = self.titles()
        self.assertGreater(peak[0], 1)
        expected = ["Startup item with no developer signature: p0", "Startup item with no developer signature: p1",
                    "Startup item with no developer signature: p2", "Malformed startup item: p2x.plist",
                    "Startup item with no developer signature: p3", "Startup item with no developer signature: p4",
                    "Startup item with no developer signature: p5"]
        self.assertEqual(titles, expected)

    def test_unreadable_file_is_flagged_among_parallel_checks(self):
        with open(os.path.join(self.folder, "a.plist"), "wb") as handle:
            handle.write(b"not a plist")
        self.write("b.plist", {"Label": "b", "ProgramArguments": ["/usr/bin/env", "python3", "x.py"]})
        titles = self.titles()
        self.assertEqual(titles, ["Unreadable startup item: a.plist", "Startup item runs a script: b"])

    def test_orphans_get_launchd_state(self):
        scanners.launchd_state = lambda label: {"loaded": True, "state": "running"}
        self.write("o.plist", {"Label": "com.gone.thing", "Program": "/Applications/Gone.app/Contents/MacOS/Gone"})
        rows = [i for i in self.scan() if i["category"] == "leftovers"]
        self.assertEqual(len(rows), 1)
        self.assertIn("One is running", rows[0]["plain"])
        self.assertEqual(rows[0]["technical"]["entries"][0]["launchd"]["state"], "running")

    def test_check_error_still_reaches_the_caller(self):
        def broken(path):
            raise RuntimeError("codesign broke")
        scanners.signature_info = broken
        self.write("a.plist", {"Label": "a", "Program": self.program("bin", "a")})
        with self.assertRaises(RuntimeError):
            scanners.scan_launch_items([])


class UnpluggedDrive(unittest.TestCase):
    def setUp(self):
        self.support = os.path.join(HOME, "Library", "Application Support")
        self.dock = os.path.join(HOME, "Library", "Preferences", "com.apple.dock.plist")
        os.makedirs(os.path.dirname(self.dock), exist_ok=True)
        folder = os.path.join(self.support, "com.qzxvendor.qzxwidget")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "data.bin"), "wb") as handle:
            handle.write(b"x" * 1024)
        old = time.time() - 200 * scanners.DAY
        for path in (os.path.join(folder, "data.bin"), folder):
            os.utime(path, (old, old))
        self.addCleanup(shutil.rmtree, folder)
        self.addCleanup(lambda: os.path.exists(self.dock) and os.remove(self.dock))

    def row(self, apps):
        rows = [r for r in scanners.scan_leftovers(apps, []) if r["technical"].get("identifier") == "com.qzxvendor.qzxwidget"]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_no_external_apps_keeps_very_likely(self):
        row = self.row([])
        self.assertEqual(row["confidence"], "very likely")
        self.assertNotIn("external drive", row["plain"])

    def test_app_on_a_plugged_in_drive_lowers_confidence(self):
        apps = [{"path": "/Volumes/Backup/Other.app", "name": "Other", "bundle_id": "com.other.app"}]
        row = self.row(apps)
        self.assertEqual(row["confidence"], "likely")
        self.assertIn("isn't plugged in", row["plain"])

    def test_dock_app_on_an_unplugged_drive_lowers_confidence(self):
        tile = {"tile-data": {"file-data": {"_CFURLString": "file:///Volumes/Gone/QzxWidget.app/", "_CFURLStringType": 15}}}
        with open(self.dock, "wb") as handle:
            plistlib.dump({"persistent-apps": [tile]}, handle)
        self.assertEqual(self.row([])["confidence"], "likely")

    def test_damaged_dock_file_is_ignored(self):
        with open(self.dock, "wb") as handle:
            handle.write(b"garbage")
        self.assertEqual(self.row([])["confidence"], "very likely")


if __name__ == "__main__":
    unittest.main()
