# Mac Health

A private health dashboard for your own Mac. It explains what's going on in plain language, separates what needs you from what doesn't, and offers a safe fix where one exists. Everything stays on your Mac.

**Status: pre-release (0.9.0).** Tested on Apple silicon with macOS 27.

## Quick start

```bash
git clone https://github.com/Mughees-Butt/mac-health.git
cd mac-health
./install.sh
```

The installer checks your Mac, creates a private signing key, builds the app, and adds the `machealth` command. It then opens the Full Disk Access settings for the last step. It's safe to run again, and `./install.sh --check` only reports what's missing.

**You need** macOS 13 or later and the Xcode Command Line Tools (`xcode-select --install`). Xcode alone isn't enough, because the app only runs the root-owned Python those tools install. [Homebrew](https://brew.sh) is optional, for package checks and fixes. Nothing else is downloaded.

**Two macOS prompts appear during setup:**
- **Using the signing key:** choose **Allow**, not Always Allow, so nothing can sign silently. This appears on every build.
- **Mac Health keeping its encryption key:** allow it for Mac Health. Deny any other program asking for `Mac Health saved results`.

**Last step:** add Mac Health under System Settings > Privacy & Security > Full Disk Access. It works without this, but can't see protected folders.

## Use

```bash
machealth            # open and scan
machealth --no-scan  # open your saved results
```

Or open `Mac Health.app` from the folder.

## What it checks

| Page | What you get |
|---|---|
| Overview | Health score, what lowered it, disk, memory, processor, battery, updates, protections |
| Alerts | Unsigned or damaged apps, apps in unusual places, suspicious startup items |
| Leftovers | Files and startup items from apps you've removed |
| Cleanup | Large caches and logs, old installers, long-unused apps |
| Developer | Homebrew updates, rebuildable tool data, stale `node_modules` |
| Files | Very large files and exact duplicates |
| Startup | What starts on its own, when it runs, memory used |
| Network | What's listening and what's connected out |
| Next steps | What to do next, or a clear sign that nothing is needed |
| History, Access, Technical | Trends, what the app can and can't do, raw readings that expire |

Removals go to Trash. Admin actions use macOS's own password prompt, and Homebrew fixes run visibly in Terminal.

## Privacy and security

- Full Disk Access belongs to the signed app, never Terminal. Always open it through `open` or `machealth`.
- The app checks its code against hashes built into it, then runs those exact bytes in memory.
- The dashboard's server listens only on `127.0.0.1` and checks a one-time token that's never written to disk.
- Your data stays in `~/.mac-health`. Results and logs that name your files are encrypted, with the key in your keychain. Scores and disk trends aren't.

| Part | Has | Why |
|---|---|---|
| Mac Health | Full Disk Access | To read protected folders during a scan |
| Homebrew and Docker checks | No Full Disk Access | Your account can change them, so they run as a separate job, and only after the app proves that job lacks access |
| Removing system files | Admin, once | macOS asks each time, and the app lists the files first |
| Terminal fixes | What Terminal has | So you can see each command, and only macOS sees your password |

**Limits**
- **It can't prove a Mac is free of malware.** A clean result means nothing looked wrong, not that nothing is wrong.
- **Other programs running as you can see what you can.** macOS doesn't separate programs in one account, except for protected folders. While a scan runs, they could see file paths in the process list.
- **Someone could try to trick you into approving a prompt.** Read what's listed, and cancel anything you didn't start.
- **A program running as you could change this source before you build it,** or replace the encryption key item with one trusting only Mac Health.

To report a security problem, see [SECURITY.md](SECURITY.md).

## Development

```text
install.sh                  One-step setup
build.sh                    Builds, hashes and signs the app
bin/machealth               Terminal command
scripts/setup-signing.sh    Creates the local signing key
scripts/uninstall.sh        Removes Mac Health, asking at each step
src/app/                    Swift app window and Info.plist
src/backend/                Python checks, local server and actions
src/ui/index.html           The whole interface, in one file
tests/                      Automated checks
```

After changing anything in `src/`, quit the app and run `./build.sh`. The app refuses to run files that don't match its built-in hashes. Python must stay 3.9 compatible, with no third-party packages.

```bash
for t in tests/test_*.py; do /usr/bin/python3 -B "$t" || break; done
```

The tests use a temporary home folder and a fake `brew`, so they don't touch your results. To run the interface from source without Full Disk Access, see the comment at the top of `src/backend/server.py`.

## Uninstall

```bash
./scripts/uninstall.sh
```

Then remove Mac Health from System Settings > Privacy & Security > Full Disk Access.

## License

[MIT](LICENSE)
