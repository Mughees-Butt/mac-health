# Mac Health

A private health dashboard for your own Mac. It explains what's going on in plain language, separates what needs you from what doesn't, and offers a safe fix where one exists. Results stay on your Mac.

**Status: pre-release.** Developed and tested on one Apple silicon Mac.

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

## Requirements

- macOS 13 or later
- Xcode Command Line Tools, for `swiftc` and `/usr/bin/python3`: `xcode-select --install`
- Optional: [Homebrew](https://brew.sh), for package checks and fixes

The app uses the system Python and needs no third-party packages.

## Install

**1. Create your private signing key.** This runs once and adds a key to your login keychain.

```bash
./scripts/setup-signing.sh
```

A stable signature is what lets Full Disk Access survive rebuilds.

**2. Build the app.**

```bash
./build.sh
```

macOS asks to use the key. Choose **Allow**, not Always Allow, so nothing can sign silently.

**3. Open it and grant access.** Open `Mac Health.app`, then add it under System Settings > Privacy & Security > Full Disk Access and reopen it. The app works without this, but can't see protected folders.

**4. Optional: add the terminal command.** Make sure `~/.local/bin` is on your `PATH`.

```bash
mkdir -p ~/.local/bin && ln -s "$PWD/bin/machealth" ~/.local/bin/machealth
```

## Use

```bash
machealth
```

This opens the app and starts a scan, with results in its window. `machealth --no-scan` opens your saved results.

After changing anything in `src/`, quit the app and rebuild. It refuses to run files that don't match the hashes built into it.

## Project layout

```text
bin/machealth             Terminal command
build.sh                  Builds, hashes and signs the app
scripts/setup-signing.sh  Creates the local signing key
src/app/                  Swift app window and Info.plist
src/backend/              Python checks, local server and actions
src/ui/index.html         The whole interface in one file
tests/                    Automated checks
```

Python must stay 3.9 compatible with no third-party packages, because the app runs `/usr/bin/python3`.

## Tests

```bash
/usr/bin/python3 -B tests/test_checks.py
```

The tests use a temporary home folder and a fake `brew`, so they don't touch your results or change your Mac.

To run the interface from source, without Full Disk Access, see the comments at the top of `src/backend/server.py`.

## Privacy and security

- Full Disk Access belongs to the signed app, never Terminal. Always open it through `open` or `machealth`.
- The app checks its code against built-in hashes, then passes those exact bytes to Python in memory.
- A one-time token travels the same way and is never written to disk.
- The server listens only on `127.0.0.1`, on a random port, and checks the token, Host and Origin.
- Your data stays in `~/.mac-health`, readable only by your account. Homebrew fixes go online when you ask.

**Limits:** it can't prove a Mac is free of malware. Another program running as you can see much of what you can, and could try to trick you into approving a prompt. Whether the hardened runtime actually blocks injection hasn't been tested.

## Uninstall

Delete `Mac Health.app` and `~/.mac-health`, remove the `machealth` link, and delete the `Mac Health Local Signing` key in Keychain Access.
