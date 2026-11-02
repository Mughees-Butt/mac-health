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
- Xcode Command Line Tools, for `swiftc` and Python: `xcode-select --install`. Xcode alone isn't enough, because the app only runs the root-owned Python these tools install.
- Optional: [Homebrew](https://brew.sh), for package checks and fixes

The app needs no third-party packages.

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

After each rebuild, macOS also asks whether Mac Health may use `Mac Health saved results`, the key that encrypts its saved data, because it's a new build. Allow it for Mac Health. If you don't, earlier results are kept as they are and nothing new is saved until you allow it. Deny any other program asking for that item.

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

Python must stay 3.9 compatible with no third-party packages, because the app runs the Command Line Tools' Python.

## Tests

```bash
for t in tests/test_*.py; do /usr/bin/python3 -B "$t" || break; done
```

The tests use a temporary home folder and a fake `brew`, so they don't touch your results or change your Mac.

To run the interface from source, without Full Disk Access, see the comments at the top of `src/backend/server.py`.

## Privacy and security

- Full Disk Access belongs to the signed app, never Terminal. Always open it through `open` or `machealth`.
- The app checks its code against built-in hashes, then passes those exact bytes to Python in memory.
- A one-time token travels the same way and is never written to disk.
- The server listens only on `127.0.0.1`, on a random port, and checks the token, Host and Origin.
- Your data stays in `~/.mac-health`. Results and logs that name your files are encrypted, with the key in your keychain, tied to the signed app. Scores and disk trends in `history.jsonl` aren't encrypted. Homebrew fixes go online when you ask.

### What has which access

| Part | Has | Why |
|---|---|---|
| Mac Health | Full Disk Access | To read protected folders during a scan |
| Homebrew and Docker checks | No Full Disk Access | Your account can change them, so they run as a separate job. If the app can't prove that job lacks access, they don't run. |
| Removing system files | Admin, once | macOS asks each time, and the app lists the files first |
| Terminal fixes | What Terminal has | So you can see each command and only macOS sees your password |

### Limits

- **It can't prove a Mac is free of malware.** A clean result means nothing looked wrong, not that nothing is wrong.
- **Other programs running as you can see what you can.** macOS doesn't separate programs in one account, except for protected folders. Saved results that name your files are encrypted, but while a scan runs, a program could still see file paths in the process list.
- **Someone could try to trick you into approving a prompt.** Read what's listed, and cancel anything you didn't start.
- **A program running as you could change this source before you build it.** The build uses a clean environment, but can't prevent that.

Tested: injecting a library into the signed app was blocked, and attaching to it or its Python process was refused from a normal program.

## Uninstall

Delete `Mac Health.app` and `~/.mac-health`, remove the `machealth` link, and delete the `Mac Health Local Signing` key and the `Mac Health saved results` item in Keychain Access.
