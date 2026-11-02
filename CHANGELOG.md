# Changelog

## 0.9.0 · pre-release

First shareable version, tested on one Apple silicon Mac.

**What it does**
- Health score with the reasons behind it, plus disk, memory, processor, battery, updates and protections
- Alerts for unsigned, damaged or unusually placed apps and suspicious startup items
- Leftovers from removed apps, temporary files, developer data, large files and exact duplicates
- What starts on its own and what's using the network
- Next steps, history, and a technical summary that deletes itself
- Safe fixes: Move to Trash, Homebrew updates and reinstalls in Terminal, and removing system leftovers through macOS's own password prompt

**Security**
- Full Disk Access belongs to the signed app only. It runs only code matching hashes built into it.
- Programs your account can change, such as `brew`, run separately without that access.
- Saved results that name your files are encrypted, with the key in your keychain.
- The local server checks a one-time token, Host and Origin.
- Reviewed by parallel security reviews, live attack tests and a `claude-security` scan, with every finding fixed.

**Setup**
- `./install.sh` sets everything up from a fresh clone. `./install.sh --check` only reports what's missing.
