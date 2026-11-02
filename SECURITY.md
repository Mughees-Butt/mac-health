# Security

Mac Health holds Full Disk Access, so security problems matter more than usual.

## Reporting

Please report problems privately through this repository's **Security** tab, using "Report a vulnerability", rather than a public issue. Include the steps to reproduce and what an attacker gains.

## What's in scope

- A program running as you gaining something through Mac Health that it couldn't get alone: protected folders, admin rights, or a signature from your key
- Mac Health deleting, moving or exposing something it shouldn't
- Anything a website can do to the local server

## Known limits

These are described in the README and aren't treated as vulnerabilities:
- Programs running as you can read your ordinary files, and see file paths in the process list during a scan
- A program running as you can change the source before you build it, or replace the encryption key item with one trusting only Mac Health. If your saved results then can't be opened, the Access page says the key changed.
- Someone could trick you into approving a macOS prompt
