# SHA-256 File Integrity Verification System

A Python-based cryptographic tool that uses **SHA-256 hashing** and **HMAC signing** to detect unauthorized file modifications, deletions, or additions — with both a CLI and a Tkinter GUI.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Project](#running-the-project)
  - [1. CLI — Generate Baseline](#1-cli--generate-baseline)
  - [2. CLI — Verify Integrity](#2-cli--verify-integrity)
  - [3. GUI](#3-gui)
  - [4. Demo (Scripted Attack Simulation)](#4-demo-scripted-attack-simulation)
  - [5. Test Suite](#5-test-suite)
- [All CLI Commands](#all-cli-commands)
- [How It Works](#how-it-works)
- [Security Notes](#security-notes)

---

## Overview

This project implements a **file integrity checker** as part of an Applied Cryptography course assignment. It computes SHA-256 digests for tracked files, stores them in an HMAC-signed JSON store (`hashes.json`), and reports any tampering — including modification, deletion, or new unauthorized files.

---

## Features

| Feature | Detail |
|---|---|
| Hash algorithm | SHA-256 via `hashlib` (streamed in 1 MB chunks) |
| Tamper detection | `MODIFIED`, `MISSING`, `NEW`, `UNKNOWN` statuses |
| Store integrity | HMAC-signed `hashes.json`; tampering with the store itself is detected |
| Constant-time comparison | `hmac.compare_digest` to prevent timing attacks |
| Reports | HTML / JSON / TXT export |
| GUI | Tkinter-based graphical interface |
| Audit trail | `integrity.log` |
| Exit codes | `0` = clean, `1` = tampered files, `2` = store tampered (scriptable) |

---

## Project Structure

```
applied-cryptography-project/
├── integrity.py        # Core logic + CLI
├── gui.py              # Tkinter GUI
├── demo.py             # Scripted attack demonstration
├── test_integrity.py   # Unit test suite
├── requirements.txt    # Dependencies (stdlib only)
├── hashes.json         # Generated hash store (after first run)
├── integrity.log       # Audit log (auto-created)
├── .integrity.key      # HMAC key (auto-generated or set via env)
├── docs/               # Sample folder used in demo/tests
└── testdir/            # Test assets
```

---

## Prerequisites

- **Python 3.8+**
- **Tkinter** (for GUI only — usually bundled with Python)

Verify:

```bash
python --version
# Python 3.x.x

python -c "import tkinter; print('Tkinter OK')"
```

> On Ubuntu/Debian, if Tkinter is missing:
> ```bash
> sudo apt install python3-tk
> ```

---

## Installation

```bash
git clone https://github.com/adityacyan/applied-cryptography-project.git
cd applied-cryptography-project

# No third-party packages needed — stdlib only
# Optionally confirm:
pip install -r requirements.txt
```

---

## Running the Project

### 1. CLI — Generate Baseline

Record SHA-256 hashes for all files in a directory:

```bash
python integrity.py generate docs/
```

With multiple targets and an exclusion pattern:

```bash
python integrity.py generate docs/ file.txt -x "*.tmp"
```

This creates/updates `hashes.json` and signs it with an HMAC key.

---

### 2. CLI — Verify Integrity

Check all tracked files against the stored baseline:

```bash
python integrity.py verify
```

Each file will be reported as:

| Status | Meaning |
|---|---|
| `OK` | Unchanged |
| `MODIFIED` | Content has changed |
| `MISSING` | File was deleted |
| `NEW` | Untracked file appeared in a monitored folder |
| `UNKNOWN` | Not in baseline, not in a monitored folder |

Generate an HTML report alongside:

```bash
python integrity.py verify --report report.html
```

Exit codes: `0` = all intact · `1` = tampering · `2` = hash store tampered

---

### 3. GUI

Launch the Tkinter graphical interface:

```bash
python gui.py
```

> Requires Tkinter. See [Prerequisites](#prerequisites) if it's missing.

---

### 4. Demo (Scripted Attack Simulation)

Runs a scripted demonstration that simulates file tampering attacks and shows detection:

```bash
python demo.py
```

---

### 5. Test Suite

Run all unit tests:

```bash
python -m unittest -v
```

---

## All CLI Commands

```bash
# Generate baseline for files/folders (skip patterns with -x)
python integrity.py generate docs/ file.txt -x "*.tmp"

# Verify all tracked files
python integrity.py verify

# Verify and export a report (supports .html, .json, .txt)
python integrity.py verify --report report.html

# Accept an authorised change (update hash for one file)
python integrity.py update file.txt

# List all tracked files
python integrity.py list

# Remove a file from tracking
python integrity.py remove <path>

# Show audit log
python integrity.py log

# Print SHA-256 hash of a specific file
python integrity.py hash <file>
```

---

## How It Works

```
Files  →  SHA-256 (1 MB streaming chunks)  →  hashes.json
                                                   ↓
                                            HMAC-SHA256 signed
                                            (key: .integrity.key
                                             or INTEGRITY_KEY env var)
                                                   ↓
                              verify  →  recompute + hmac.compare_digest
                                                   ↓
                              OK / MODIFIED / MISSING / NEW / UNKNOWN
```

---

## Security Notes

- **Keep the HMAC key separate from the hash store.** If an attacker can rewrite both `hashes.json` and `.integrity.key`, tampering goes undetected.
- Set the key via environment variable for production use:
  ```bash
  export INTEGRITY_KEY="your-secret-key"
  ```
- Baseline must be generated from a **trusted, clean state** — changes made before `generate` is run will not be detected.
- Even a **single-bit change** produces a completely different SHA-256 digest (avalanche effect).

---

## References

- [hashlib — Python Docs](https://docs.python.org/3/library/hashlib.html)
- [hmac — Python Docs](https://docs.python.org/3/library/hmac.html)
- Full design details: [REPORT.md](./REPORT.md)