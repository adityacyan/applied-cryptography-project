# SHA-256 File Integrity Verification System

Python + `hashlib` only (no third-party packages).

## Usage
```
python integrity.py generate docs/ file.txt -x "*.tmp"   # hash files/folders (skip patterns), save baseline
python integrity.py verify                               # check all; detects MODIFIED / MISSING / NEW files
python integrity.py verify --report report.html          # also write .html/.json/.txt report
python integrity.py update file.txt                      # accept an authorised change
python integrity.py list | remove <path> | log | hash <file>
python gui.py                                            # graphical interface (Tkinter)
python demo.py                                           # scripted attack demonstration
python -m unittest -v                                    # test suite
```
`verify` exits 0 if all intact, 1 on tampering, 2 if the hash store itself was tampered with (usable in scripts/cron).

## How it maps to the project tasks
| Task | Implementation |
|---|---|
| Hash generation | `sha256_file()` streams files in 1 MB chunks through `hashlib.sha256` |
| Integrity checking | `verify()` recomputes hashes, compares with constant-time `hmac.compare_digest` |
| Tampering detection | `OK` / `MODIFIED` / `MISSING` / `NEW` (unauthorised file in a tracked folder) / `UNKNOWN` |
| Hash storage | `hashes.json`: atomic write, owner-only permissions, hash + size + timestamp, HMAC-signed |
| Security verification | Editing the store or key is detected; `demo.py` and unit tests demonstrate each attack; `integrity.log` keeps an audit trail |

## Files
`integrity.py` core + CLI · `gui.py` Tkinter app · `demo.py` demo · `test_integrity.py` tests

## Security notes
- A bare hash file can be rewritten by an attacker together with the tampered file. The HMAC key
  (`INTEGRITY_KEY` env var, or `.integrity.key`) prevents that; keep the key separate from the store.
- Any change, even one bit, yields a completely different SHA-256 digest.
- Changes made before the baseline was generated are not detected; baseline from a trusted state.
