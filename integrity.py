#!/usr/bin/env python3
"""SHA-256 based File Integrity Verification System (core library + CLI).

Commands:
  generate <path...>   hash files (directories are walked) and store the hashes
  verify [path...]     compare with stored hashes; detects MODIFIED / MISSING / NEW files
  update <path...>     accept an authorised change (re-baseline already tracked files)
  list                 show stored hashes
  remove <path...>     stop tracking files
  log                  show the audit log
  hash <file>          print the SHA-256 of a file (no storage)

The hash store is signed with HMAC-SHA256, so editing the store (or editing a file and
its stored hash together) is detected. Key: env INTEGRITY_KEY, else .integrity.key.
"""
import argparse
import fnmatch
import hashlib
import hmac
import html
import json
import os
import secrets
import sys
from datetime import datetime, timezone

STORE = "hashes.json"
KEYFILE = ".integrity.key"
LOGFILE = "integrity.log"
CHUNK = 1024 * 1024
OK, MODIFIED, MISSING, NEW, UNKNOWN = "OK", "MODIFIED", "MISSING", "NEW", "UNKNOWN"


class StoreTampered(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- hashing
def sha256_file(path):
    """Stream the file in chunks so large files never need to fit in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- key / store
def get_key(keyfile=KEYFILE):
    env = os.environ.get("INTEGRITY_KEY")
    if env:
        return env.encode()
    if not os.path.exists(keyfile):
        with open(keyfile, "wb") as f:
            f.write(secrets.token_hex(32).encode())
        _private(keyfile)
    with open(keyfile, "rb") as f:
        return f.read().strip()


def _private(path):
    try:
        os.chmod(path, 0o600)  # owner-only (best effort on Windows)
    except OSError:
        pass


def _sign(body, key):
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def load_store(store=STORE, keyfile=KEYFILE):
    """Return {'entries': {...}, 'roots': [...]}; raises StoreTampered on bad signature."""
    if not os.path.exists(store):
        return {"entries": {}, "roots": []}
    with open(store, "r", encoding="utf-8") as f:
        data = json.load(f)
    body = {"entries": data.get("entries", {}), "roots": data.get("roots", [])}
    if not hmac.compare_digest(str(data.get("hmac", "")), _sign(body, get_key(keyfile))):
        log(f"ALERT hash store signature mismatch ({store})", store)
        raise StoreTampered("hash store signature mismatch - the store (or key) was modified!")
    return body


def save_store(body, store=STORE, keyfile=KEYFILE):
    data = dict(body, hmac=_sign(body, get_key(keyfile)))
    tmp = store + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, store)  # atomic write
    _private(store)


def log(msg, store=STORE):
    path = os.path.join(os.path.dirname(os.path.abspath(store)), LOGFILE)
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{now()}  {msg}\n")


# ---------------------------------------------------------------- file discovery
def norm(p):
    return os.path.normpath(os.path.abspath(p))


def _internal(path, store, keyfile):
    d = os.path.dirname(os.path.abspath(store))
    return norm(path) in {norm(store), norm(keyfile), norm(store + ".tmp"), norm(os.path.join(d, LOGFILE))}


def _excluded(path, exclude):
    parts = norm(path).split(os.sep)
    return any(fnmatch.fnmatch(x, pat) for pat in exclude for x in parts[-1:] + parts[:-1])


def expand(paths, exclude=(), store=STORE, keyfile=KEYFILE):
    """Yield absolute paths of files, walking directories, skipping excludes/internal files."""
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not _excluded(d, exclude))
                for name in sorted(files):
                    full = os.path.join(root, name)
                    if not _excluded(full, exclude) and not _internal(full, store, keyfile):
                        yield norm(full)
        elif os.path.isfile(p) and not _internal(p, store, keyfile):
            yield norm(p)
        else:
            yield norm(p)  # nonexistent: reported by caller


# ---------------------------------------------------------------- operations
def generate(paths, exclude=(), store=STORE, keyfile=KEYFILE, quiet=False):
    body = load_store(store, keyfile)
    count = 0
    for p in paths:
        if os.path.isdir(p) and norm(p) not in body["roots"]:
            body["roots"].append(norm(p))
    for p in expand(paths, exclude, store, keyfile):
        if not os.path.isfile(p):
            print(f"[SKIP]     not a file: {p}")
            continue
        digest = sha256_file(p)
        body["entries"][p] = {"sha256": digest, "size": os.path.getsize(p), "recorded": now()}
        if not quiet:
            print(f"[HASHED]   {digest}  {p}")
        count += 1
    body["roots"].sort()
    save_store(body, store, keyfile)
    log(f"GENERATE {count} file(s)", store)
    return count


def verify(paths=None, exclude=(), store=STORE, keyfile=KEYFILE, quiet=False):
    """Return {path: status}. With no paths: all tracked files + NEW files under tracked dirs."""
    body = load_store(store, keyfile)
    entries = body["entries"]
    if paths:
        targets = list(expand(paths, exclude, store, keyfile))
    else:
        targets = list(entries)
        for f in expand(body["roots"], exclude, store, keyfile):
            if f not in entries:
                targets.append(f)
    results = {}
    for p in dict.fromkeys(targets):
        rec = entries.get(p)
        if rec is None:
            results[p] = NEW if any(p.startswith(r + os.sep) for r in body["roots"]) else UNKNOWN
        elif not os.path.isfile(p):
            results[p] = MISSING
        else:
            results[p] = OK if hmac.compare_digest(sha256_file(p), rec["sha256"]) else MODIFIED
        if not quiet:
            _print_result(p, results[p], rec)
    bad = sum(s != OK for s in results.values())
    log(f"VERIFY {len(results)} checked, {bad} problem(s)" + "".join(
        f"\n    {s} {p}" for p, s in results.items() if s != OK), store)
    return results


def _print_result(p, status, rec):
    tag = {OK: "OK", MODIFIED: "TAMPERED", MISSING: "MISSING", NEW: "NEW", UNKNOWN: "UNKNOWN"}[status]
    print(f"[{tag}]".ljust(11), p)
    if status == MODIFIED:
        print(f"             expected {rec['sha256']}\n             actual   {sha256_file(p)}")


def update(paths, exclude=(), store=STORE, keyfile=KEYFILE):
    """Re-baseline tracked files (or add NEW ones) after an authorised change."""
    body = load_store(store, keyfile)
    n = 0
    for p in list(body["entries"]):  # tracked files under given paths that no longer exist
        if not os.path.isfile(p) and any(p == norm(x) or p.startswith(norm(x) + os.sep) for x in paths):
            del body["entries"][p]
            print(f"[REMOVED]  {p} (file gone)")
            n += 1
    for p in expand(paths, exclude, store, keyfile):
        if os.path.isfile(p):
            body["entries"][p] = {"sha256": sha256_file(p), "size": os.path.getsize(p), "recorded": now()}
            print(f"[UPDATED]  {p}")
            n += 1
        elif p in body["entries"]:
            del body["entries"][p]
            print(f"[REMOVED]  {p} (file gone)")
            n += 1
    save_store(body, store, keyfile)
    log(f"UPDATE {n} file(s) re-baselined", store)
    return n


def remove(paths, store=STORE, keyfile=KEYFILE):
    body = load_store(store, keyfile)
    for p in expand(paths, (), store, keyfile):
        body["entries"].pop(p, None)
    for p in paths:
        if norm(p) in body["roots"]:
            body["roots"].remove(norm(p))
    save_store(body, store, keyfile)
    log(f"REMOVE {len(paths)} path(s) untracked", store)


def write_report(results, path):
    """Write a verification report as .json, .html or .txt (by extension)."""
    summary = {s: sum(v == s for v in results.values()) for s in (OK, MODIFIED, MISSING, NEW, UNKNOWN)}
    ext = os.path.splitext(path)[1].lower()
    with open(path, "w", encoding="utf-8") as f:
        if ext == ".json":
            json.dump({"generated": now(), "summary": summary, "files": results}, f, indent=2)
        elif ext in (".html", ".htm"):
            colors = {OK: "#2e7d32", MODIFIED: "#c62828", MISSING: "#ef6c00", NEW: "#1565c0", UNKNOWN: "#6a1b9a"}
            rows = "".join(
                f"<tr><td style='color:{colors[s]};font-weight:bold'>{s}</td><td>{html.escape(p)}</td></tr>"
                for p, s in results.items())
            f.write(f"<!doctype html><meta charset=utf-8><title>Integrity Report</title>"
                    f"<body style='font-family:sans-serif'><h1>File Integrity Report</h1><p>{now()} &mdash; "
                    f"{html.escape(str(summary))}</p><table border=1 cellpadding=6 style='border-collapse:collapse'>"
                    f"<tr><th>Status</th><th>File</th></tr>{rows}</table></body>")
        else:
            f.write(f"Integrity report {now()}\n{summary}\n\n" + "\n".join(f"{s:9} {p}" for p, s in results.items()))


# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", default=STORE)
    ap.add_argument("--keyfile", default=KEYFILE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("generate", "verify", "update"):
        sp = sub.add_parser(name)
        sp.add_argument("paths", nargs="*" if name == "verify" else "+")
        sp.add_argument("-x", "--exclude", action="append", default=[], metavar="PATTERN",
                        help="glob to skip, e.g. '*.tmp' or '__pycache__' (repeatable)")
        if name == "verify":
            sp.add_argument("--report", metavar="FILE", help="write report (.json/.html/.txt)")
    sub.add_parser("list")
    sub.add_parser("remove").add_argument("paths", nargs="+")
    sub.add_parser("log")
    sub.add_parser("hash").add_argument("file")
    a = ap.parse_args(argv)
    s, k = a.store, a.keyfile

    try:
        if a.cmd == "generate":
            print(f"{generate(a.paths, a.exclude, s, k)} file(s) recorded in {s}")
        elif a.cmd == "verify":
            res = verify(a.paths or None, a.exclude, s, k)
            if a.report:
                write_report(res, a.report)
                print(f"report written to {a.report}")
            bad = [p for p, st in res.items() if st != OK]
            print(f"\n{len(res) - len(bad)}/{len(res)} files intact"
                  + (" - TAMPERING DETECTED" if bad else ""))
            return 1 if bad else 0
        elif a.cmd == "update":
            update(a.paths, a.exclude, s, k)
        elif a.cmd == "list":
            for p, r in load_store(s, k)["entries"].items():
                print(f"{r['sha256']}  {r['size']:>9}  {r['recorded']}  {p}")
        elif a.cmd == "remove":
            remove(a.paths, s, k)
        elif a.cmd == "log":
            lp = os.path.join(os.path.dirname(os.path.abspath(s)), LOGFILE)
            print(open(lp, encoding="utf-8").read() if os.path.exists(lp) else "(empty)")
        elif a.cmd == "hash":
            print(f"{sha256_file(a.file)}  {a.file}")
    except StoreTampered as err:
        print(f"[ALERT] {err}")
        return 2
    except (OSError, json.JSONDecodeError) as err:
        print(f"[ERROR] {err}")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
