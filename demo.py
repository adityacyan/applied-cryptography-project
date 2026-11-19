"""End-to-end demonstration of SHA-256 integrity verification."""
import hashlib
import json
import os
import tempfile

import integrity as ig

HERE = os.path.dirname(os.path.abspath(__file__))


def banner(t):
    print(f"\n=== {t} ===")


with tempfile.TemporaryDirectory() as d:
    os.chdir(d)
    os.makedirs("docs")
    with open("docs/report.txt", "w") as f:
        f.write("Quarterly report: revenue 100,000\n")
    with open("docs/data.bin", "wb") as f:
        f.write(os.urandom(4096))

    banner("1. Sanity check: our hash matches hashlib's one-shot SHA-256")
    expected = hashlib.sha256(b"abc").hexdigest()
    with open("abc.txt", "wb") as f:
        f.write(b"abc")
    assert ig.sha256_file("abc.txt") == expected == \
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    print("SHA-256('abc') =", expected, "(matches NIST test vector)")
    os.remove("abc.txt")

    banner("2. Hash generation + storage")
    ig.generate(["docs"])

    banner("3. Verify untouched files")
    assert set(ig.verify().values()) == {"OK"}

    banner("4. Tamper with a file (change 100,000 -> 900,000) and one-bit flip in binary")
    with open("docs/report.txt", "w") as f:
        f.write("Quarterly report: revenue 900,000\n")
    with open("docs/data.bin", "r+b") as f:
        b = bytearray(f.read())
        b[0] ^= 1
        f.seek(0)
        f.write(b)
    r = ig.verify()
    assert set(r.values()) == {"MODIFIED"}

    banner("5. Deleted file")
    os.remove("docs/report.txt")
    assert "MISSING" in ig.verify().values()

    banner("5b. Unauthorised new file dropped into tracked folder")
    with open("docs/backdoor.py", "w") as f:
        f.write("evil")
    assert "NEW" in ig.verify().values()

    banner("5c. Authorised change accepted with 'update', report exported")
    ig.update(["docs"])
    assert set(ig.verify().values()) == {"OK"}
    ig.write_report(ig.verify(quiet=True), "report.html")

    banner("6. Attacker edits the stored hash to hide tampering")
    with open("hashes.json") as f:
        s = json.load(f)
    k = next(iter(s["entries"]))
    s["entries"][k]["sha256"] = "0" * 64
    with open("hashes.json", "w") as f:
        json.dump(s, f)
    try:
        ig.verify()
        raise SystemExit("FAIL: store tampering not detected")
    except ig.StoreTampered as e:
        print("[ALERT]", e)

    print("\nAll demonstrations passed.")
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
