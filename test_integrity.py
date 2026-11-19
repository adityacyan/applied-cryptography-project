import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest

import integrity as ig


class T(unittest.TestCase):
    def setUp(self):
        quiet = contextlib.redirect_stdout(io.StringIO())  # keep test output clean
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        self._tmp = tempfile.TemporaryDirectory()
        self.d = self._tmp.name
        self.kw = dict(store=os.path.join(self.d, "h.json"), keyfile=os.path.join(self.d, "k"))
        os.makedirs(os.path.join(self.d, "data"))
        self.a = os.path.join(self.d, "data", "a.txt")
        self.write(self.a, b"hello")
        self.data = os.path.join(self.d, "data")

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, p, b):
        with open(p, "wb") as f:
            f.write(b)

    def v(self, *a, **k):
        return ig.verify(*a, quiet=True, **self.kw, **k)

    def test_known_vectors(self):
        self.write(self.a, b"abc")
        self.assertEqual(ig.sha256_file(self.a), hashlib.sha256(b"abc").hexdigest())
        self.write(self.a, b"")
        self.assertEqual(ig.sha256_file(self.a), hashlib.sha256(b"").hexdigest())

    def test_large_file_chunking(self):
        blob = os.urandom(ig.CHUNK * 2 + 17)
        self.write(self.a, blob)
        self.assertEqual(ig.sha256_file(self.a), hashlib.sha256(blob).hexdigest())

    def test_ok_modified_missing(self):
        ig.generate([self.data], quiet=True, **self.kw)
        self.assertEqual(set(self.v().values()), {ig.OK})
        self.write(self.a, b"hellp")  # one-character change
        self.assertEqual(self.v()[ig.norm(self.a)], ig.MODIFIED)
        os.remove(self.a)
        self.assertEqual(self.v()[ig.norm(self.a)], ig.MISSING)

    def test_new_file_detected(self):
        ig.generate([self.data], quiet=True, **self.kw)
        b = os.path.join(self.data, "evil.sh")
        self.write(b, b"x")
        self.assertEqual(self.v()[ig.norm(b)], ig.NEW)

    def test_update_rebaselines(self):
        ig.generate([self.data], quiet=True, **self.kw)
        self.write(self.a, b"changed")
        ig.update([self.a], **self.kw)
        self.assertEqual(set(self.v().values()), {ig.OK})

    def test_exclude(self):
        self.write(os.path.join(self.data, "x.tmp"), b"t")
        ig.generate([self.data], exclude=["*.tmp"], quiet=True, **self.kw)
        self.assertEqual(len(ig.load_store(**self.kw)["entries"]), 1)

    def test_store_tamper_detected(self):
        ig.generate([self.data], quiet=True, **self.kw)
        with open(self.kw["store"]) as f:
            s = json.load(f)
        s["entries"][ig.norm(self.a)]["sha256"] = "0" * 64
        with open(self.kw["store"], "w") as f:
            json.dump(s, f)
        with self.assertRaises(ig.StoreTampered):
            self.v()

    def test_wrong_key_detected(self):
        ig.generate([self.data], quiet=True, **self.kw)
        self.write(self.kw["keyfile"], b"another-key")
        with self.assertRaises(ig.StoreTampered):
            self.v()

    def test_cli_exit_codes_and_report(self):
        base = ["--store", self.kw["store"], "--keyfile", self.kw["keyfile"]]
        self.assertEqual(ig.main(base + ["generate", self.data]), 0)
        self.assertEqual(ig.main(base + ["verify"]), 0)
        self.write(self.a, b"zzz")
        rep = os.path.join(self.d, "r.html")
        self.assertEqual(ig.main(base + ["verify", "--report", rep]), 1)
        with open(rep) as f:
            self.assertIn("MODIFIED", f.read())


if __name__ == "__main__":
    unittest.main()
