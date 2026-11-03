import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fakebackup as fb  # noqa: E402
from iphonescan import cli, indicators, report  # noqa: E402
from iphonescan.backup import Backup, BackupError  # noqa: E402
from iphonescan.checks import run_all  # noqa: E402

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def _ind():
    i = indicators.Indicators()
    i.add_stix(fb.FAKE_STIX, "test.stix2")
    return i


class IndicatorTests(unittest.TestCase):
    def test_domain_and_subdomain_match(self):
        i = _ind()
        self.assertEqual(i.match_domain("evil-spy.example")[1], "Pegasus")
        self.assertEqual(i.match_url("https://a.b.evil-spy.example/path")[1], "Pegasus")
        self.assertIsNone(i.match_url("https://notevil-spy.example/"))
        self.assertIsNone(i.match_url("https://apple.com"))
        self.assertIsNone(i.match_url("http://[::1"))  # malformed URL must not crash
        self.assertEqual(i.match("process:name", "BH"), "Pegasus")

    def test_parse_index(self):
        text = """indicators:
  -
    type: github
    name: One
    github:
      owner: a
      repo: b
      branch: main
      path: x/one.stix2
  -
    type: github
    name: Two
    github:
      owner: c
      repo: d
      branch: master
      path: two.stix2
"""
        e = indicators.parse_index(text)
        self.assertEqual([x["path"] for x in e], ["x/one.stix2", "two.stix2"])
        self.assertEqual(e[0]["name"], "One")


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _scan(self, path, password=None):
        with Backup(path, password) as b:
            return run_all(b, _ind())

    def _titles(self, r):
        return [f"{f.severity}: {f.title}" for f in r.findings]

    def test_infected_unencrypted(self):
        p = fb.make_backup(self.dir / "b", fb.infected_files(), apps=fb.INFECTED_APPS)
        r = self._scan(p)
        t = "\n".join(self._titles(r))
        self.assertEqual(r.worst(), "critical")
        self.assertIn("jailbroken", t)
        self.assertIn("Safari history", t)
        self.assertIn("Messages", t)
        self.assertIn("Process name matches", t)
        self.assertIn("spyware operators", t)
        self.assertIn("high: Configuration profile installed: System Update (SpyCo)", t)
        self.assertIn("supervised", t)
        self.assertIn("critical: File matches known spyware artifact", t)
        self.assertIn("critical: Configuration profile installed: Free VPN", t)
        self.assertIn("Backup is not encrypted", t)
        perms = [f for f in r.findings if f.category == "Permissions"]
        self.assertEqual(len(perms), 1)
        self.assertIn("com.example.flashlight", perms[0].evidence[0])
        self.assertIn("com.saurik.Cydia", r.apps)

    def test_clean(self):
        p = fb.make_backup(self.dir / "c", fb.clean_files(), apps=["net.whatsapp.WhatsApp"])
        r = self._scan(p)
        self.assertNotIn(r.worst(), ("critical", "high"))
        text = report.to_text(r, color=False)
        self.assertIn("RESULT:", text)

    def test_old_ios_flagged(self):
        p = fb.make_backup(self.dir / "o", fb.clean_files(), info={"Product Version": "15.7"})
        r = self._scan(p)
        self.assertTrue(any(f.severity == "high" and "out of date" in f.title for f in r.findings))

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_encrypted_backup(self):
        p = fb.make_backup(self.dir / "e", fb.infected_files(), apps=fb.INFECTED_APPS, password="hunter2")
        with self.assertRaises(BackupError):
            Backup(p, None)
        with self.assertRaises(BackupError):
            Backup(p, "wrong")
        r = self._scan(p, "hunter2")
        t = "\n".join(self._titles(r))
        self.assertIn("Safari history", t)
        self.assertIn("Process name matches", t)
        self.assertNotIn("Backup is not encrypted", t)
        self.assertTrue(r.device["encrypted_backup"])

    def test_reports_render(self):
        p = fb.make_backup(self.dir / "r", fb.infected_files(), apps=fb.INFECTED_APPS)
        r = self._scan(p)
        h = report.to_html(r)
        self.assertIn("<title>iPhone Security Scan</title>", h)
        self.assertIn("DANGER", h)
        self.assertEqual(json.loads(report.to_json(r))["verdict"], "DANGER")

    def test_cli_end_to_end(self):
        p = fb.make_backup(self.dir / "parent" / "UDID123", fb.infected_files(), apps=fb.INFECTED_APPS)
        stix = self.dir / "t.stix2"
        stix.write_text(json.dumps(fb.FAKE_STIX))
        html = self.dir / "r.html"
        # pointing at the parent folder should find the single backup inside
        code = cli.main(["scan", str(p.parent), "--indicators", str(stix), "--html", str(html)])
        self.assertEqual(code, 1)
        self.assertTrue(html.read_text().startswith("<!doctype html>"))

    def test_not_a_backup(self):
        code = cli.main(["scan", str(self.dir), "--offline"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
