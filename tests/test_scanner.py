import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from appsec_scan.scanner import scan  # noqa: E402

SAMPLES = ROOT / "samples" / "vulnerable-app"


class ScannerTests(unittest.TestCase):
    def test_detects_expected_rules(self):
        ids = {f.rule for f in scan([SAMPLES])}
        expected = {"SEC001", "CRY001", "CRY002", "CRY003", "INJ001", "INJ002", "INJ003", "INJ004",
                    "XSS001", "CFG001", "CFG002", "DOC001", "DOC002"}
        self.assertTrue(expected <= ids, f"faltan: {expected - ids}")

    def test_clean_code_has_no_findings(self):
        clean = ROOT / "examples"
        high = [f for f in scan([clean]) if f.severity in ("high", "critical")]
        self.assertEqual(high, [], [f.to_dict() for f in high])

    def test_ignore_comment(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.py"
            p.write_text("import hashlib\nh = hashlib.md5(b'x')  # appsec-ignore\n")
            self.assertEqual(scan([p]), [])

    def test_secret_patterns_built_at_runtime(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "k.txt"
            p.write_text("AK" + "IA" + "ABCDEFGHIJKLMNOP\n-----BEGIN " + "RSA PRIVATE KEY-----\n")
            ids = {f.rule for f in scan([p])}
            self.assertEqual(ids, {"SEC002", "SEC003"})

    def test_cli_exit_code_and_json(self):
        r = subprocess.run([sys.executable, "-m", "appsec_scan", str(SAMPLES), "--format", "json"],
                           cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertGreater(len(json.loads(r.stdout)), 5)
        ok = subprocess.run([sys.executable, "-m", "appsec_scan", str(ROOT / "examples")], cwd=ROOT,
                            capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout)

    def test_sarif(self):
        r = subprocess.run([sys.executable, "-m", "appsec_scan", str(SAMPLES), "--format", "sarif"],
                           cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(json.loads(r.stdout)["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
