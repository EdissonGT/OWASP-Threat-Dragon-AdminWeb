"""Tests for config, baseline, diff mode, history, badge, Markdown summary, JS metrics and --fix."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from repocheckup import config, fixer, quality, quality_js, report, share, tracking  # noqa: E402
from repocheckup.scanner import scan  # noqa: E402

SAMPLES = ROOT / "samples" / "vulnerable-app"
WEAK = "import hashlib\n\n\ndef h(x):\n    return hashlib.m" + "d5(x).hexdigest()\n"


def cli(*args, cwd=ROOT, stdin=None):
    return subprocess.run([sys.executable, "-m", "repocheckup", *map(str, args)], cwd=cwd, capture_output=True,
                          text=True, input=stdin, env={**__import__("os").environ, "PYTHONPATH": str(ROOT)})


def repo(files):
    d = tempfile.TemporaryDirectory()
    for name, content in files.items():
        p = Path(d.name) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
                    *args], cwd=cwd, check=True, capture_output=True)


class ConfigTests(unittest.TestCase):
    def tearDown(self):
        quality.set_limits()

    def test_disable_and_severity_override(self):
        findings = scan([SAMPLES])[0]
        cfg = {"disable": ["QLT", "SEC001"], "severity": {"CRY001": "low"}}
        kept = config.apply(findings, cfg)
        self.assertFalse([f for f in kept if f.rule.startswith("QLT") or f.rule == "SEC001"])
        self.assertEqual({f.severity for f in kept if f.rule == "CRY001"}, {"low"})

    def test_file_is_found_and_used(self):
        cfg = {"disable": ["CRY001"], "fail_on": "critical", "limits": {"max_params": 1}, "lang": "es"}
        files = {"a.py": WEAK + "\n\ndef f(a, b):\n    return a\n", ".repocheckup.json": json.dumps(cfg)}
        with repo(files) as d:
            r = cli(d, "--checks", "security,quality", "--format", "json")
            data = json.loads(r.stdout)
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertEqual([f["rule"] for f in data["findings"]], ["QLT003"])
            self.assertIn("Demasiados", data["findings"][0]["title"])
            ignored = json.loads(cli(d, "--checks", "security", "--format", "json", "--no-config").stdout)
            self.assertEqual([f["rule"] for f in ignored["findings"]], ["CRY001"])

    def test_command_line_wins_over_file(self):
        with repo({"a.py": WEAK, ".repocheckup.json": json.dumps({"fail_on": "never"})}) as d:
            self.assertEqual(cli(d, "--checks", "security").returncode, 0)
            self.assertEqual(cli(d, "--checks", "security", "--fail-on", "medium").returncode, 1)

    def test_invalid_config_is_reported(self):
        for bad in ('{"nope": 1}', '{"severity": {"X": "huge"}}', '{"limits": {"max_params": 0}}', "not json",
                    '{"checks": ["magic"]}', '{"theme": "neon"}'):
            with repo({"a.py": "x = 1\n", ".repocheckup.json": bad}) as d:
                r = cli(d)
                self.assertEqual(r.returncode, 2, bad)
                self.assertIn("repocheckup:", r.stderr)


class BaselineTests(unittest.TestCase):
    def test_baseline_hides_known_and_reports_new(self):
        with repo({"a.py": WEAK}) as d:
            base = Path(d) / "base.json"
            self.assertEqual(cli(d, "--checks", "security", "--write-baseline", base).returncode, 0)
            self.assertEqual(cli(d, "--checks", "security", "--baseline", base, "--fail-on", "low").returncode, 0)
            # moving the flagged line must not make it "new"
            (Path(d) / "a.py").write_text("# header\n\n" + WEAK, encoding="utf-8")
            self.assertEqual(cli(d, "--checks", "security", "--baseline", base, "--fail-on", "low").returncode, 0)
            (Path(d) / "a.py").write_text(WEAK + "import pickle\nd = pickle.loads(b)\n", encoding="utf-8")  # repocheckup-ignore
            r = cli(d, "--checks", "security", "--baseline", base, "--format", "json")
            self.assertEqual([f["rule"] for f in json.loads(r.stdout)["findings"]], ["INJ004"])
            self.assertEqual(r.returncode, 1)

    def test_duplicates_are_counted(self):
        line = "h = hashlib.m" + "d5(x)\n"
        with repo({"a.py": line * 2}) as d:
            findings = scan([Path(d) / "a.py"], ["security"])[0]
            base = Path(d) / "b.json"
            tracking.write_baseline(findings[:1], base)
            new, hidden = tracking.apply_baseline(findings, base)
            self.assertEqual((len(new), hidden), (1, 1))

    def test_missing_baseline_is_an_error(self):
        self.assertEqual(cli(SAMPLES, "--baseline", "/no/such/file.json").returncode, 2)


class DiffTests(unittest.TestCase):
    def test_only_changed_lines_are_reported(self):
        with repo({"old.py": WEAK, "keep.py": "x = 1\n"}) as d:
            git(d, "init", "-q", "-b", "main")
            git(d, "add", "-A")
            git(d, "commit", "-q", "-m", "init")
            (Path(d) / "keep.py").write_text("x = 1\nimport pickle\ny = pickle.loads(b)\n", encoding="utf-8")  # repocheckup-ignore
            (Path(d) / "new.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")  # repocheckup-ignore
            r = cli(".", "--checks", "security", "--diff", "HEAD", "--format", "json", cwd=d)
            found = sorted((f["rule"], Path(f["file"]).name) for f in json.loads(r.stdout)["findings"])
            self.assertEqual(found, [("INJ003", "new.py"), ("INJ004", "keep.py")])
            full = json.loads(cli(".", "--checks", "security", "--format", "json", cwd=d).stdout)
            self.assertEqual(len(full["findings"]), 3)

    def test_bad_reference_and_no_git(self):
        with self.assertRaises(tracking.TrackingError):
            tracking.changed_lines("--output=/tmp/x")
        with repo({"a.py": "x = 1\n"}) as d:
            self.assertEqual(cli(".", "--diff", "main", cwd=d).returncode, 2)


class HistoryAndShareTests(unittest.TestCase):
    def test_history_trend_and_sparkline(self):
        with repo({"a.py": WEAK}) as d:
            hist, page = Path(d) / "h.json", Path(d) / "r.html"
            cli(d, "--checks", "security", "--history", hist, "--fail-on", "never")
            (Path(d) / "a.py").write_text("x = 1\n", encoding="utf-8")
            r = cli(d, "--checks", "security", "--history", hist, "--html", page, "--lang", "es")
            runs = json.loads(hist.read_text())
            self.assertEqual([h["score"] for h in runs], [96, 100])
            self.assertIn("Tendencia: +4", r.stdout)
            self.assertIn('class="spark"', page.read_text(encoding="utf-8"))
        self.assertEqual(report.sparkline([{"score": 50}]), "")

    def test_badge(self):
        svg = share.badge_svg(92)
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn("92/100 A", svg)
        self.assertIn(share.GRADE_COLORS["A"], svg)
        self.assertIn(share.GRADE_COLORS["F"], share.badge_svg(10))

    def test_markdown_summary(self):
        findings = scan([SAMPLES])[0]
        md = share.to_markdown(findings, ["security", "quality", "health"], "es", hidden=3)
        self.assertTrue(md.startswith(share.MARKER))
        self.assertIn("## repocheckup: 53/100 · D", md)
        self.assertIn("| Seguridad | 0/100 | F | 34 |", md)
        self.assertIn("3 hallazgos conocidos", md)
        self.assertIn("…y 34 más.", md)
        self.assertNotIn("<script", md)

    def test_cli_writes_badge_and_markdown(self):
        with tempfile.TemporaryDirectory() as d:
            badge, md = Path(d) / "b.svg", Path(d) / "s.md"
            cli(SAMPLES, "--badge", badge, "--markdown", md, "--fail-on", "never")
            self.assertIn("53/100 D", badge.read_text())
            self.assertIn("repocheckup: 53/100", md.read_text(encoding="utf-8"))


class JavaScriptMetricsTests(unittest.TestCase):
    def test_finds_functions_and_measures_them(self):
        code = '''
// function fake(a, b, c) { not real }
const s = "function alsoFake() {";
function plain(a, b) { return a + b; }
const arrow = async (x, { y, z }, w = [1, 2]) => {
  if (x && y) { return 1; }
  for (const i of w) { if (i) { continue; } }
  return z ? 1 : 2;
};
class Box {
  constructor(size) { this.size = size; }
  area(scale) {
    if (scale) { return this.size * scale; }
    return this.size;
  }
}
'''
        found = {name: (line, length, cx, params) for name, line, length, cx, params in quality_js.functions(code)}
        self.assertEqual(set(found), {"plain", "arrow", "constructor", "area"})
        self.assertEqual(found["plain"], (4, 1, 1, 2))
        self.assertEqual(found["arrow"][2:], (6, 3))
        self.assertEqual(found["area"], (12, 4, 2, 1))

    def test_long_complex_function_is_reported(self):
        body = "".join(f"  if (a{i}) {{ total += {i}; }}\n" for i in range(90))
        code = f"function big(a, b, c, d, e, f, g, h) {{\n{body}  return total;\n}}\n"
        ids = {f.rule for f in quality.check_file(Path("x.ts"), code)}
        self.assertEqual(ids, {"QLT001", "QLT002", "QLT003"})
        self.assertEqual(quality.check_file(Path("x.js"), "const f = (a) => { return a; };\n"), [])


class FixerTests(unittest.TestCase):
    def advice(self, path, **over):
        fix = {"rule": "CRY001", "file": str(path), "line": 5, "explanation": "use sha256", "false_positive": False,
               "original_code": "return hashlib.m" + "d5(x).hexdigest()", "fixed_code": "return hashlib.sha256(x).hexdigest()"}
        fix.update(over)
        return {"fixes": [fix]}

    def test_applies_fix_with_file_indentation(self):
        with repo({"a.py": WEAK}) as d:
            path = Path(d) / "a.py"
            edits, skipped = fixer.plan(self.advice(path), [d])
            self.assertEqual((len(edits), skipped), (1, []))
            self.assertIn("+    return hashlib.sha256(x).hexdigest()", fixer.diff(edits[0]))
            self.assertEqual(fixer.apply(edits, lambda e: True), 1)
            self.assertEqual(path.read_text(), "import hashlib\n\n\ndef h(x):\n    return hashlib.sha256(x).hexdigest()\n")
            self.assertEqual(scan([path], ["security"])[0], [])

    def test_wrong_line_number_still_finds_the_code(self):
        with repo({"a.py": WEAK}) as d:
            edits, _ = fixer.plan(self.advice(Path(d) / "a.py", line=1), [d])
            self.assertEqual(edits[0].start, 4)

    def test_refuses_unsafe_or_unmatched_fixes(self):
        with repo({"a.py": WEAK}) as d, repo({"other.py": WEAK}) as outside:
            path = Path(d) / "a.py"
            cases = [(self.advice(path, original_code="return something_else()"), "not found"),
                     (self.advice(Path(outside) / "other.py"), "outside"),
                     (self.advice(Path(d) / "missing.py"), "outside")]
            for advice, reason in cases:
                edits, skipped = fixer.plan(advice, [d])
                self.assertEqual(edits, [])
                self.assertIn(reason, skipped[0][1])
            for quiet in (self.advice(path, false_positive=True), self.advice(path, fixed_code=""),
                          self.advice(path, original_code="")):
                self.assertEqual(fixer.plan(quiet, [d]), ([], []))
            self.assertEqual(path.read_text(), WEAK)

    def test_declined_fix_changes_nothing_and_overlaps_are_dropped(self):
        with repo({"a.py": WEAK}) as d:
            path = Path(d) / "a.py"
            double = {"fixes": self.advice(path)["fixes"] * 2}
            edits, skipped = fixer.plan(double, [d])
            self.assertEqual(len(edits), 1)
            self.assertIn("overlaps", skipped[0][1])
            self.assertEqual(fixer.apply(edits, lambda e: False), 0)
            self.assertEqual(path.read_text(), WEAK)

    def test_keeps_crlf_line_endings(self):
        with repo({"a.py": ""}) as d:
            path = Path(d) / "a.py"
            path.write_bytes(WEAK.replace("\n", "\r\n").encode())
            edits, _ = fixer.plan(self.advice(path), [d])
            fixer.apply(edits, lambda e: True)
            data = path.read_bytes()
            self.assertIn(b"sha256(x).hexdigest()\r\n", data)
            self.assertNotIn(b"\r\r", data)


class FixCommandTests(unittest.TestCase):
    """End to end through main(), with the AI call replaced by a canned answer."""

    def run_main(self, d, *flags):
        from unittest import mock
        from repocheckup import __main__ as cli_module
        path = Path(d) / "a.py"
        advice = {"summary": "s", "priorities": [], "quick_wins": [], "fixes": FixerTests().advice(path)["fixes"]}
        out, err = __import__("io").StringIO(), __import__("io").StringIO()
        with mock.patch.object(cli_module.ai, "advise", return_value=(advice, [])), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch("sys.stdin", __import__("io").StringIO("")):
            code = cli_module.main([d, "--checks", "security", "--no-config", "--fix", *flags])
        return code, out.getvalue(), err.getvalue(), path

    def test_without_terminal_shows_diff_but_does_not_write(self):
        with repo({"a.py": WEAK}) as d:
            _, out, err, path = self.run_main(d)
            self.assertIn("+    return hashlib.sha256(x).hexdigest()", out)
            self.assertIn("not applied", err)
            self.assertEqual(path.read_text(), WEAK)

    def test_yes_applies_the_fix(self):
        with repo({"a.py": WEAK}) as d:
            _, _, err, path = self.run_main(d, "--yes")
            self.assertIn("1 of 1 fixes applied", err)
            self.assertIn("sha256", path.read_text())


if __name__ == "__main__":
    unittest.main()
