import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from repocheckup import ai, deps, health, quality, report, security  # noqa: E402
from repocheckup.scanner import scan  # noqa: E402

SAMPLES = ROOT / "samples" / "vulnerable-app"


def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "repocheckup", *map(str, args)], cwd=ROOT, capture_output=True, text=True)


def tmp_repo(files):
    d = tempfile.TemporaryDirectory()
    for name, content in files.items():
        p = Path(d.name) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


class SecurityTests(unittest.TestCase):
    def test_sample_triggers_expected_rules(self):
        ids = {f.rule for f in scan([SAMPLES], ["security"])[0]}
        expected = {"SEC001", "CRY001", "CRY002", "CRY003", "INJ001", "INJ002", "INJ003", "INJ004", "INJ005",
                    "XSS001", "XSS002", "CFG001", "CFG002", "CFG006", "DOC001", "DOC002", "TF001", "TF002", "TF003",
                    "K8S001", "K8S002", "K8S003", "K8S004", "GHA001", "GHA002", "SSRF001"}
        self.assertEqual(expected - ids, set())

    def test_secure_examples_have_no_high_findings(self):
        found = [f for f in scan([ROOT / "examples"], ["security"])[0] if f.severity in ("high", "critical")]
        self.assertEqual(found, [], [f.to_dict() for f in found])

    def test_ignore_comment(self):
        text = "import hashlib\nh = hashlib.md5(b'x')  # repocheckup-ignore\n"
        self.assertEqual(security.check_file(Path("a.py"), text), [])

    def test_token_patterns_built_at_runtime(self):
        text = "AK" + "IA" + "ABCDEFGHIJKLMNOP\n-----BEGIN " + "RSA PRIVATE KEY-----\n"
        self.assertEqual({f.rule for f in security.check_file(Path("k.txt"), text)}, {"SEC002", "SEC003"})

    def test_placeholders_are_not_secrets(self):
        text = 'password = "${DB_PASSWORD}"\napi_key = "your-api-key-here"\nsecret = os.environ["S"]\n'
        self.assertEqual(security.check_file(Path("a.py"), text), [])

    def test_dockerfile_pinned_and_non_root_is_clean(self):
        text = "FROM python:3.12-slim\nUSER app\n"
        self.assertEqual(security.check_file(Path("Dockerfile"), text), [])

    def test_parameterized_sql_is_clean(self):
        text = 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
        self.assertEqual(security.check_file(Path("a.py"), text), [])


class QualityTests(unittest.TestCase):
    def rules(self, name, text):
        return {f.rule for f in quality.check_file(Path(name), text)}

    def test_long_function(self):
        body = "def f():\n" + "".join(f"    x{i} = {i}\n" for i in range(90))
        self.assertIn("QLT001", self.rules("a.py", body))

    def test_complexity_params_and_mutable_default(self):
        ids = {f.rule for f in scan([SAMPLES / "app.py"], ["quality"])[0]}
        self.assertTrue({"QLT002", "QLT003", "QLT005", "QLT006", "QLT009"} <= ids, ids)

    def test_syntax_error(self):
        self.assertEqual(self.rules("a.py", "def broken(:\n"), {"QLT008"})

    def test_empty_catch_js(self):
        self.assertIn("QLT005", self.rules("a.js", "try { x() } catch (e) {}\n"))

    def test_clean_function(self):
        self.assertEqual(self.rules("a.py", "def add(a, b):\n    return a + b\n"), set())

    def test_duplicates(self):
        block = "".join(f"result_value_{i} = compute_something(input_{i}, {i})\n" for i in range(12))
        found = quality.find_duplicates([(Path("a.py"), block), (Path("b.py"), block)])
        self.assertEqual([f.rule for f in found], ["QLT007"])
        self.assertEqual(quality.find_duplicates([(Path("a.py"), block)]), [])


class HealthTests(unittest.TestCase):
    def test_empty_repo(self):
        with tmp_repo({"main.py": "print(1)\n"}) as d:
            ids = {f.rule for f in health.check_repo(Path(d))}
        self.assertEqual(ids, {"HLT001", "HLT002", "HLT003", "HLT004", "HLT005", "HLT008", "HLT009"})

    def test_healthy_repo(self):
        files = {"README.md": "x" * 400, "LICENSE": "MIT", ".gitignore": "", "SECURITY.md": "", "CONTRIBUTING.md": "",
                 ".github/workflows/ci.yml": "on: push\n", ".github/dependabot.yml": "version: 2\n",
                 "tests/test_a.py": "", "requirements.txt": "flask==3.0.0\n"}
        with tmp_repo(files) as d:
            self.assertEqual(health.check_repo(Path(d)), [])

    def test_env_lockfile_and_unpinned(self):
        files = {".env": "A=1\n", ".env.example": "A=\n", "package.json": "{}", "requirements.txt": "flask\nx==1\n"}
        with tmp_repo(files) as d:
            found = health.check_repo(Path(d))
        ids = [f.rule for f in found]
        self.assertEqual(ids.count("HLT010"), 1)
        self.assertIn("HLT006", ids)
        self.assertIn("HLT007", ids)
        self.assertIn("HLT012", ids)


class DepsTests(unittest.TestCase):
    def test_reports_vulnerable_pins(self):
        lock = json.dumps({"packages": {"": {}, "node_modules/lodash": {"version": "4.17.0"}}})
        with tmp_repo({"requirements.txt": "flask==0.12\nrequests\n", "package-lock.json": lock}) as d:
            seen = []

            def fake(pkgs):
                seen.extend(pkgs)
                return [["GHSA-xxxx"] if name == "flask" else [] for _, name, _ in pkgs]
            found, warn = deps.check_repo(Path(d), query=fake)
        self.assertIsNone(warn)
        self.assertEqual(sorted(seen), [("PyPI", "flask", "0.12"), ("npm", "lodash", "4.17.0")])
        self.assertEqual([(f.rule, f.line) for f in found], [("DEP001", 1)])

    def test_network_failure_is_a_warning(self):
        def boom(pkgs):
            raise OSError("offline")
        with tmp_repo({"requirements.txt": "flask==0.12\n"}) as d:
            found, warn = deps.check_repo(Path(d), query=boom)
        self.assertEqual(found, [])
        self.assertIn("offline", warn)


class ReportTests(unittest.TestCase):
    def test_scores_and_grades(self):
        findings = scan([SAMPLES])[0]
        per, overall = report.scores(findings, ["security", "quality", "health"])
        self.assertEqual(per["security"], 0)
        self.assertTrue(0 <= overall < 75)
        self.assertEqual(report.scores([], ["security"]), ({"security": 100}, 100))
        self.assertEqual([report.grade(s) for s in (95, 80, 65, 45, 10)], list("ABCDF"))

    def test_html_escapes_content(self):
        text = 'el.innerHTML = "<script>alert(1)</script>"\n'
        found = security.check_file(Path("x.js"), text)
        page = report.to_html(found, ["security"], 1, "en", target="<b>target</b>")
        self.assertNotIn("<script>alert(1)", page)
        self.assertNotIn("<b>target</b>", page)
        self.assertIn("&lt;script&gt;alert(1)", page)

    def test_themes(self):
        found = security.check_file(Path("a.py"), "h = hashlib.m" + "d5(x)\n")
        matrix = report.to_html(found, ["security"], 1, "en")
        classic = report.to_html(found, ["security"], 1, "en", theme="classic")
        self.assertIn('<canvas id="rain"', matrix)
        self.assertIn("prefers-reduced-motion", matrix)
        self.assertNotIn("rain", classic)
        self.assertIn("repocheckup_", report.to_text(found, ["security"], 1, "en", color=True))
        self.assertNotIn("repocheckup_", report.to_text(found, ["security"], 1, "en", color=False))
        self.assertNotIn("repocheckup_", report.to_text(found, ["security"], 1, "en", color=True, theme="classic"))

    def test_spanish_messages(self):
        found = security.check_file(Path("a.py"), "h = hashlib.m" + "d5(x)\n", "es")
        self.assertIn("Hash débil", found[0].title)


ADVICE = {
    "summary": "Risky <b>repo</b>.",
    "priorities": [{"title": "Fix SQL injection", "why": "Data theft", "steps": ["Use parameters"],
                    "rules": ["INJ001"], "effort": "small"}],
    "fixes": [{"rule": "INJ001", "file": "app.py", "line": 13, "explanation": "Parameterize it",
               "original_code": "", "fixed_code": 'cur.execute("SELECT 1 WHERE a = %s", (a,))', "false_positive": False},
              {"rule": "CFG005", "file": "x.py", "line": 2, "explanation": "Test URL", "original_code": "", "fixed_code": "",
               "false_positive": True}],
    "quick_wins": ["Add a .gitignore"],
}


class Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class FakeClient:
    """Mimics client.beta.messages.stream(...) as a context manager with get_final_message()."""

    def __init__(self, text=None, stop_reason="end_turn", error=None):
        self.text = json.dumps(ADVICE) if text is None else text
        self.stop_reason, self.error, self.calls = stop_reason, error, []
        self.beta = Obj(messages=Obj(stream=self.stream))

    def stream(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        message = Obj(stop_reason=self.stop_reason, content=[Obj(type="thinking"), Obj(type="text", text=self.text)],
                      usage=Obj(input_tokens=10, output_tokens=5), model="fake-model")
        outer = self

        class Ctx:
            def __enter__(self):
                return Obj(get_final_message=lambda: message)

            def __exit__(self, *a):
                return False
        return Ctx()


class AiTests(unittest.TestCase):
    def setUp(self):
        self.findings = scan([SAMPLES])[0]
        self.checks = ["security", "quality", "health"]

    def test_request_shape_and_result(self):
        client = FakeClient()
        advice, notes = ai.advise(self.findings, self.checks, "es", max_findings=5, client=client)
        self.assertEqual(advice, ADVICE)
        call = client.calls[0]
        self.assertEqual(call["model"], "claude-opus-5-5")
        self.assertEqual(call["output_config"]["format"]["type"], "json_schema")
        self.assertEqual(call["output_config"]["effort"], "medium")
        self.assertEqual(call["fallbacks"], "default")
        self.assertNotIn("thinking", call)
        self.assertNotIn("temperature", call)
        self.assertIn("Spanish", call["messages"][0]["content"])
        self.assertTrue(any("5 most severe of" in n for n in notes))
        self.assertTrue(any("10 input and 5 output" in n for n in notes))

    def test_payload_sends_most_severe_with_code_context(self):
        payload, sent = ai.build_payload(self.findings, self.checks, 5)
        self.assertEqual(sent, 5)
        self.assertEqual(payload["total_findings"], len(self.findings))
        self.assertEqual(sum(payload["findings_not_shown_by_rule"].values()), len(self.findings) - 5)
        self.assertTrue(all(f["severity"] in ("high", "critical") for f in payload["findings"]))
        with_code = [f for f in payload["findings"] if f["code"]]
        self.assertTrue(with_code)
        self.assertRegex(with_code[0]["code"], r"^\d+: ")

    def test_failures_become_notes(self):
        cases = [(FakeClient(stop_reason="refusal"), "declined"), (FakeClient(stop_reason="max_tokens"), "cut off"),
                 (FakeClient(text="not json"), "not valid JSON"), (FakeClient(text="{}"), "expected fields"),
                 (FakeClient(error=OSError("no network")), "no network")]
        for client, expected in cases:
            advice, notes = ai.advise(self.findings, self.checks, client=client)
            self.assertIsNone(advice)
            self.assertTrue(any(expected in n for n in notes), notes)

    def test_no_findings_makes_no_call(self):
        client = FakeClient()
        self.assertEqual(ai.advise([], self.checks, client=client)[0], None)
        self.assertEqual(client.calls, [])

    def test_schema_is_strict(self):
        def check(node):
            if node.get("type") == "object":
                self.assertIs(node["additionalProperties"], False)
                self.assertEqual(sorted(node["required"]), sorted(node["properties"]))
                for child in node["properties"].values():
                    check(child)
            elif node.get("type") == "array":
                check(node["items"])
        check(ai.SCHEMA)

    def test_rendering_escapes_ai_text(self):
        page = report.to_html(self.findings, self.checks, 1, "en", target="t", advice=ADVICE)
        self.assertIn("AI recommendations", page)
        self.assertIn("Risky &lt;b&gt;repo&lt;/b&gt;.", page)
        self.assertNotIn("Risky <b>repo</b>", page)
        text = report.ai_to_text(ADVICE, "es")
        self.assertIn("Qué corregir primero", text)
        self.assertIn("Probable falso positivo", text)
        self.assertIn("ai", json.loads(report.to_json(self.findings, self.checks, 1, ADVICE)))

    def test_cli_without_sdk_explains_how_to_install(self):
        try:
            import anthropic  # noqa: F401
            self.skipTest("anthropic SDK is installed")
        except ImportError:
            pass
        r = run_cli(SAMPLES, "--ai", "--fail-on", "never")
        self.assertEqual(r.returncode, 0)
        self.assertIn("repocheckup[ai]", r.stderr)
        self.assertIn("Overall score", r.stdout)


class CliTests(unittest.TestCase):
    def test_exit_codes_and_json(self):
        r = run_cli(SAMPLES, "--format", "json")
        self.assertEqual(r.returncode, 1)
        data = json.loads(r.stdout)
        self.assertGreater(len(data["findings"]), 30)
        self.assertEqual(run_cli(SAMPLES, "--fail-on", "never").returncode, 0)
        self.assertEqual(run_cli(SAMPLES, "--fail-on", "never", "--min-score", "90").returncode, 1)
        self.assertEqual(run_cli("no-such-path").returncode, 2)

    def test_repo_itself_is_clean(self):
        r = run_cli(".", "--exclude", "samples", "--fail-on", "medium")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_sarif_and_html_output(self):
        with tempfile.TemporaryDirectory() as d:
            html_file, sarif = Path(d) / "r.html", Path(d) / "r.sarif"
            r = run_cli(SAMPLES, "--format", "sarif", "--output", sarif, "--html", html_file, "--lang", "es")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")
            self.assertIn("Puntaje general", html_file.read_text(encoding="utf-8"))

    def test_checks_selection(self):
        data = json.loads(run_cli(SAMPLES, "--checks", "health", "--format", "json", "--fail-on", "never").stdout)
        self.assertEqual({f["category"] for f in data["findings"]}, {"health"})
        self.assertEqual(run_cli(".", "--checks", "nope").returncode, 2)


if __name__ == "__main__":
    unittest.main()
