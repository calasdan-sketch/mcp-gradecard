"""Score servers from findings and render reports."""

from __future__ import annotations

import re
import sys
import textwrap

from . import catalog, discovery, redact

DEDUCTIONS = {"critical": 40, "high": 20, "medium": 10, "low": 5}

#: The check id of every finding about what a server says of its tools (the
#: --deep description scan); a report that has none of them for a server whose
#: tools were read says so in its own words (see _deep_line).
DESCRIPTION_CHECK = "tool-description-injection"

# Report glyphs and their ASCII stand-ins. A Windows console or pipe often
# runs cp1252, which cannot encode the check mark or the box-drawing rule:
# printing them there raised UnicodeEncodeError and killed the report.
_ASCII_SYMBOLS = {"✓": "[ok]", "─": "-", "·": "*", "—": "--"}


def sym(s: str) -> str:
    """`s` if the current stdout can encode it, else ASCII stand-ins."""
    enc = getattr(sys.stdout, "encoding", None)
    if not enc:
        return s  # e.g. io.StringIO: takes any str
    try:
        s.encode(enc)
    except (UnicodeEncodeError, LookupError):
        return "".join(_ASCII_SYMBOLS.get(ch)
                       or ch.encode("ascii", "replace").decode("ascii")
                       for ch in s)
    return s


def score(findings: list[dict]) -> tuple[int, str]:
    s = 100
    for f in findings:
        s -= DEDUCTIONS.get(f.get("severity", "low"), 5)
    s = max(0, s)
    grade = "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"
    # Severity floor: any single critical finding caps the grade at D, no
    # matter how few findings there are (a lone critical still scores 60).
    if grade in ("A", "B", "C") and any(
            f.get("severity") == "critical" for f in findings):
        grade = "D"
    return s, grade


def summarize(results: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        for f in r["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "servers": len(results),
        "findings": sum(counts.values()),
        "by_severity": counts,
    }


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _deep_line(r: dict) -> "str | None":
    """What the report says of a server whose tools --deep read when what
    they say raised nothing. Not "no findings": that would speak for the
    whole server, and the scanner only knows some patterns."""
    read = r.get("deep_read")
    if read is None or any(f["check"] == DESCRIPTION_CHECK
                           for f in r["findings"]):
        return None
    if not read:
        return "deep: the server lists no tools, so there was nothing to read"
    return (f"deep: {read} tool{'' if read == 1 else 's'} read, no known "
            "poisoning patterns matched (heuristic - this is not proof of "
            "safety)")



_FIRST = 3          # findings under "Fix first" in the terminal report
_FIRST_WIDTH = 104


def _verdict_block(results: list[dict], warnings: list[dict], n_configs: int,
                   advice: bool, deep: bool) -> list[str]:
    """The end of the terminal report: the overall grade in one sentence, the
    few findings to fix first, and the next commands worth knowing. What a
    person reads last is what they act on."""
    from . import report     # report imports this module
    s = redact.sanitize
    overall = report._worst_grade(results)
    sentence = report._verdict(results, warnings, n_configs)
    serious = [f for r in results for f in r["findings"]
               if f["severity"] in ("critical", "high")]
    if serious and all(f.get("known") for f in serious):
        sentence = ("Nothing new: every critical or high finding is already "
                    "in the baseline.")
    out = ["", f"  Overall: {overall}  {sym('—')}  {sentence}"]
    worst: list[tuple[dict, list[dict]]] = []
    for r in sorted(results, key=lambda x: (x["score"], str(x["name"]))):
        hot = sorted((f for f in r["findings"]
                      if not f.get("known")
                      and f["severity"] in ("critical", "high")),
                     key=lambda f: _SEV_ORDER.get(f["severity"], 9))
        if hot:
            worst.append((r, hot))
    if worst:
        out.append("  Fix first:")
        for i, (r, hot) in enumerate(worst[:_FIRST], 1):
            head = hot[0]["message"].split(" \u2014 ")[0]
            if len(head.split(": ")[0]) >= 25:
                head = head.split(": ")[0]
            if len(head) > _FIRST_WIDTH:
                head = head[:_FIRST_WIDTH - 3].rstrip() + "..."
            more = (f"  (+{len(hot) - 1} more serious)" if len(hot) > 1
                    else "")
            out.append(f"    {i}. {s(str(r['name']))} [{r['grade']}]: "
                       f"{s(head)}{more}")
        if len(worst) > _FIRST:
            out.append(f"    (and {len(worst) - _FIRST} more server(s) with "
                       "critical or high findings)")
    nxt = []
    if not advice and any(r["findings"] for r in results):
        nxt.append(("--advice", "what to do about each finding"))
    nxt.append(("--format html -o report.html", "a report you can hand over"))
    if not deep:
        nxt.append(("--deep", "also read what servers say about their "
                              "tools (launches them)"))
    out.append("  Next:")
    for cmd, what in nxt:
        out.append(("    " + ("mcp-gradecard " + cmd if cmd else "").ljust(44)
                    + what).rstrip())
    return out


# ANSI colour for the terminal report. Untrusted text reaches the report with
# its escape characters spelled out, so an escape sequence here is ours.
_RESET = "\x1b[0m"
_GRADE_COLOUR = {"A": "32", "B": "32", "C": "33", "D": "31", "F": "1;31",
                 "?": "90"}
_SEV_COLOUR = {"CRITICAL": "1;31", "HIGH    ": "31", "MEDIUM  ": "33",
               "LOW     ": "36"}
_GRADE_LINE = re.compile(r"^(  )\[([A-F?])\](?= \S)", re.M)
_SEV_LINE = re.compile(r"^(        )\[(CRITICAL|HIGH    |MEDIUM  |LOW     )\]",
                       re.M)
_OVERALL_LINE = re.compile(r"^(  Overall: )([A-F?])(?=  )", re.M)


def colorize(text: str) -> str:
    """Add ANSI colour to the grade letters and severity tags of a finished
    terminal report."""
    def grade(m):
        return f"{m.group(1)}[\x1b[{_GRADE_COLOUR[m.group(2)]}m{m.group(2)}{_RESET}]"

    def sev(m):
        return (f"{m.group(1)}[\x1b[{_SEV_COLOUR[m.group(2)]}m{m.group(2)}"
                f"{_RESET}]")

    def overall(m):
        return f"{m.group(1)}\x1b[{_GRADE_COLOUR[m.group(2)]}m{m.group(2)}{_RESET}"
    text = _GRADE_LINE.sub(grade, text)
    text = _SEV_LINE.sub(sev, text)
    return _OVERALL_LINE.sub(overall, text)


def render_human(results: list[dict], warnings: list[dict] | None = None,
                 n_configs: int = 0, configs: list[dict] | None = None,
                 advice: bool = False, policy: "dict | None" = None,
                 comparison: "dict | None" = None) -> str:
    """Render the human report.

    warnings: discovery warnings for config files that existed but were
    skipped (unparseable, unreadable, unknown/unsupported shape).
    n_configs: how many configs were actually discovered and parsed.
    configs: the discovered configs themselves; each one that parsed but
    holds no servers gets an info line ("0 servers configured") so a known
    client with nothing installed reads as exactly that, not as skipped.
    When zero configs were discovered the report says so plainly — a
    confident "no findings" is never emitted for unscanned configs. Nor is it
    for a server whose tools --deep read: that line says what was read and
    that the scan is a heuristic.

    Names, paths and messages come from the configs being audited. Each is
    sanitized where it is placed in the report: a control or bidi character
    in one is spelled out (\\x1b), and a line break in a name cannot start a
    line of its own and fake a result. The finished report is sanitized
    again as a backstop.
    """
    s = redact.sanitize
    warnings = warnings or []
    rule = sym("─")
    lines = ["", f"{rule * 2} mcp-gradecard {rule * 39}"]
    for w in warnings:
        lines.append(f"  [!] skipped {s(w['path'])} <{s(w['client'])}>: "
                     f"{s(w['reason'])}")
    managed: set = set()
    for c in configs or []:
        if discovery.is_managed_client(c["client"]):
            # one line per file, whatever it holds: the organization's servers
            # are not the ones this person wrote
            if c["path"] not in managed:
                managed.add(c["path"])
                count = sum(len(g.get("servers") or {}) for g in configs
                            if g["path"] == c["path"])
                lines.append(
                    f"  [i] managed config present: {s(c['path'])} "
                    f"<{s(c['client'])}> - set by your organization, "
                    f"{count} server(s); --fix never rewrites it")
        elif not c.get("servers"):
            lines.append(f"  [i] {s(c['path'])} <{s(c['client'])}>: "
                         "0 servers configured")
    if not results:
        if n_configs == 0:
            lines.append(f"  [mcp-gradecard] warning: no MCP configs discovered "
                         f"{sym('—')} this is not a clean bill of health.")
            lines += ["",
                      "  It looked in the usual places for Claude Code, Claude "
                      "Desktop, Cursor, VS Code,",
                      "  Windsurf, Zed and other clients, and found no MCP "
                      "servers.",
                      "",
                      "  To see what a report looks like:   mcp-gradecard --demo",
                      "  To check one file you know about:  mcp-gradecard "
                      "--config FILE"]
        else:
            lines.append("  no MCP servers found in audited configs.")
        lines.append(rule * 50)
        return redact.sanitize_report("\n".join(lines))
    for r in sorted(results, key=lambda x: x["score"]):
        lines.append("")
        lines.append(f"  [{r['grade']}] {s(r['name'])}  ({r['score']}/100)  "
                     f"<{s(r['client'])}>")
        lines.append(f"        {s(r['path'])}" + (
            f"  (project: {s(r['project'])})" if "project" in r else ""))
        for f in sorted(r["findings"],
                        key=lambda x: _SEV_ORDER.get(x["severity"], 9)):
            lines.append(f"        [{f['severity'].upper():8}] "
                         f"{s(f['message'])}"
                         + ("  (known)" if f.get("known") else ""))
            if advice:
                fix = catalog.remediation(f["check"])
                if fix:
                    for i, part in enumerate(textwrap.wrap(
                            fix, 84, break_long_words=False) or [""]):
                        lines.append("            " + ("fix: " if i == 0
                                                       else "     ") + part)
        for f in r.get("suppressed") or []:
            sup = f.get("suppression") or {}
            lines.append(f"        [SUPPRESSED] {s(f['check'])} until "
                         f"{s(str(sup.get('expires')))}: "
                         f"{s(str(sup.get('reason')))}")
        deep = _deep_line(r)
        if deep:
            lines.append(f"        {deep}")
        elif not r["findings"]:
            lines.append(f"        {sym('✓')} no findings")
    total = summarize(results)
    sev = total["by_severity"]
    lines += ["",
              f"  {total['servers']} server{'' if total['servers'] == 1 else 's'} "
              f"{sym('·')} {total['findings']} "
              f"finding{'' if total['findings'] == 1 else 's'} "
              f"(crit={sev['critical']} high={sev['high']} "
              f"med={sev['medium']} low={sev['low']})"]
    if policy:
        bits = []
        if policy.get("baseline"):
            bits.append(f"baseline: {policy['new']} new, {policy['known']} "
                        f"known, {policy['fixed']} fixed")
        if policy.get("suppressed"):
            bits.append(f"{policy['suppressed']} suppressed (listed above)")
        if bits:
            lines.append("  " + f" {sym('·')} ".join(bits))
        for e in policy.get("expired") or []:
            lines.append(f"  [!] a suppression of '{s(str(e['check']))}' "
                         f"expired on {s(str(e['expires']))}: the finding "
                         "counts again")
    if comparison:
        from . import compare as compare_mod
        lines += ["", f"  Since the previous check: "
                      f"{redact.sanitize(compare_mod.summary_line(comparison))}"]
        for item in comparison["resolved"][:30]:
            lines.append(f"    [resolved] {redact.sanitize(item['severity']).upper()} "
                         f"{redact.sanitize(item['server'])}: {redact.sanitize(item['title'])}"
                         + (" (server removed)" if item["server_removed"]
                            else ""))
        for item in comparison["new"][:30]:
            lines.append(f"    [new]      {redact.sanitize(item['severity']).upper()} "
                         f"{redact.sanitize(item['server'])}: {redact.sanitize(item['title'])}")
        for m in comparison["grade_changes"][:30]:
            lines.append(f"    [grade]    {redact.sanitize(m['server'])}: {m['before']} -> "
                         f"{m['after']}")
        if comparison.get("note"):
            lines.append(f"    note: {redact.sanitize(comparison['note'])}")
    if warnings:
        lines.append(f"  [mcp-gradecard] warning: {len(warnings)} config file(s) "
                     f"existed but were not audited {sym('—')} results are "
                     "not a clean bill of health.")
    lines += _verdict_block(results, warnings, n_configs, advice, deep=any(
        r.get("deep_read") is not None for r in results))
    lines.append(rule * 50)
    return redact.sanitize_report("\n".join(lines))


def _sarif_rule(check: str) -> dict:
    """A SARIF rule for one check id: its title, what to do, its OWASP MCP
    Top 10 tags and the `security-severity` GitHub ranks by (raised to the
    worst finding of the run)."""
    refs = catalog.owasp(check)
    rule = {"id": check, "name": check,
            "shortDescription": {"text": catalog.title(check)},
            "properties": {"tags": ["security", "mcp"]
                           + [f"OWASP-{ref}" for ref in refs],
                           "security-severity": "0.0"}}
    fix = catalog.remediation(check)
    if fix:
        owasp = "; ".join(f"{ref} {catalog.OWASP[ref]}" for ref in refs)
        rule["fullDescription"] = {"text": catalog.title(check)}
        rule["help"] = {"text": fix + (f" (OWASP MCP Top 10: {owasp})"
                                       if owasp else "")}
        rule["helpUri"] = catalog.OWASP_URL if refs else (
            "https://github.com/calasdan-sketch/mcp-gradecard")
    return rule


def _fingerprint(r: dict, f: dict) -> str:
    """The same finding on the same server gets the same id on every run,
    so code scanning can tell new alerts from old ones. Numbers in the
    message are left out: a count ("3 tools changed", "+2 more") moves
    while the alert is the same one."""
    import hashlib
    import json
    import os
    import re
    try:
        path = os.path.realpath(str(r.get("path")))
    except (OSError, ValueError):
        path = str(r.get("path"))
    key = json.dumps([r.get("client"), path, r.get("project"),
                      r.get("name"), f["check"],
                      re.sub(r"[0-9]+", "#", f["message"])],
                     ensure_ascii=False)
    return hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()


_SARIF_LEVEL = {"critical": "error", "high": "error",
                "medium": "warning", "low": "note"}


def render_sarif(results: list[dict], version: str,
                 baseline: bool = False) -> dict:
    """SARIF 2.1.0 log (GitHub code scanning, IDE viewers). One rule per
    check id; each finding points at the config file that holds the server."""
    import pathlib
    rules: dict[str, dict] = {}
    out = []
    for r in results:
        try:
            uri = pathlib.Path(r["path"]).resolve().as_uri()
        except ValueError:
            uri = str(r["path"]).replace("\\", "/")
        listed = [(f, None) for f in r["findings"]] + [
            (f, f.get("suppression")) for f in r.get("suppressed") or []]
        for f, sup in listed:
            rule = rules.setdefault(f["check"], _sarif_rule(f["check"]))
            props = rule["properties"]
            if float(catalog.security_severity(f["severity"])) > float(
                    props["security-severity"]):
                props["security-severity"] = catalog.security_severity(
                    f["severity"])
            item = {
                "ruleId": f["check"],
                "level": _SARIF_LEVEL.get(f["severity"], "note"),
                "message": {"text": f"{r['name']}: {f['message']}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri}}}],
                "partialFingerprints": {"mcpGradecard/v1": _fingerprint(
                    r, f)},
                "properties": {"severity": f["severity"],
                               "server": r["name"], "client": r["client"],
                               **({"project": r["project"]}
                                  if "project" in r else {})},
            }
            if sup is not None:
                item["suppressions"] = [{
                    "kind": "external", "status": "accepted",
                    "justification": f"{sup.get('reason')} "
                                     f"(until {sup.get('expires')})"}]
            elif baseline:
                item["baselineState"] = ("unchanged" if f.get("known")
                                         else "new")
            out.append(item)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcp-gradecard", "version": version,
                "informationUri":
                    "https://github.com/calasdan-sketch/mcp-gradecard",
                "rules": list(rules.values())}},
            "results": out,
        }],
    }
