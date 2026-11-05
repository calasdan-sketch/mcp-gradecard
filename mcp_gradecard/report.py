"""The HTML and Markdown reports: an audit you can read top to bottom or hand
to someone else.

Both say the same things in the same order: the overall grade and what it
rests on, the risks that matter most, one section per server with what to do
about each finding, the OWASP MCP Top 10 risks the findings are evidence of,
and what the audit did and did not look at.

Everything shown that came from a config or a server (names, paths,
messages) is untrusted: it is sanitized (control and bidi characters spelled
out) and then escaped for the format. The HTML page has no scripts and loads
nothing, and its Content-Security-Policy says so to the browser.
"""

from __future__ import annotations

import datetime
import html

from . import catalog, redact, scoring

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_GRADES = "ABCDF"
_TOP = 5            # findings in "what to fix first"

DEFAULT_TITLE = "MCP Safety Report"

LIMITS = (
    "The static audit reads configuration files only; it does not run or "
    "connect to any server.",
    "With --deep, tool descriptions are read from the servers it was "
    "allowed to launch and checked against known prompt-injection patterns. "
    "That is a heuristic: a clean scan is not proof that a server is safe, "
    "and a match is a lead for a person to read, not a verdict.",
    "Remote (http/sse) servers are judged by their configuration; their live "
    "tool lists are not fetched.",
    "Known-vulnerable packages are matched against the advisory feed built "
    "into this version (and OSV with --online); a package with no published "
    "advisory reads as clean.",
    "Nothing here reviews a server's source code or what its tools do when "
    "called.",
)


def _worst_grade(results: list[dict]) -> str:
    if not results:
        return "?"
    return max((r["grade"] for r in results), key=_GRADES.index)


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: _SEV_ORDER.get(f["severity"], 9))


def _top(results: list[dict]) -> "list[tuple[dict, dict]]":
    pairs = [(r, f) for r in results for f in r["findings"]
             if f["severity"] in ("critical", "high")]
    pairs.sort(key=lambda p: (_SEV_ORDER.get(p[1]["severity"], 9),
                              p[0]["score"]))
    return pairs[:_TOP]


def _owasp_counts(results: list[dict]) -> "dict[str, int]":
    counts = {k: 0 for k in catalog.OWASP}
    for r in results:
        for f in r["findings"]:
            for ref in catalog.owasp(f["check"]):
                counts[ref] += 1
    return counts


def _verdict(results: list[dict], warnings: list[dict],
             n_configs: int) -> str:
    """One plain sentence on top of the report."""
    summary = scoring.summarize(results)["by_severity"]
    if n_configs == 0:
        return ("No MCP configuration was found, so nothing was audited. "
                "This is not a clean bill of health.")
    if not results:
        return "The configurations found hold no MCP servers."
    if summary["critical"]:
        text = (f"{summary['critical']} critical finding(s): act on these "
                "before you use these servers again.")
    elif summary["high"]:
        text = (f"{summary['high']} high finding(s) need attention; nothing "
                "critical was found.")
    elif summary["medium"] or summary["low"]:
        text = ("No critical or high findings. The medium and low ones are "
                "worth a look.")
    else:
        text = "No findings."
    if warnings:
        text += (f" {len(warnings)} config file(s) could not be audited, so "
                 "this is not a clean bill of health.")
    return text


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC")


def _remedies(findings: list[dict]) -> "list[tuple[str, str]]":
    seen = []
    for f in _sorted_findings(findings):
        if f["check"] not in [c for c, _ in seen] \
                and catalog.remediation(f["check"]):
            seen.append((f["check"], catalog.remediation(f["check"])))
    return seen


def _empty_configs(configs: "list[dict] | None") -> "list[dict]":
    return [c for c in configs or [] if not c.get("servers")]


# -- HTML ---------------------------------------------------------------------

def _h(text) -> str:
    """Untrusted text, safe inside HTML element content or a quoted
    attribute."""
    return html.escape(redact.sanitize(str(text)), quote=True)


_CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1c1d1f;--muted:#5d6168;--line:#e3e3df;
--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#4b5563;--ok:#15803d;
--chip:#efefeb;--a:#15803d;--b:#4d7c0f;--c:#a16207;--d:#c2410c;--f:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#111214;--card:#1a1b1e;
--ink:#e8e8e6;--muted:#a1a4aa;--line:#2c2e33;--chip:#26282c;--crit:#f2867e;
--high:#fb923c;--med:#facc15;--low:#9ca3af;--ok:#4ade80;--a:#4ade80;
--b:#a3e635;--c:#facc15;--d:#fb923c;--f:#f2867e}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55
-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px}
h3{font-size:16px;margin:0}
.meta{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:18px 20px;margin:12px 0}
.hero{display:flex;gap:20px;align-items:center;flex-wrap:wrap}
.hero>div:last-child{flex:1;min-width:240px}
td.nm{white-space:nowrap}
code{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
background:var(--chip);border-radius:4px;padding:0 4px}
.grade{width:76px;height:76px;border-radius:14px;display:flex;
align-items:center;justify-content:center;font-size:42px;font-weight:700;
color:#fff;flex:none}
.g-A{background:var(--a)}.g-B{background:var(--b)}.g-C{background:var(--c)}
.g-D{background:var(--d)}.g-F{background:var(--f)}.g-\\?{background:var(--low)}
.grade.sm{width:34px;height:34px;font-size:18px;border-radius:8px}
.verdict{font-size:17px;font-weight:600;margin:0 0 6px}
.counts{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}
.pill{border-radius:999px;padding:2px 10px;font-size:13px;font-weight:600;
background:var(--chip)}
.sev{display:inline-block;min-width:70px;text-align:center;border-radius:6px;
padding:1px 6px;font-size:12px;font-weight:700;text-transform:uppercase;
color:#fff}
.s-critical{background:var(--crit)}.s-high{background:var(--high)}
.s-medium{background:var(--med)}.s-low{background:var(--low)}
@media (prefers-color-scheme:dark){.sev,.grade{color:#111214}}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);
vertical-align:top}
th{font-size:12px;color:var(--muted);text-transform:uppercase;
letter-spacing:.04em}
td.msg{overflow-wrap:anywhere}
.server-head{display:flex;gap:12px;align-items:center}
.path{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.tag{display:inline-block;background:var(--chip);border-radius:5px;
padding:0 6px;margin:1px 2px 1px 0;font-size:12px;white-space:nowrap}
.fix{margin:10px 0 0;padding-left:18px}.fix li{margin:4px 0}
.ok{color:var(--ok);font-weight:600}
.warn{border-left:4px solid var(--high)}
ul.plain{margin:6px 0;padding-left:18px}
footer{margin-top:40px;color:var(--muted);font-size:12px}
a{color:inherit}
@media print{body{background:#fff}.card{break-inside:avoid}main{padding:0}}
@media (max-width:640px){th.hide,td.hide{display:none}}
"""


def _code(text: str) -> str:
    """Our own remediation text (never config text): `x` becomes code."""
    import re
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", _h(text))


def _sev(severity: str) -> str:
    sev = severity if severity in _SEV_ORDER else "low"
    return f'<span class="sev s-{sev}">{_h(sev)}</span>'


def _tags(check: str) -> str:
    return "".join(
        f'<span class="tag" title="{_h(catalog.OWASP[ref])}">{ref}</span>'
        for ref in catalog.owasp(check))


def _grade(grade: str, small: bool = False) -> str:
    g = grade if grade in _GRADES else "?"
    return (f'<div class="grade{" sm" if small else ""} g-{g}" '
            f'aria-label="grade {g}">{g}</div>')


def render_html(results: list[dict], warnings: "list[dict] | None" = None,
                configs: "list[dict] | None" = None, version: str = "",
                title: "str | None" = None, deep: bool = False,
                generated: "str | None" = None) -> str:
    """A self-contained HTML report (inline styles, no scripts, no external
    resources)."""
    warnings = warnings or []
    configs = configs or []
    n_configs = len({c["path"] for c in configs})
    counts = scoring.summarize(results)["by_severity"]
    title = title if title is not None and title.strip() else DEFAULT_TITLE
    when = generated or _now()
    overall = _worst_grade(results)
    out = []
    w = out.append
    w("<!doctype html>")
    w('<html lang="en"><head><meta charset="utf-8">')
    w('<meta name="viewport" content="width=device-width,initial-scale=1">')
    w('<meta http-equiv="Content-Security-Policy" content="default-src '
      "'none'; style-src 'unsafe-inline'\">")
    w('<meta name="referrer" content="no-referrer">')
    w(f"<title>{_h(title)}</title><style>{_CSS}</style></head><body><main>")
    w(f"<h1>{_h(title)}</h1>")
    w(f'<div class="meta">Generated {_h(when)} by mcp-gradecard {_h(version)}'
      f" &middot; {n_configs} config file(s) &middot; {len(results)} "
      f"server(s) &middot; {'static + live tool scan (--deep)' if deep else 'static audit'}</div>")

    # verdict
    w('<section class="card hero">')
    w(_grade(overall))
    w("<div>")
    w(f'<p class="verdict">{_h(_verdict(results, warnings, n_configs))}</p>')
    w('<div class="meta">Overall grade is the lowest grade of any server. '
      "Each server starts at 100 and loses 40 per critical, 20 per high, "
      "10 per medium and 5 per low finding; any critical caps it at D.</div>")
    w('<div class="counts">')
    for sev in ("critical", "high", "medium", "low"):
        w(f'<span class="pill">{_sev(sev)} {counts[sev]}</span>')
    w("</div></div></section>")

    if warnings:
        w('<section class="card warn"><h3>Not audited</h3><ul class="plain">')
        for wr in warnings:
            w(f"<li><code>{_h(wr['path'])}</code> &lt;{_h(wr['client'])}&gt;: "
              f"{_h(wr['reason'])}</li>")
        w("</ul></section>")

    top = _top(results)
    if top:
        w("<h2>Fix these first</h2><section class=\"card\"><table>")
        w("<tr><th>Severity</th><th>Server</th><th>Finding</th></tr>")
        for r, f in top:
            w(f"<tr><td>{_sev(f['severity'])}</td><td class=\"nm\">"
              f"{_h(r['name'])}</td>"
              f'<td class="msg"><strong>{_h(catalog.title(f["check"]))}'
              f"</strong><br>{_h(f['message'])}</td></tr>")
        w("</table></section>")

    if results:
        w("<h2>Servers</h2><section class=\"card\"><table>")
        w('<tr><th>Grade</th><th>Server</th><th class="hide">Client</th>'
          "<th>Score</th><th>Findings</th></tr>")
        for r in sorted(results, key=lambda x: (x["score"], x["name"])):
            c = {s: 0 for s in _SEV_ORDER}
            for f in r["findings"]:
                c[f["severity"]] = c.get(f["severity"], 0) + 1
            parts = [f"{c[s]} {s}" for s in _SEV_ORDER if c[s]]
            w(f"<tr><td>{_grade(r['grade'], True)}</td>"
              f"<td>{_h(r['name'])}</td><td class=\"hide\">{_h(r['client'])}"
              f"</td><td>{r['score']}/100</td>"
              f"<td>{_h(', '.join(parts) or 'none')}</td></tr>")
        w("</table></section>")

        w("<h2>Findings by server</h2>")
        for r in sorted(results, key=lambda x: (x["score"], x["name"])):
            w('<section class="card"><div class="server-head">')
            w(_grade(r["grade"], True))
            w(f"<div><h3>{_h(r['name'])} <span class=\"meta\">"
              f"&lt;{_h(r['client'])}&gt; &middot; {r['score']}/100</span>"
              f'</h3><div class="path">{_h(r["path"])}'
              + (f" (project: {_h(r['project'])})" if "project" in r else "")
              + "</div></div></div>")
            if r["findings"]:
                w('<table><tr><th>Severity</th><th>Finding</th>'
                  '<th class="hide">OWASP MCP</th></tr>')
                for f in _sorted_findings(r["findings"]):
                    w(f"<tr><td>{_sev(f['severity'])}</td>"
                      f'<td class="msg"><strong>{_h(catalog.title(f["check"]))}'
                      f"</strong> <span class=\"meta\">({_h(f['check'])})"
                      f"</span><br>{_h(f['message'])}</td>"
                      f'<td class="hide">{_tags(f["check"])}</td></tr>')
                w("</table>")
                remedies = _remedies(r["findings"])
                if remedies:
                    w('<p class="meta" style="margin:12px 0 0">What to do'
                      '</p><ul class="fix">')
                    for check, text in remedies:
                        w(f"<li><strong>{_h(catalog.title(check))}:</strong> "
                          f"{_code(text)}</li>")
                    w("</ul>")
            else:
                deep_line = scoring._deep_line(r)
                w(f'<p class="ok">{_h(deep_line or "No findings.")}</p>')
            w("</section>")

    empty = _empty_configs(configs)
    if empty:
        w("<h2>Config files with no servers</h2><section class=\"card\">"
          '<ul class="plain">')
        for c in empty:
            w(f"<li><code>{_h(c['path'])}</code> &lt;{_h(c['client'])}&gt;"
              "</li>")
        w("</ul></section>")

    w("<h2>OWASP MCP Top 10</h2><section class=\"card\"><table>")
    w("<tr><th>Risk</th><th>Findings</th></tr>")
    for ref, n in _owasp_counts(results).items():
        w(f"<tr><td><span class=\"tag\">{ref}</span> "
          f"{_h(catalog.OWASP[ref])}</td><td>{n}</td></tr>")
    w("</table><p class=\"meta\">The mapping is mcp-gradecard's reading of "
      "which risk each finding is evidence of. A zero means no finding of "
      "that kind, not that the risk is absent. Source: "
      f'<a href="{catalog.OWASP_URL}">OWASP MCP Top 10</a> (beta).</p>'
      "</section>")

    w("<h2>What this audit covers</h2><section class=\"card\">"
      '<ul class="plain">')
    for line in LIMITS:
        w(f"<li>{_h(line)}</li>")
    w("</ul></section>")
    w(f"<footer>mcp-gradecard {_h(version)} &middot; "
      "secrets found in configs are never printed in this report.</footer>")
    w("</main></body></html>")
    return "\n".join(out)


# -- Markdown -----------------------------------------------------------------

_MD_SPECIAL = set("\\`*_{}[]<>|~#!&")


def _m(text) -> str:
    """Untrusted text, inert in Markdown: every character that could start
    markup (a link, an image, raw HTML, a table cell) is escaped."""
    out = []
    for ch in redact.sanitize(str(text)):
        if ch == "&":
            out.append("&amp;")
        elif ch in _MD_SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def render_markdown(results: list[dict],
                    warnings: "list[dict] | None" = None,
                    configs: "list[dict] | None" = None, version: str = "",
                    title: "str | None" = None, deep: bool = False,
                    generated: "str | None" = None) -> str:
    """The same report as render_html, in Markdown (a PR comment, a ticket,
    a wiki page)."""
    warnings = warnings or []
    configs = configs or []
    n_configs = len({c["path"] for c in configs})
    counts = scoring.summarize(results)["by_severity"]
    title = title if title is not None and title.strip() else DEFAULT_TITLE
    when = generated or _now()
    lines = [f"# {_m(title)}", "",
             f"Generated {_m(when)} by mcp-gradecard {_m(version)} · "
             f"{n_configs} config file(s) · {len(results)} server(s) · "
             + ("static + live tool scan (--deep)" if deep
                else "static audit"), "",
             (f"**Overall grade: {_worst_grade(results)}** "
              "(the lowest grade of any server)" if results
              else "**Overall grade: n/a** (no servers)"), "",
             _m(_verdict(results, warnings, n_configs)), "",
             "| Critical | High | Medium | Low |", "|---|---|---|---|",
             f"| {counts['critical']} | {counts['high']} | "
             f"{counts['medium']} | {counts['low']} |", ""]
    if warnings:
        lines += ["## Not audited", ""]
        lines += [f"- {_m(w['path'])} ({_m(w['client'])}): {_m(w['reason'])}"
                  for w in warnings]
        lines.append("")
    top = _top(results)
    if top:
        lines += ["## Fix these first", "",
                  "| Severity | Server | Finding |", "|---|---|---|"]
        for r, f in top:
            lines.append(f"| {f['severity'].upper()} | {_m(r['name'])} | "
                         f"**{_m(catalog.title(f['check']))}**: "
                         f"{_m(f['message'])} |")
        lines.append("")
    if results:
        lines += ["## Servers", "",
                  "| Grade | Server | Client | Score | Findings |",
                  "|---|---|---|---|---|"]
        ordered = sorted(results, key=lambda x: (x["score"], x["name"]))
        for r in ordered:
            lines.append(f"| {r['grade']} | {_m(r['name'])} | "
                         f"{_m(r['client'])} | {r['score']}/100 | "
                         f"{len(r['findings'])} |")
        lines.append("")
        lines += ["## Findings by server", ""]
        for r in ordered:
            lines += [f"### [{r['grade']}] {_m(r['name'])} "
                      f"({_m(r['client'])}, {r['score']}/100)", "",
                      f"{_m(r['path'])}"
                      + (f" (project: {_m(r['project'])})"
                         if "project" in r else ""), ""]
            if not r["findings"]:
                lines += [_m(scoring._deep_line(r) or "No findings."), ""]
                continue
            lines += ["| Severity | Check | Finding | OWASP MCP |",
                      "|---|---|---|---|"]
            for f in _sorted_findings(r["findings"]):
                lines.append(
                    f"| {f['severity'].upper()} | {_m(f['check'])} | "
                    f"**{_m(catalog.title(f['check']))}**: "
                    f"{_m(f['message'])} | "
                    f"{', '.join(catalog.owasp(f['check']))} |")
            lines.append("")
            remedies = _remedies(r["findings"])
            if remedies:
                lines += ["What to do:", ""]
                lines += [f"- **{_m(catalog.title(c))}**: {_m(t)}"
                          for c, t in remedies]
                lines.append("")
    empty = _empty_configs(configs)
    if empty:
        lines += ["## Config files with no servers", ""]
        lines += [f"- {_m(c['path'])} ({_m(c['client'])})" for c in empty]
        lines.append("")
    lines += ["## OWASP MCP Top 10", "", "| Risk | Findings |", "|---|---|"]
    for ref, n in _owasp_counts(results).items():
        lines.append(f"| {ref} {_m(catalog.OWASP[ref])} | {n} |")
    lines += ["", "The mapping is mcp-gradecard's reading of which risk each "
              "finding is evidence of; a zero means no finding of that kind, "
              f"not that the risk is absent. Source: {catalog.OWASP_URL} "
              "(beta).", "", "## What this audit covers", ""]
    lines += [f"- {_m(line)}" for line in LIMITS]
    lines += ["", "Secrets found in configs are never printed in this "
              "report.", ""]
    return "\n".join(lines)
