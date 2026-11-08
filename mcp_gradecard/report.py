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
import re

from . import catalog, redact, scoring
from . import compare as compare_mod

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


SEVERITY_KEY = (
    ("critical", "the server runs a downloader, pipes content into a shell "
                 "or is started with encoded code, or a tool description "
                 "tries to take control of the agent; fix before using it"),
    ("high", "a serious weakness, such as a credential in a URL, a plain-http "
             "remote server or a code-injecting launch setting; fix soon"),
    ("medium", "weakens the setup or makes an attack easier, such as an "
               "unpinned package; plan a fix"),
    ("low", "hygiene; worth tidying"),
)


def _scope_rows(results: list[dict], configs: "list[dict] | None",
                version: str, deep: bool, when: str,
                prepared_by: "str | None", client: "str | None",
                scope_note: "str | None", reviewed_by: "str | None",
                online: bool, n_advisories: "int | None"
                ) -> "list[tuple[str, str]]":
    """The scope-and-method statement a buyer of a one-off audit expects:
    for whom, by whom, when, what was looked at, how, what was not, and
    whether a person read the serious findings. Plain (label, text) pairs;
    the renderers escape them."""
    def given(v):
        return v.strip() if isinstance(v, str) and v.strip() else None

    configs = configs or []
    n_files = len({c["path"] for c in configs})
    clients = sorted({str(c.get("client")) for c in configs if c.get("client")})
    rows = []
    if given(client):
        rows.append(("Prepared for", given(client)))
    if given(prepared_by):
        rows.append(("Prepared by", given(prepared_by)))
    rows.append(("Date and tool", f"{when}; mcp-gradecard {version}"))
    if n_files:
        examined = (f"{n_files} configuration file(s)"
                    + (f" ({', '.join(clients)})" if clients else "")
                    + f" holding {len(results)} MCP server(s). Only the "
                    "settings written in those files were read.")
    else:
        examined = (f"{len(results)} MCP server(s) from saved tool lists "
                    "or a built-in sample; no configuration file was read.")
    rows.append(("What was examined", examined))
    read = [r for r in results if r.get("deep_read") is not None]
    if deep:
        rows.append(("Live tool scan",
                     f"The tool lists of {len(read)} of {len(results)} "
                     "server(s) were read and scanned for prompt-injection "
                     "patterns; the others were not launched or were saved "
                     "lists, as each server's section says."))
    else:
        rows.append(("Live tool scan",
                     "Not done. No server was launched and no tool "
                     "description was read, so poisoned tool text is not "
                     "covered by this report."))
    rows.append(("Package lookups",
                 ("Online: package names and versions were also checked "
                  "against OSV."
                  if online else
                  "mcp-gradecard sent nothing anywhere"
                  + ("; the servers it launched may have contacted their "
                     "own services." if deep else "."))
                 + (f" The advisory feed in this version lists "
                    f"{n_advisories} known issue(s); a package with no "
                    "published advisory reads as clean."
                    if n_advisories is not None else "")))
    if given(scope_note):
        rows.append(("Engagement scope", given(scope_note)))
    rows.append(("Review by a person",
                 (f"Critical and high findings were read by "
                  f"{given(reviewed_by)} before this report was issued."
                  if given(reviewed_by) else
                  "Not recorded. Findings come from automatic rules; a "
                  "match is a lead for a person to confirm, not a verdict.")))
    rows.append(("Grades",
                 "A server starts at 100 and loses 40 per critical, 20 per "
                 "high, 10 per medium and 5 per low finding (A 90+, B 75+, "
                 "C 60+, D 40+, F below); any critical caps it at D. The "
                 "overall grade is the lowest. Grades are comparable only "
                 "between runs of the same mcp-gradecard version: newer "
                 "versions add checks."))
    return rows


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


CLAIMS = (
    "What this report supports: on the date shown, this version of "
    "mcp-gradecard found the findings listed in the configuration files and "
    "tool lists named in it.",
    "What it does not support: that any server is safe, secure or "
    "compliant with a standard. It is not a certification, a penetration "
    "test or a code review.",
)


def _report_id(results: list[dict]) -> str:
    """A short fingerprint of what the report found: the same findings give
    the same id, so two copies can be compared at a glance."""
    import hashlib
    from . import baseline
    ids = sorted(f.get("id") or baseline.finding_id(r, f)
                 for r in results for f in r["findings"])
    return hashlib.sha256("\n".join(ids).encode()).hexdigest()[:12]


def _inventory(results: list[dict]) -> "list[tuple[str, str, str]]":
    """(server, client, what it launches or connects to) for every server,
    from the config: packages with their pin state, remote hosts. Never
    arguments or paths (they can hold secrets)."""
    from . import detectors, supply
    rows = []
    for r in results:
        cfg = r.get("config")
        if not isinstance(cfg, dict) or cfg.get("toolFile"):
            rows.append((str(r["name"]), str(r["client"]), "saved tool list"))
            continue
        parts = []
        try:
            for p in detectors._iter_packages(cfg):
                if p.sure:
                    parts.append(f"{p.ecosystem} {p.name} "
                                 + (p.release() or "(not pinned)"))
            hosts = sorted({h for _w, u in detectors.remote_urls(cfg)
                            for h in [supply._host_only(u)] if h})
            parts += [f"remote {h}" for h in hosts]
        except Exception:                           # noqa: BLE001
            parts.append("(could not be read)")
        if not parts:
            parts.append("local command")
        rows.append((str(r["name"]), str(r["client"]), "; ".join(parts)))
    return rows


def _accepted(results: list[dict]) -> "list[tuple[dict, dict]]":
    return [(r, f) for r in results for f in r.get("suppressed") or []]


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
                generated: "str | None" = None,
                prepared_by: "str | None" = None,
                policy: "dict | None" = None,
                comparison: "dict | None" = None,
                client: "str | None" = None,
                scope_note: "str | None" = None,
                reviewed_by: "str | None" = None, online: bool = False,
                n_advisories: "int | None" = None) -> str:
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
      f"server(s) &middot; {'static + live tool scan (--deep)' if deep else 'static audit'}"
      + (f" &middot; prepared by {_h(prepared_by)}"
         if prepared_by and prepared_by.strip() else "")
      + f" &middot; report id {_report_id(results)}</div>")

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

    w("<h2>Scope and method</h2><section class=\"card\"><table>")
    for label, text in _scope_rows(results, configs, version, deep, when,
                                   prepared_by, client, scope_note,
                                   reviewed_by, online, n_advisories):
        w(f"<tr><th>{_h(label)}</th><td class=\"msg\">{_h(text)}</td></tr>")
    w("</table><p class=\"meta\">Severity: "
      + _h("; ".join(f"{k} = {v}" for k, v in SEVERITY_KEY))
      + ".</p></section>")

    if warnings:
        w('<section class="card warn"><h3>Not audited</h3><ul class="plain">')
        for wr in warnings:
            w(f"<li><code>{_h(wr['path'])}</code> &lt;{_h(wr['client'])}&gt;: "
              f"{_h(wr['reason'])}</li>")
        w("</ul></section>")

    if comparison:
        w("<h2>Since the previous check</h2><section class=\"card\">")
        w(f"<p><strong>{_h(compare_mod.summary_line(comparison))}"
          "</strong></p>")
        rows = ([("Resolved", i) for i in comparison["resolved"][:100]]
                + [("New", i) for i in comparison["new"][:100]])
        if rows:
            w("<table><tr><th>Change</th><th>Severity</th><th>Server</th>"
              "<th>Finding</th></tr>")
            for kind, i in rows:
                w(f"<tr><td>{kind}</td><td>{_sev(i['severity'])}</td>"
                  f"<td class=\"nm\">{_h(i['server'])}</td><td class=\"msg\">"
                  f"{_h(i['title'])}"
                  + (" (server removed)" if i.get("server_removed") else "")
                  + "</td></tr>")
            w("</table>")
        if comparison["grade_changes"]:
            w("<ul class=\"plain\">")
            for m in comparison["grade_changes"][:100]:
                w(f"<li><code>{_h(m['server'])}</code>: {_h(m['before'])} "
                  f"&rarr; {_h(m['after'])}</li>")
            w("</ul>")
        if comparison.get("note"):
            w(f'<div class="meta">{_h(comparison["note"])}</div>')
        w("</section>")

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

    accepted = _accepted(results)
    if accepted or (policy or {}).get("expired"):
        w("<h2>Accepted findings</h2><section class=\"card\"><table>")
        w("<tr><th>Server</th><th>Check</th><th>Reason</th><th>Until</th>"
          "</tr>")
        for r, f in accepted:
            sup = f.get("suppression") or {}
            w(f"<tr><td>{_h(r['name'])}</td><td>{_h(f['check'])}</td>"
              f"<td class=\"msg\">{_h(sup.get('reason'))}</td>"
              f"<td>{_h(sup.get('expires'))}</td></tr>")
        w("</table><p class=\"meta\">These findings were accepted by the "
          "owner of the configuration, each for a stated reason and until a "
          "date; they are left out of the grades above.")
        for e in (policy or {}).get("expired") or []:
            w(f" A suppression of {_h(e['check'])} expired on "
              f"{_h(e['expires'])} and no longer applies.")
        w("</p></section>")

    w("<h2>Inventory</h2><section class=\"card\"><table>")
    w('<tr><th>Server</th><th class="hide">Client</th><th>Runs or connects '
      "to</th></tr>")
    for name, client, what in _inventory(results):
        w(f"<tr><td>{_h(name)}</td><td class=\"hide\">{_h(client)}</td>"
          f"<td class=\"msg\">{_h(what)}</td></tr>")
    w("</table></section>")

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
    for line in LIMITS + CLAIMS:
        w(f"<li>{_h(line)}</li>")
    w("</ul></section>")
    w(f"<footer>mcp-gradecard {_h(version)} &middot; "
      "secrets found in configs are never printed in this report.</footer>")
    w("</main></body></html>")
    return "\n".join(out)


# -- Markdown -----------------------------------------------------------------

_MD_SPECIAL = set("\\`*_{}[]<>|~#!&")


_EMAIL_AT = re.compile(r"(?<=[A-Za-z0-9._%+\-])@(?=[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*"
                       r"\.[A-Za-z]{2,})")


def _defang(text: str) -> str:
    """Break what a GitHub-flavoured renderer would turn into a link on its
    own (`https://...`, `www.`, an e-mail address), the way security reports
    write indicators: https[:]//host, www[.]host, user[@]host."""
    text = re.sub(r"(?i)\b([a-z][a-z0-9+.\-]{0,20}):(?=//)", r"\1[:]", text)
    text = re.sub(r"(?i)\bwww\.", "www[.]", text)
    return _EMAIL_AT.sub("[@]", text)


def _mc(text) -> str:
    """Untrusted text as a Markdown code span: nothing inside one is markup,
    a link or an auto-link. A `|` is escaped for the table it may sit in, and
    the fence is longer than any run of backticks in the text."""
    body = redact.sanitize(str(text)).replace("|", "\\|")
    if not body:
        return "` `"
    run = max((len(m) for m in re.findall(r"`+", body)), default=0)
    fence = "`" * (run + 1)
    pad = " " if body.startswith("`") or body.endswith("`") or run else ""
    return f"{fence}{pad}{body}{pad}{fence}"


def _m(text) -> str:
    """Untrusted text, inert in Markdown: every character that could start
    markup (a link, an image, raw HTML, a table cell) is escaped, and what
    would be auto-linked is defanged."""
    out = []
    for ch in _defang(redact.sanitize(str(text))):
        if ch == "&":
            out.append("&amp;")
        elif ch in _MD_SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _ours(text: str) -> str:
    """This project's own remediation text: its `code` stays code, the rest
    is escaped like anything else."""
    parts = re.split(r"(`[^`]+`)", text)
    return "".join(p if p.startswith("`") and p.endswith("`") and len(p) > 1
                   else _m(p) for p in parts)


def render_markdown(results: list[dict],
                    warnings: "list[dict] | None" = None,
                    configs: "list[dict] | None" = None, version: str = "",
                    title: "str | None" = None, deep: bool = False,
                    generated: "str | None" = None,
                    prepared_by: "str | None" = None,
                    policy: "dict | None" = None,
                    comparison: "dict | None" = None,
                    client: "str | None" = None,
                    scope_note: "str | None" = None,
                    reviewed_by: "str | None" = None, online: bool = False,
                    n_advisories: "int | None" = None) -> str:
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
                else "static audit")
             + (f" · prepared by {_m(prepared_by)}"
                if prepared_by and prepared_by.strip() else "")
             + f" · report id {_report_id(results)}", "",
             (f"**Overall grade: {_worst_grade(results)}** "
              "(the lowest grade of any server)" if results
              else "**Overall grade: n/a** (no servers)"), "",
             _m(_verdict(results, warnings, n_configs)), "",
             "| Critical | High | Medium | Low |", "|---|---|---|---|",
             f"| {counts['critical']} | {counts['high']} | "
             f"{counts['medium']} | {counts['low']} |", ""]
    lines += ["## Scope and method", ""]
    lines += [f"- **{_m(label)}:** {_m(text)}" for label, text in
              _scope_rows(results, configs, version, deep, when, prepared_by,
                          client, scope_note, reviewed_by, online,
                          n_advisories)]
    lines += ["", "Severity: " + _m("; ".join(f"{k} = {v}"
                                            for k, v in SEVERITY_KEY)) + ".",
              ""]
    if warnings:
        lines += ["## Not audited", ""]
        lines += [f"- {_mc(w['path'])} ({_mc(w['client'])}): {_m(w['reason'])}"
                  for w in warnings]
        lines.append("")
    if comparison:
        lines += ["## Since the previous check", "",
                  f"**{_m(compare_mod.summary_line(comparison))}**", ""]
        rows = ([("Resolved", i) for i in comparison["resolved"][:100]]
                + [("New", i) for i in comparison["new"][:100]])
        if rows:
            lines += ["| Change | Severity | Server | Finding |",
                      "|---|---|---|---|"]
            for kind, i in rows:
                lines.append(
                    f"| {kind} | {i['severity'].upper()} | {_mc(i['server'])} "
                    f"| {_m(i['title'])}"
                    + (" (server removed)" if i.get("server_removed") else "")
                    + " |")
            lines.append("")
        for m in comparison["grade_changes"][:100]:
            lines.append(f"- {_mc(m['server'])}: {_m(m['before'])} to "
                         f"{_m(m['after'])}")
        if comparison["grade_changes"]:
            lines.append("")
        if comparison.get("note"):
            lines += [_m(comparison["note"]), ""]
    top = _top(results)
    if top:
        lines += ["## Fix these first", "",
                  "| Severity | Server | Finding |", "|---|---|---|"]
        for r, f in top:
            lines.append(f"| {f['severity'].upper()} | {_mc(r['name'])} | "
                         f"**{_m(catalog.title(f['check']))}**: "
                         f"{_m(f['message'])} |")
        lines.append("")
    if results:
        lines += ["## Servers", "",
                  "| Grade | Server | Client | Score | Findings |",
                  "|---|---|---|---|---|"]
        ordered = sorted(results, key=lambda x: (x["score"], x["name"]))
        for r in ordered:
            lines.append(f"| {r['grade']} | {_mc(r['name'])} | "
                         f"{_mc(r['client'])} | {r['score']}/100 | "
                         f"{len(r['findings'])} |")
        lines.append("")
        lines += ["## Findings by server", ""]
        for r in ordered:
            lines += [f"### [{r['grade']}] {_mc(r['name'])} "
                      f"({_mc(r['client'])}, {r['score']}/100)", "",
                      f"{_mc(r['path'])}"
                      + (f" (project: {_mc(r['project'])})"
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
                lines += [f"- **{_m(catalog.title(c))}**: {_ours(t)}"
                          for c, t in remedies]
                lines.append("")
    accepted = _accepted(results)
    if accepted or (policy or {}).get("expired"):
        lines += ["## Accepted findings", "",
                  "| Server | Check | Reason | Until |", "|---|---|---|---|"]
        for r, f in accepted:
            sup = f.get("suppression") or {}
            lines.append(f"| {_mc(r['name'])} | {_m(f['check'])} | "
                         f"{_m(sup.get('reason'))} | "
                         f"{_m(sup.get('expires'))} |")
        lines += ["", "Accepted by the owner of the configuration, each for "
                  "a stated reason and until a date; left out of the "
                  "grades above."]
        for e in (policy or {}).get("expired") or []:
            lines.append(f"A suppression of {_m(e['check'])} expired on "
                         f"{_m(e['expires'])} and no longer applies.")
        lines.append("")
    lines += ["## Inventory", "", "| Server | Client | Runs or connects to |",
              "|---|---|---|"]
    lines += [f"| {_mc(n)} | {_mc(c)} | {_m(w)} |"
              for n, c, w in _inventory(results)]
    lines.append("")
    empty = _empty_configs(configs)
    if empty:
        lines += ["## Config files with no servers", ""]
        lines += [f"- {_mc(c['path'])} ({_mc(c['client'])})" for c in empty]
        lines.append("")
    lines += ["## OWASP MCP Top 10", "", "| Risk | Findings |", "|---|---|"]
    for ref, n in _owasp_counts(results).items():
        lines.append(f"| {ref} {_m(catalog.OWASP[ref])} | {n} |")
    lines += ["", "The mapping is mcp-gradecard's reading of which risk each "
              "finding is evidence of; a zero means no finding of that kind, "
              f"not that the risk is absent. Source: {catalog.OWASP_URL} "
              "(beta).", "", "## What this audit covers", ""]
    lines += [f"- {_m(line)}" for line in LIMITS + CLAIMS]
    lines += ["", "Secrets found in configs are never printed in this "
              "report.", ""]
    return "\n".join(lines)
