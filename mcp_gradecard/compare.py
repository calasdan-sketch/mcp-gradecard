"""Before and after: what a previous check found, set against this one.

`--compare PREVIOUS.json` takes an earlier `--format json` report (or a
baseline file) and says which findings are gone, which are new, which are
still open and how each server's grade moved. This is what a paid check is
re-run for: "you had 7 findings, 5 are fixed, 2 remain".

Rules that keep it honest:

* The previous file is untrusted text: only strings and small numbers are
  read from it, every string is cut and later escaped by the renderers.
* A finding that came from the live tool scan (`--deep`) is reported as
  fixed only when both runs were deep. A static run cannot see it, and
  "not looked for" is not "fixed".
* A server that is no longer in the configuration is listed as removed, and
  its findings count as resolved because of that, not because they were
  repaired.
* A previous file that is not a gradecard report is refused (exit 2).
"""

from __future__ import annotations

import json

from . import baseline as baseline_mod

MAX_FILE = 16_000_000
_TEXT = 300
_DEEP_CHECKS = {"tool-description-injection", "tool-changed", "tool-added",
                "tool-removed", "tool-shadowing", "deep-probe"}
_GRADES = "ABCDF"
_SEVERITIES = {"critical", "high", "medium", "low"}


class CompareError(Exception):
    """The previous report cannot be used. The message is safe to print."""


def _s(value, limit: int = _TEXT) -> str:
    return value[:limit] if isinstance(value, str) else ""


def load(path: str) -> dict:
    """The parts of an earlier report that a comparison uses."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_FILE + 1)
    except OSError as e:
        raise CompareError(f"cannot read --compare file: "
                           f"{e.strerror or type(e).__name__}")
    if len(raw) > MAX_FILE:
        raise CompareError(f"--compare file is larger than {MAX_FILE} bytes")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        raise CompareError("--compare file is not valid JSON")
    if not isinstance(data, dict):
        raise CompareError("--compare file is not an mcp-gradecard report")
    tool = data.get("tool")
    findings_only = (data.get("schema") == baseline_mod.SCHEMA
                     and isinstance(data.get("findings"), list))
    if findings_only:
        servers = {}
        items = []
        for item in data["findings"][:200_000]:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                items.append({"id": _s(item["id"], 64),
                              "server": _s(item.get("server")),
                              "client": _s(item.get("client")),
                              "check": _s(item.get("check")),
                              "severity": _s(item.get("severity")),
                              "title": ""})
        return {"version": _s(data.get("version"), 40), "deep": None,
                "overall": None, "servers": servers, "findings": items}
    if (tool is None and "schema_version" not in data and "schema" not in data
            and isinstance(data.get("results"), list)
            and all(isinstance(r, dict) and "findings" in r
                    for r in data["results"][:50])):
        raise CompareError("--compare file looks like a report from "
                           "mcp-gradecard 0.3.0 or earlier, which did not "
                           "number its findings: it cannot be compared; run "
                           "the earlier check again with this version")
    if not (isinstance(tool, dict) and tool.get("name") == "mcp-gradecard"
            and data.get("schema_version") == 1
            and isinstance(data.get("results"), list)):
        raise CompareError("--compare file is not an mcp-gradecard report "
                           "(expected the output of --format json, or a "
                           "--write-baseline file)")
    servers = {}
    items = []
    unnumbered = 0
    for r in data["results"][:20_000]:
        if not isinstance(r, dict):
            continue
        key = (_s(r.get("client")), _s(r.get("name")))
        grade = r.get("grade") if r.get("grade") in tuple(_GRADES) else None
        servers[key] = grade
        for f in (r.get("findings") or [])[:5_000] + \
                (r.get("suppressed") or [])[:5_000]:
            if isinstance(f, dict) and not isinstance(f.get("id"), str):
                unnumbered += 1
            if isinstance(f, dict) and isinstance(f.get("id"), str):
                items.append({"id": _s(f["id"], 64), "server": key[1],
                              "client": key[0], "check": _s(f.get("check")),
                              "severity": _s(f.get("severity")),
                              "title": _s(f.get("title"))})
    if unnumbered:
        raise CompareError("--compare file has findings without an id (a "
                           "report from before 0.5.0): it cannot be compared; "
                           "run the earlier check again with this version")
    scan = data.get("scan")
    deep = scan.get("deep") if isinstance(scan, dict) and isinstance(
        scan.get("deep"), bool) else None
    grades = [g for g in servers.values() if g]
    overall = max(grades, key=_GRADES.index) if grades else None
    return {"version": _s((tool or {}).get("version"), 40), "deep": deep,
            "overall": overall, "servers": servers, "findings": items}


def compare(previous: dict, results: list, deep: bool) -> dict:
    """What changed. `results` carry finding ids (baseline.apply sets them)."""
    from . import catalog
    now_ids = {}
    now_servers = {}
    for r in results:
        key = (str(r.get("client")), str(r.get("name")))
        now_servers[key] = r.get("grade")
        for f in list(r.get("findings") or []) + list(r.get("suppressed") or []):
            if f.get("id"):
                now_ids[f["id"]] = (key, f)
    comparable_deep = bool(deep) and previous.get("deep") is True
    resolved, not_comparable = [], 0
    still = 0
    prev_ids = set()
    for item in previous["findings"]:
        prev_ids.add(item["id"])
        if item["id"] in now_ids:
            still += 1
            continue
        key = (item["client"], item["server"])
        if item["check"] in _DEEP_CHECKS and not comparable_deep \
                and key in now_servers:
            not_comparable += 1
            continue
        resolved.append({
            "server": item["server"], "client": item["client"],
            "check": item["check"], "severity": item["severity"],
            "title": item["title"] or catalog.title(item["check"]),
            "server_removed": key not in now_servers})
    new = [{"server": key[1], "client": key[0], "check": f["check"],
            "severity": f["severity"], "title": catalog.title(f["check"])}
           for i, (key, f) in now_ids.items() if i not in prev_ids]
    # The same check on the same server with the same severity, worded
    # differently (a host or a version changed in the message), is the same
    # problem still open, not one fixed and one new.
    kept = []
    for n in new:
        match = next((r for r in resolved
                      if (r["client"], r["server"], r["check"], r["severity"])
                      == (n["client"], n["server"], n["check"], n["severity"])),
                     None)
        if match is not None:
            resolved.remove(match)
            still += 1
        else:
            kept.append(n)
    new = kept
    moves = [{"server": k[1], "client": k[0], "before": previous["servers"][k],
              "after": g} for k, g in now_servers.items()
             if k in previous["servers"] and previous["servers"][k]
             and previous["servers"][k] != g]
    added = [{"server": k[1], "client": k[0], "grade": g}
             for k, g in now_servers.items() if k not in previous["servers"]
             and previous["servers"]]
    gone = [{"server": k[1], "client": k[0], "grade": g}
            for k, g in previous["servers"].items() if k not in now_servers]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for lst in (resolved, new):
        lst.sort(key=lambda x: (order.get(x["severity"], 9), x["server"],
                                x["check"]))
    grades = [r["grade"] for r in results if r.get("grade") in tuple(_GRADES)]
    return {
        "previous_version": previous["version"],
        "previous_overall": previous["overall"],
        "overall": max(grades, key=_GRADES.index) if grades else None,
        "resolved": resolved, "new": new, "still_open": still,
        "grade_changes": moves, "servers_added": added,
        "servers_removed": gone,
        "not_comparable": not_comparable,
        "note": ("Findings of the live tool scan are compared only when both "
                 "runs used --deep." if not_comparable else ""),
    }


def summary_line(c: dict) -> str:
    bits = [f"{len(c['resolved'])} resolved", f"{c['still_open']} still open",
            f"{len(c['new'])} new"]
    head = ""
    if c.get("previous_overall") and c.get("overall"):
        head = (f"overall grade {c['previous_overall']} -> {c['overall']}; "
                if c["previous_overall"] != c["overall"]
                else f"overall grade unchanged at {c['overall']}; ")
    return head + ", ".join(bits)
