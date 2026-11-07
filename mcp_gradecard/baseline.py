"""Baselines and suppressions: what a team has already looked at.

Two files, both explicit (never found by themselves: a cloned repository
could otherwise ship a suppression file that hides its own findings):

* a **baseline** (`--write-baseline FILE`, then `--baseline FILE`): the
  findings that exist today. A later run still reports them, marked
  `known`, but `--fail-on` only counts findings that are new. This is the
  way to add the gate to a team that already has findings.
* **suppressions** (`--suppressions FILE`): a finding somebody decided to
  live with, each with a written reason and an expiry date. A suppressed
  finding leaves the grade and the gate, and stays visible in the report
  with its reason and date. When the date passes the finding is back, and
  the run says so. A file with no reason, no date, a bad date or a date
  more than a year away is refused (exit 2): a gate must not be switched
  off by a typo.

The id of a finding does not contain a path, so a baseline written on one
machine matches the same finding on a CI runner.
"""

from __future__ import annotations

import datetime
import fnmatch
import hashlib
import json
import os
import re
import tempfile

SCHEMA = 1
MAX_FILE = 4_000_000
MAX_ENTRIES = 5000
MAX_HORIZON_DAYS = 366
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")


class PolicyError(Exception):
    """A baseline or suppression file that cannot be used. The message is
    safe to print."""


def finding_id(result: dict, finding: dict) -> str:
    """Stable across machines: client, server name, check and the message
    with its numbers left out. Not the path, not the project directory."""
    text = re.sub(r"[0-9]+", "#", str(finding.get("message")))
    key = json.dumps([result.get("client"), result.get("name"),
                      finding.get("check"), text], ensure_ascii=False)
    return hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def _read(path: str, what: str):
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_FILE + 1)
    except OSError as e:
        raise PolicyError(f"cannot read {what} file: "
                          f"{e.strerror or type(e).__name__}")
    if len(raw) > MAX_FILE:
        raise PolicyError(f"{what} file is larger than {MAX_FILE} bytes")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        raise PolicyError(f"{what} file is not valid JSON")
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise PolicyError(f"{what} file is not a schema {SCHEMA} file "
                          "(expected an object with \"schema\": 1)")
    return data


def _date(value, field: str, label: str) -> datetime.date:
    if not isinstance(value, str) or not _DATE.match(value):
        raise PolicyError(f"{label}: \"{field}\" must be a date like "
                          "2026-12-31")
    try:
        return datetime.date.fromisoformat(value)
    except ValueError:
        raise PolicyError(f"{label}: \"{field}\" is not a real date")


def load_suppressions(path: str, today: "datetime.date | None" = None
                      ) -> "list[dict]":
    today = today or datetime.date.today()
    data = _read(path, "suppressions")
    items = data.get("suppressions")
    if not isinstance(items, list) or len(items) > MAX_ENTRIES:
        raise PolicyError("suppressions file needs a \"suppressions\" list "
                          f"of at most {MAX_ENTRIES} entries")
    out = []
    for i, item in enumerate(items, 1):
        label = f"suppression {i}"
        if not isinstance(item, dict):
            raise PolicyError(f"{label} is not an object")
        unknown = set(item) - {"check", "server", "client", "contains",
                               "reason", "expires", "owner"}
        if unknown:
            raise PolicyError(f"{label}: unknown field {sorted(unknown)[0]!r}"
                              " (a misspelt field would suppress too much)")
        if not isinstance(item.get("check"), str) or not item["check"]:
            raise PolicyError(f"{label}: \"check\" is required (a check id; "
                              "run --explain to list them)")
        reason = item.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 8 \
                or len(reason) > 500:
            raise PolicyError(f"{label}: \"reason\" is required (8 to 500 "
                              "characters): say why this is accepted")
        for key in ("server", "client", "contains", "owner"):
            if key in item and (not isinstance(item[key], str)
                                or len(item[key]) > 200):
                raise PolicyError(f"{label}: \"{key}\" must be text of at "
                                  "most 200 characters")
        expires = _date(item.get("expires"), "expires", label)
        if expires > today + datetime.timedelta(days=MAX_HORIZON_DAYS):
            raise PolicyError(f"{label}: \"expires\" is more than a year "
                              "away; suppressions must be reviewed at least "
                              "yearly")
        out.append({**item, "_expires": expires})
    return out


def load_baseline(path: str) -> "dict[str, dict]":
    data = _read(path, "baseline")
    items = data.get("findings")
    if not isinstance(items, list) or len(items) > MAX_ENTRIES * 10:
        raise PolicyError("baseline file needs a \"findings\" list")
    out = {}
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            out[item["id"]] = item
    return out


def write_baseline(path: str, results: list, version: str) -> int:
    seen = {}
    for r in results:
        for f in r["findings"]:
            seen[finding_id(r, f)] = {
                "id": finding_id(r, f), "server": r["name"],
                "client": r["client"], "check": f["check"],
                "severity": f["severity"], "message": f["message"]}
    doc = {"schema": SCHEMA, "tool": "mcp-gradecard", "version": version,
           "findings": sorted(seen.values(), key=lambda x: (
               x["client"], x["server"], x["check"], x["id"]))}
    text = json.dumps(doc, indent=1, ensure_ascii=True) + "\n"
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".baseline-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return len(seen)


def _matches(rule: dict, result: dict, finding: dict) -> bool:
    if rule["check"] != finding.get("check"):
        return False
    if "server" in rule and not fnmatch.fnmatchcase(
            str(result.get("name")), rule["server"]):
        return False
    if "client" in rule and not fnmatch.fnmatchcase(
            str(result.get("client")), rule["client"]):
        return False
    if "contains" in rule and rule["contains"] not in str(
            finding.get("message")):
        return False
    return True


def apply(results: list, suppressions: "list[dict] | None" = None,
          baseline: "dict[str, dict] | None" = None,
          today: "datetime.date | None" = None) -> dict:
    """Mark every finding. Suppressed findings move to `result["suppressed"]`
    (with the reason and date) and leave the score; known ones stay and carry
    `known: True`. Every finding gets its `id`. Returns the counts for the
    report."""
    from . import scoring
    today = today or datetime.date.today()
    active = [s for s in suppressions or [] if s["_expires"] >= today]
    lapsed = [s for s in suppressions or [] if s["_expires"] < today]
    used = set()
    summary = {"suppressed": 0, "expired": [], "known": 0, "new": 0,
               "fixed": 0, "baseline": baseline is not None}
    seen_ids = set()
    for r in results:
        keep, hidden = [], []
        for f in r["findings"]:
            f["id"] = finding_id(r, f)
            seen_ids.add(f["id"])
            hit = next((s for s in active if _matches(s, r, f)), None)
            if hit is not None:
                used.add(id(hit))
                hidden.append({**f, "suppression": {
                    "reason": hit["reason"], "expires": hit["expires"],
                    **({"owner": hit["owner"]} if "owner" in hit else {})}})
                continue
            if baseline is not None:
                f["known"] = f["id"] in baseline
                summary["known" if f["known"] else "new"] += 1
            keep.append(f)
        r["findings"] = keep
        r["suppressed"] = hidden
        summary["suppressed"] += len(hidden)
        if hidden:
            r["score"], r["grade"] = scoring.score(keep)
    for s in lapsed:
        if any(_matches(s, r, f) for r in results for f in r["findings"]):
            summary["expired"].append({
                "check": s["check"], "expires": s["expires"],
                "server": s.get("server"), "reason": s["reason"]})
    if baseline is not None:
        summary["fixed"] = sum(1 for i in baseline if i not in seen_ids)
    summary["unused"] = [s["check"] for s in active if id(s) not in used]
    return summary
