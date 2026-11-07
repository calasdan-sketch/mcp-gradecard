"""Audit a saved tool list without launching anything (`--tools-json`).

A client or a vendor can hand over what a server's `tools/list` returns; this
reads such files and runs the same description scan, the same pins and the
same shadowing check that `--deep` runs on a live server, with no process
started. Accepted shapes:

* a `tools/list` answer, or its `result`: `{"tools": [...]}`
* a bare list of tool objects: `[...]`
* several servers: `{"servers": {"name": <either shape above>}}`, or the
  same mapping without the `servers` key; a server entry may also carry
  `instructions`, `title` and `description` (what `initialize` returned).
"""

from __future__ import annotations

import json
import os

from . import deep, scoring

MAX_FILE = 16_000_000
MAX_SERVERS = 200


class ToolFileError(Exception):
    """A file that cannot be read as a tool list; the message is safe to
    print."""


def _tools_of(value):
    if isinstance(value, dict) and isinstance(value.get("result"), dict):
        value = value["result"]
    if isinstance(value, dict) and isinstance(value.get("tools"), list):
        return value["tools"], {k: value[k] for k in
                                ("instructions", "title", "description")
                                if isinstance(value.get(k), str)
                                and value[k].strip()}
    if isinstance(value, list):
        return value, {}
    return None, {}


def load(path: str) -> "list[dict]":
    """Results (as the audit builds them) for the servers in one file."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_FILE + 1)
    except OSError as e:
        raise ToolFileError(f"cannot read: {e.strerror or type(e).__name__}")
    if len(raw) > MAX_FILE:
        raise ToolFileError(f"larger than {MAX_FILE} bytes")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        raise ToolFileError("not valid JSON")
    tools, server = _tools_of(data)
    named: "dict[str, tuple]" = {}
    if tools is not None:
        named[os.path.splitext(os.path.basename(path))[0] or "tools"] = (
            tools, server)
    elif isinstance(data, dict):
        group = data.get("servers") if isinstance(data.get("servers"),
                                                  dict) else data
        for name, value in list(group.items())[:MAX_SERVERS]:
            t, srv = _tools_of(value)
            if t is None:
                raise ToolFileError(f"server {str(name)[:40]!r} has no "
                                    "\"tools\" list")
            named[str(name)] = (t, srv)
    if not named:
        raise ToolFileError("no tool list found (expected {\"tools\": [...]},"
                            " a list of tools, or a mapping of servers)")
    results = []
    for name, (raw_tools, srv) in named.items():
        tools = [deep.normalize_tool(t) if isinstance(t, dict)
                 else {"name": "", "description": str(t)}
                 for t in raw_tools[:deep.MAX_TOOLS]]
        findings = deep.audit_descriptions(tools, srv or None)
        if len(raw_tools) > deep.MAX_TOOLS:
            findings.append({
                "severity": "low", "check": "deep-probe",
                "message": f"only the first {deep.MAX_TOOLS} tools were "
                           "scanned"})
        score, grade = scoring.score(findings)
        results.append({
            "name": name, "client": "tools-json", "path": path,
            "config": {"toolFile": True}, "findings": findings,
            "score": score, "grade": grade, "tools": tools,
            "deep_read": len(tools), "deep_server": srv or None,
            "deep_complete": True, "key_path": None})
    return results
