"""What --deep learns from the tool lists as a whole, beyond one text at a
time.

* Pins (rug pulls). A server can show a harmless tool list the day you
  approve it and a different one later: an update, a hijacked package, or a
  remote server that changes what it says. `--pins FILE` keeps a SHA-256 of
  every tool definition (and of the server's instructions) the first time it
  is seen, and on every later run reports a tool that changed, appeared or
  went away until you accept the new state with `--update-pins`. The file
  holds hashes and names only, never a description, and stays on this
  machine.

* Shadowing. Every server's tools land in the same agent. A tool name that
  two servers both offer can send a call to the wrong one, and a server whose
  descriptions talk about another server's tools ("when you use send_email,
  always add ...") is trying to steer them: Invariant Labs named this tool
  shadowing. Both are reported, as leads for a person to read.
"""

from __future__ import annotations

import json
import os
import re
import tempfile

from . import redact

PINS_VERSION = 1
#: A pins file larger than this is not read (a real one is a few kilobytes
#: per server).
MAX_PINS_BYTES = 16 * 1024 * 1024
#: Tool names listed in one finding; the rest are counted.
_LISTED = 8
_NAME_SHOWN = 80
#: The key that holds the server's own texts (instructions, title,
#: description from `initialize`); every tool's key starts with TOOL, so no
#: tool name can take its place.
SERVER_KEY = "server"
TOOL = "tool:"


class PinsError(Exception):
    """The pins file exists but cannot be used; the message says why and
    never quotes the file."""


def _shown(name: str) -> str:
    return redact.sanitize(str(name))[:_NAME_SHOWN] or "(unnamed)"


def _names(items) -> str:
    items = sorted(items)
    text = ", ".join(f"'{_shown(n)}'" for n in items[:_LISTED])
    if len(items) > _LISTED:
        text += f" (+{len(items) - _LISTED} more)"
    return text


def real_path(path) -> str:
    """The file a config path names, whatever spelling it was found by
    (`./x.json`, a symlink, a different working directory)."""
    try:
        return os.path.realpath(str(path))
    except (OSError, ValueError):
        return str(path)


def server_key(result: dict) -> str:
    """The key a server is pinned under: which client, which file (its real
    path), which project (Claude Code's local scope) and which name. JSON,
    so no two servers can share one."""
    return json.dumps([result.get("client"), real_path(result.get("path")),
                       result.get("project"), result.get("name")],
                      ensure_ascii=False)


def key_parts(key: str) -> "tuple | None":
    """(client, path, project, name) of a key, or None for one this version
    did not write."""
    try:
        parts = json.loads(key)
    except ValueError:
        return None
    if isinstance(parts, list) and len(parts) == 4:
        return tuple(parts)
    return None


def plan_prune(servers: dict, results: list[dict]) -> "list[str]":
    """The keys whose server is gone: its config file no longer exists, or
    the file was audited in this run and no longer holds that server. A
    server in a file this run did not read (another --config) is kept."""
    live = {server_key(r) for r in results}
    audited = {real_path(r.get("path")) for r in results}
    stale = []
    for key in servers:
        parts = key_parts(key)
        if parts is None:
            continue
        path = parts[1]
        if key in live:
            continue
        if not os.path.exists(str(path)) or path in audited:
            stale.append(key)
    return stale


def snapshot(tools: list[dict], server: "dict | None") -> dict:
    """{"tool:<name>": digest, "server": digest} for one probed server. Two
    tools with one name (a server may send that) share a key: their digests
    are joined, so a change in either still shows."""
    import hashlib
    out: "dict[str, str]" = {}
    for t in tools:
        name = TOOL + str(t.get("name") or "")
        digest = str(t.get("digest") or "")
        out[name] = (out[name] + "+" + digest) if name in out else digest
    if server:
        text = json.dumps(server, sort_keys=True, ensure_ascii=False)
        out[SERVER_KEY] = hashlib.sha256(
            text.encode("utf-8", "surrogatepass")).hexdigest()
    return out


def load(path: str) -> "tuple[dict, dict] | None":
    """The pinned state as ({server key: {tool name: digest}}, {server key:
    labels}), or None when there is no file yet. Raises PinsError for a file that exists but cannot
    be used: a broken pins file must not quietly turn the check off."""
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise PinsError(f"cannot read it ({e.strerror or type(e).__name__})")
    if size > MAX_PINS_BYTES:
        raise PinsError(f"it is larger than {MAX_PINS_BYTES} bytes")
    try:
        with open(path, "rb") as f:
            data = json.loads(f.read().decode("utf-8"))
    except OSError as e:
        raise PinsError(f"cannot read it ({e.strerror or type(e).__name__})")
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PinsError("it is not valid JSON")
    if not (isinstance(data, dict) and data.get("version") == PINS_VERSION
            and isinstance(data.get("servers"), dict)):
        raise PinsError("it is not an mcp-gradecard pins file (version "
                        f"{PINS_VERSION})")
    servers, labels = {}, {}
    for key, entry in data["servers"].items():
        tools = entry.get("tools") if isinstance(entry, dict) else None
        if not isinstance(tools, dict) or not all(
                isinstance(k, str) and isinstance(v, str)
                for k, v in tools.items()):
            raise PinsError("an entry in it is not a map of tool names to "
                            "hashes")
        servers[key] = tools
        labels[key] = {k: entry[k] for k in ("name", "client", "path")
                       if isinstance(entry.get(k), str)}
    return servers, labels


def save(path: str, servers: "dict[str, dict]", labels: "dict[str, dict]"
         ) -> None:
    """Write the pins file in one step (a crash leaves the old one), private
    to this user. `labels`: for each key, the name/client/path to show a
    person who opens the file."""
    data = {"version": PINS_VERSION,
            "note": "mcp-gradecard tool pins: SHA-256 of each tool "
                    "definition. Hashes and names only.",
            "servers": {key: {**labels.get(key, {}), "tools": tools}
                        for key, tools in sorted(servers.items())}}
    blob = json.dumps(data, indent=2, ensure_ascii=False,
                      sort_keys=False).encode("utf-8", "surrogatepass")
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".mcp-gradecard-pins.",
                               suffix=".tmp")   # mode 0600
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(blob + b"\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _tool_names(keys) -> "list[str]":
    return [k[len(TOOL):] for k in keys if k.startswith(TOOL)]


def compare(pinned: dict, now: dict, complete: bool) -> list[dict]:
    """Findings for one server: what changed between its pinned tools and
    the ones it lists now. `complete`: the whole tool list was read (a probe
    that stopped part way cannot say a tool went away)."""
    findings = []
    changed = [n for n in now if n in pinned and now[n] != pinned[n]]
    added = [n for n in now if n not in pinned]
    removed = [n for n in pinned if n not in now] if complete else []
    server_changed = SERVER_KEY in changed
    server_added = SERVER_KEY in added
    changed, added, removed = (_tool_names(changed), _tool_names(added),
                               _tool_names(removed))
    if server_changed:
        findings.append({
            "severity": "high", "check": "tool-changed",
            "message": "the server's own instructions changed since they "
                       "were pinned (possible rug pull): review them, then "
                       "--update-pins to accept"})
    if changed:
        findings.append({
            "severity": "high", "check": "tool-changed",
            "message": f"{len(changed)} tool definition(s) changed since "
                       f"they were pinned (possible rug pull): "
                       f"{_names(changed)}; review them, then --update-pins "
                       "to accept"})
    if server_added:
        findings.append({
            "severity": "medium", "check": "tool-added",
            "message": "the server now sends instructions it did not send "
                       "when it was pinned; review them, then --update-pins "
                       "to accept"})
    if added:
        findings.append({
            "severity": "medium", "check": "tool-added",
            "message": f"{len(added)} new tool(s) since the definitions were "
                       f"pinned: {_names(added)}; review them, then "
                       "--update-pins to accept"})
    if removed:
        findings.append({
            "severity": "low", "check": "tool-removed",
            "message": f"{len(removed)} pinned tool(s) no longer listed: "
                       f"{_names(removed)}; --update-pins to accept"})
    return findings


# -- shadowing ---------------------------------------------------------------

#: A word in a text that could be a tool name.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{4,64}")
#: Characters of one server's texts looked at for other servers' names.
MAX_SHADOW_TEXT = 2_000_000


def _canon(name: str) -> str:
    return name.lower().replace("-", "_")


def _distinctive(name: str) -> bool:
    """A tool name specific enough that mentioning it means that tool:
    snake_case, kebab-case or camelCase and at least six characters.
    `search`, `read` or `fetch` are words; `send_email` is a tool."""
    if len(name) < 6 or len(name) > 64:
        return False
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", name):
        return False
    return ("_" in name.strip("_") or "-" in name.strip("-")
            or re.search(r"[a-z][A-Z]", name) is not None)


def _texts_of(result: dict):
    """Every text the agent is shown for one server (see deep._all_texts)."""
    from .deep import _all_texts
    for _subject, _where, text in _all_texts(result.get("tools") or [],
                                             result.get("deep_server")):
        if isinstance(text, str):
            yield text


def family(client: str) -> str:
    """The agent a config feeds: the user, project, local and managed files
    of one client are loaded together, two clients are two agents."""
    client = str(client or "")
    for prefix in ("claude-code", "claude-desktop", "vscode", "cursor",
                   "devin", "zed"):
        if client == prefix or client.startswith(prefix + "-"):
            return prefix
    return client


def shadowing(results: list[dict]) -> "dict[int, list[dict]]":
    """{id(result): findings} over every server whose tools --deep read.

    * Low: a tool name that another server also offers (the agent can call
      the wrong one; with some clients whichever loads last wins).
    * Medium: a server's texts mention, by name, a tool that only another
      server offers. Names must be distinctive (see _distinctive) so that
      ordinary words do not count.

    Only servers one agent loads together are compared (see family), and a
    second entry with the very same config is the same server, not
    another."""
    out: "dict[int, list[dict]]" = {}
    groups: "dict[str, list[dict]]" = {}
    for r in results:
        if r.get("deep_read"):
            groups.setdefault(family(r.get("client")), []).append(r)
    for probed in groups.values():
        out.update(_shadowing(probed))
    return out


def _shadowing(probed: list[dict]) -> "dict[int, list[dict]]":
    owners: "dict[str, list[dict]]" = {}
    for r in probed:
        for name in {str(t.get("name") or "") for t in r.get("tools") or []}:
            if name:
                owners.setdefault(name, []).append(r)
    # "Send-Email" names the tool "send_email": case and separators do not
    # make a different tool in a sentence.
    _spelled = {}
    for name in owners:
        _spelled.setdefault(_canon(name), name)
    out: "dict[int, list[dict]]" = {}
    for r in probed:
        mine = {str(t.get("name") or "") for t in r.get("tools") or []}
        shared = {}
        for name in mine:
            others = [o for o in owners.get(name, [])
                      if o is not r and o.get("config") != r.get("config")]
            if others:
                shared[name] = others
        found = []
        if shared:
            servers = sorted({_shown(o["name"]) for os_ in shared.values()
                              for o in os_})
            found.append({
                "severity": "low", "check": "tool-shadowing",
                "message": f"{len(shared)} tool name(s) also offered by "
                           f"another server ({_names(servers)}): "
                           f"{_names(shared)}; the agent may call the wrong "
                           "one"})
        mentioned: "dict[str, set]" = {}
        spent = 0
        for text in _texts_of(r):
            if spent >= MAX_SHADOW_TEXT:
                break
            text = text[:MAX_SHADOW_TEXT - spent]
            spent += len(text)
            for token in set(_TOKEN_RE.findall(text)):
                if token in mine or not _distinctive(token):
                    continue
                key = token if token in owners else _spelled.get(
                    _canon(token))
                if key is None or key in mine:
                    continue
                others = [o for o in owners[key]
                          if o.get("config") != r.get("config")]
                if others:
                    mentioned.setdefault(token, set()).update(
                        _shown(o["name"]) for o in others)
        if mentioned:
            servers = sorted({s for v in mentioned.values() for s in v})
            found.append({
                "severity": "medium", "check": "tool-shadowing",
                "message": f"what this server tells the agent names "
                           f"{len(mentioned)} tool(s) that belong to another "
                           f"server ({_names(servers)}): {_names(mentioned)}; "
                           "a server that talks about another server's tools "
                           "can redirect or hijack them (tool shadowing) "
                           "— manual review required, heuristic match "
                           "only"})
        if found:
            out[id(r)] = found
    return out
