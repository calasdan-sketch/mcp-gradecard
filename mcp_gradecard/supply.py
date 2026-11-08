"""The package supply chain, read offline: look-alike package names and a
CycloneDX bill of materials.

Nothing here touches the network. `detect_typosquat` compares the packages a
server launches with a built-in list of well-known MCP packages; it can say
"this name is one letter from a famous one", never "this package is
malicious" - a registry lookup would be needed for that, and the answer
would still be a judgement. `render_cyclonedx` lists what the configs would
download, pinned or not, as a CycloneDX 1.5 JSON document an auditor's tools
can read.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import uuid

#: Well-known MCP packages, by ecosystem. Names only: being on this list is
#: not an endorsement, it is the set a look-alike would imitate. Normalized
#: (lower case) before comparing.
POPULAR = {
    "npm": (
        "@modelcontextprotocol/sdk", "@modelcontextprotocol/inspector",
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-gitlab",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-google-maps",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-everything",
        "@modelcontextprotocol/server-sequential-thinking",
        "@modelcontextprotocol/server-gdrive",
        "@modelcontextprotocol/server-redis",
        "@modelcontextprotocol/server-everart",
        "@playwright/mcp", "@upstash/context7-mcp", "firecrawl-mcp",
        "@notionhq/notion-mcp-server", "mcp-remote",
        "@supabase/mcp-server-supabase", "@stripe/mcp",
        "@sentry/mcp-server", "chrome-devtools-mcp", "tavily-mcp",
        "exa-mcp-server", "@browserbasehq/mcp-server-browserbase",
        "@executeautomation/playwright-mcp-server",
        "@cloudflare/mcp-server-cloudflare", "@azure/mcp",
        "n8n-mcp", "mcp-framework", "fastmcp",
    ),
    "PyPI": (
        "mcp", "fastmcp", "mcp-server-fetch", "mcp-server-git",
        "mcp-server-time", "mcp-server-sqlite", "mcp-server-qdrant",
        "markitdown-mcp", "mcp-server-kubernetes",
        "mcp-proxy", "mcp-server-sentry", "awslabs.core-mcp-server",
    ),
}
#: Scopes whose look-alikes matter most.
OFFICIAL_SCOPES = {"@modelcontextprotocol", "@playwright", "@upstash",
                   "@notionhq", "@supabase", "@stripe", "@sentry",
                   "@browserbasehq", "@cloudflare", "@azure"}

#: Scopes squatters use because they sound official.
GENERIC_SCOPES = {"@mcp", "@mcp-servers", "@modelcontext", "@anthropic",
                  "@anthropic-ai", "@model-context-protocol", "@mcpservers"}

_SIMPLE = {"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"}


def _norm(name: str, ecosystem: str) -> str:
    name = name.lower()
    if ecosystem == "PyPI":
        name = re.sub(r"[-_.]+", "-", name)         # PEP 503
    return name


def _squash(name: str) -> str:
    """The name a hurried reader would see: separators gone, look-alike
    digits and `rn` folded."""
    name = re.sub(r"[-_.]", "", name.lower())
    name = "".join(_SIMPLE.get(c, c) for c in name)
    return name.replace("rn", "m").replace("vv", "w")


def distance(a: str, b: str, limit: int = 2) -> int:
    """Damerau-Levenshtein distance (adjacent swaps count as one), or
    `limit` + 1 when it is larger. Bounded: names are cut at 80 characters."""
    a, b = a[:80], b[:80]
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (ca != cb))
            if prev2 is not None and i > 1 and j > 1 \
                    and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return min(prev[-1], limit + 1)


def _split_scope(name: str) -> "tuple[str, str]":
    if name.startswith("@") and "/" in name:
        scope, rest = name.split("/", 1)
        return scope, rest
    return "", name


def lookalike(name: str, ecosystem: str) -> "tuple[str, str] | None":
    """(well-known name, why) when `name` imitates one, else None."""
    known = POPULAR.get(ecosystem, ())
    me = _norm(name, ecosystem)
    if me in {_norm(k, ecosystem) for k in known}:
        return None                                  # it is the real one
    my_scope, my_rest = _split_scope(me)
    for real in known:
        r = _norm(real, ecosystem)
        scope, rest = _split_scope(r)
        if scope and my_scope != scope:
            # right package name under a scope that is almost the official
            if my_rest == rest and (not my_scope
                                    or distance(my_scope, scope) <= 2
                                    or my_scope in GENERIC_SCOPES):
                return real, "the same name under a different scope"
            if my_scope and scope in OFFICIAL_SCOPES \
                    and 0 < distance(my_scope, scope) <= 2 \
                    and distance(my_rest, rest) <= 3:
                return real, "a scope one or two letters from the official one"
            continue
        if len(r) >= 10 and len(me) >= 10 and r != me:
            if _squash(r) == _squash(me):
                return real, "the same name with separators or look-alike " \
                             "characters changed"
            if distance(me, r, 1) <= 1:
                return real, "one character away"
    return None


def detect_typosquat(name: str, cfg: dict) -> "list[dict]":
    from . import detectors
    findings, seen = [], set()
    for p in detectors._iter_packages(cfg):
        if not p.sure or p.name in seen:
            continue
        seen.add(p.name)
        hit = lookalike(p.name, p.ecosystem)
        if hit:
            findings.append({
                "severity": "medium", "check": "typosquat",
                "message": f"package '{p.name}' looks like the well-known "
                           f"'{hit[0]}' ({hit[1]}); if you did not mean "
                           "a different package, this may be a look-alike "
                           "- check the name and the publisher"})
    return findings


# -- CycloneDX -----------------------------------------------------------------

def purl(p) -> str:
    kind = "npm" if p.ecosystem == "npm" else "pypi"
    name = p.name
    if kind == "npm" and name.startswith("@"):
        name = "%40" + name[1:]
    elif kind == "pypi":
        name = re.sub(r"[-_.]+", "-", name.lower())
    release = p.release()
    return f"pkg:{kind}/{urllib.parse.quote(name, safe='/%')}" + (
        f"@{urllib.parse.quote(release, safe='')}" if release else "")


def _host_only(url: str) -> "str | None":
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname
        if not u.scheme or not host:
            return None
        return f"{u.scheme.lower()}://{host}" + (
            f":{u.port}" if u.port else "")
    except ValueError:
        return None


def render_cyclonedx(results: "list[dict]", version: str,
                     title: "str | None" = None) -> dict:
    """CycloneDX 1.5 BOM of what the audited configs download and connect
    to: one library component per (server, package) and one service per
    remote endpoint (scheme and host only: a path or query can hold a
    secret). Deterministic: the same configs give the same document."""
    from . import detectors
    components, services = [], []
    for i, r in enumerate(results):
        cfg = r.get("config")
        if not isinstance(cfg, dict):
            continue
        try:
            packages = [p for p in detectors._iter_packages(cfg) if p.sure]
        except Exception:                           # noqa: BLE001
            packages = []
        for j, p in enumerate(packages):
            release = p.release()
            components.append({
                "type": "library", "bom-ref": f"pkg-{i}-{j}",
                "name": p.name, **({"version": release} if release else {}),
                "purl": purl(p),
                "properties": [
                    {"name": "mcp-gradecard:server", "value": str(r["name"])},
                    {"name": "mcp-gradecard:client", "value": str(r["client"])},
                    {"name": "mcp-gradecard:pinned",
                     "value": "true" if release else "false"},
                    {"name": "mcp-gradecard:requested-version",
                     "value": str(p.version) if p.version else ""}]})
        endpoints = set()
        try:
            for _where, url in detectors.remote_urls(cfg):
                host = _host_only(url)
                if host:
                    endpoints.add(host)
        except Exception:                           # noqa: BLE001
            pass
        if endpoints:
            services.append({
                "bom-ref": f"svc-{i}", "name": str(r["name"]),
                "endpoints": sorted(endpoints),
                "properties": [
                    {"name": "mcp-gradecard:client", "value": str(r["client"])},
                    {"name": "mcp-gradecard:grade", "value": str(r["grade"])}]})
    body = {"components": components, "services": services}
    serial = uuid.uuid5(uuid.NAMESPACE_URL, "mcp-gradecard:" + json.dumps(
        body, sort_keys=True))
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}", "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application",
                                      "name": "mcp-gradecard",
                                      "author": "Calas Automations Inc.",
                                      "version": version}]},
            "component": {"type": "application",
                          "name": title or "MCP agent configuration"}},
        "components": components, "services": services,
        "dependencies": [],
    }
