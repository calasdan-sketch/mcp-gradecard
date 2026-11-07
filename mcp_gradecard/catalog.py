"""What each check id means: a title, what to do about it, and where it sits
in the OWASP MCP Top 10.

One place for the words the HTML and Markdown reports and the SARIF rules
use, so a finding reads the same everywhere. The mapping is to the OWASP
MCP Top 10 (2025 edition, beta at the time of writing:
https://owasp.org/www-project-mcp-top-10/); it is this project's reading of
which risk a check is evidence of, not a statement by OWASP.
"""

from __future__ import annotations

OWASP_URL = "https://owasp.org/www-project-mcp-top-10/"

#: OWASP MCP Top 10 (2025) ids and titles, as listed on OWASP_URL.
OWASP = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Prompt Injection via Contextual Payloads",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

#: check id -> (title, OWASP ids, what to do). Every check id the code emits
#: has an entry (a test holds it to that).
CHECKS: "dict[str, tuple[str, tuple[str, ...], str]]" = {
    "suspicious-command": (
        "Launch command downloads or runs code through a shell",
        ("MCP05", "MCP04"),
        "Replace the entry with a pinned package (npx pkg@1.2.3, uvx "
        "pkg==1.2.3) or a local binary you have reviewed. `--fix --remove` "
        "can delete it."),
    "pipe-to-shell": (
        "Downloaded script piped straight into a shell",
        ("MCP05", "MCP04"),
        "Never run `curl ... | sh` from an MCP config: download, review and "
        "pin the script, or install the server from a package registry. "
        "`--fix --remove` can delete it."),
    "inline-code": (
        "Code passed inline to an interpreter",
        ("MCP05",),
        "Move the code into a reviewed file or package; an inline `-c`/`-e` "
        "script is invisible to most reviews."),
    "exfiltration-endpoint": (
        "Remote endpoint baked into the launch",
        ("MCP10", "MCP04"),
        "Confirm the host is one you expect this server to talk to. If it is "
        "yours, trust it with `--allow-host`; if not, remove the server."),
    "remote-server": (
        "Remote MCP server (traffic leaves the machine)",
        ("MCP10",),
        "Check you trust the operator with everything your agent will send. "
        "Trust a host of your own with `--allow-host`."),
    "insecure-transport": (
        "Remote MCP server reached without TLS",
        ("MCP07", "MCP03"),
        "Use the server's https:// (or wss://) URL. Over plain http anyone on "
        "the network can read tokens and rewrite tool descriptions."),
    "credential-in-url": (
        "Credential written into a server URL",
        ("MCP01", "MCP07"),
        "Rotate the credential, remove it from the URL and send it in an "
        "Authorization header that references an environment variable "
        "(\"Bearer ${TOKEN}\"), or use the server's OAuth sign-in."),
    "unparseable-url": (
        "URL that parsers read differently",
        ("MCP04",),
        "Rewrite the URL plainly (no backslashes, percent-escaped hosts or "
        "control characters); until then treat the server as unsafe."),
    "git-source": (
        "Package installed from a git repository",
        ("MCP04",),
        "Pin the source to a full commit hash, or install a released version "
        "from the registry."),
    "package-registry": (
        "Package installed from a non-default registry",
        ("MCP04",),
        "Make sure the registry is yours and served over https; anyone who "
        "controls it controls the code this server runs."),
    "floating-version": (
        "Package version not pinned",
        ("MCP04",),
        "Pin an exact version (pkg@1.2.3 / pkg==1.2.3) so a compromised "
        "release cannot reach you on the next launch."),
    "typosquat": (
        "Package name resembles a well-known MCP package",
        ("MCP04",),
        "Compare the name letter by letter with the package you meant and "
        "check its publisher on the registry page. If it is the right "
        "package, accept it with a suppression that says so; if not, "
        "replace it with the real name."),
    "known-vulnerable": (
        "Known-vulnerable package version",
        ("MCP04",),
        "Upgrade to a fixed version (the finding names it) and pin it."),
    "osv-lookup": (
        "Vulnerability database lookup failed",
        ("MCP08",),
        "Re-run with network access to api.osv.dev; until then the package "
        "has not been checked against OSV."),
    "unauditable": (
        "Entry cannot be audited from the config",
        ("MCP09",),
        "Find out what the client actually runs for this entry (often an "
        "extension) and review that."),
    "secret-env": (
        "Secrets handed to the server",
        ("MCP01", "MCP02"),
        "Give the server a token with the narrowest scope and shortest life "
        "that works, and only to servers you trust."),
    "secret-header": (
        "Literal credential in a header",
        ("MCP01",),
        "Reference an environment variable (\"Bearer ${TOKEN}\") instead of "
        "writing the credential into the file, and rotate it."),
    "plaintext-secret": (
        "Credential stored in plain text in the config",
        ("MCP01",),
        "Move the value to your OS keychain or shell environment and "
        "reference it (\"${TOKEN}\" where the client supports it). In a "
        "project file: rotate it and make sure the file is not committed."),
    "container-escape": (
        "Container option that reaches the host",
        ("MCP02", "MCP05"),
        "Drop --privileged, host namespaces, dangerous capabilities and the "
        "container-engine socket; mount only the folders the server needs, "
        "read-only where possible."),
    "container-isolation": (
        "Weakened container isolation",
        ("MCP02",),
        "Remove the option unless the server documents why it needs it."),
    "launch-env": (
        "Environment variable that changes what the server loads or trusts",
        ("MCP05", "MCP04"),
        "Remove the variable unless you wrote it and know why the server "
        "needs it; never point a preload, a loader or a certificate "
        "variable at a file you did not review."),
    "elevated-launch": (
        "Server started with elevated rights",
        ("MCP02", "MCP05"),
        "Run the server as your own user. A server that needs root for one "
        "task should get that task through a narrow, reviewed helper."),
    "invalid-config": (
        "Server entry that cannot be analyzed",
        ("MCP08",),
        "Fix the entry so it is a JSON object with a command or a URL."),
    "detector-error": (
        "Check could not complete",
        ("MCP08",),
        "Treat the server as unaudited and report the issue to "
        "mcp-gradecard."),
    "deep-probe": (
        "Live tool scan did not run or was incomplete",
        ("MCP08",),
        "Read the reason; launch the server with --probe-critical or "
        "--probe-project only if you would run it yourself."),
    "tool-description-injection": (
        "Prompt injection in what the server tells the agent",
        ("MCP03", "MCP06"),
        "Read the flagged text yourself (the client's tool list shows it). "
        "If it instructs the agent, remove the server and report it."),
    "tool-changed": (
        "Tool definition changed since it was pinned (rug pull)",
        ("MCP03", "MCP04"),
        "Compare the tool with what you approved. If the change is expected "
        "(an upgrade), accept it with --update-pins; if not, remove the "
        "server."),
    "tool-added": (
        "New tool since the definitions were pinned",
        ("MCP03", "MCP02"),
        "Review what the new tool does before your agent uses it, then "
        "accept it with --update-pins."),
    "tool-removed": (
        "Tool gone since the definitions were pinned",
        ("MCP08",),
        "Usually an upgrade; accept with --update-pins once you have "
        "checked."),
    "tool-shadowing": (
        "Tool name or text that collides with another server's tools",
        ("MCP03", "MCP09"),
        "Make sure the agent can tell the tools apart; remove the server "
        "whose description talks about another server's tools unless you "
        "know why it does."),
}

_SEVERITY_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5",
                   "low": "3.0"}


def title(check: str) -> str:
    return CHECKS.get(check, (check,))[0]


def owasp(check: str) -> "tuple[str, ...]":
    entry = CHECKS.get(check)
    return entry[1] if entry else ()


def remediation(check: str) -> str:
    entry = CHECKS.get(check)
    return entry[2] if entry else ""


def security_severity(severity: str) -> str:
    """GitHub code scanning's `security-severity` (a CVSS-like 0-10 score as
    a string), which it uses to show critical/high/medium/low."""
    return _SEVERITY_SCORE.get(severity, "3.0")


def explain(check: str) -> str:
    """Plain-language text for `--explain CHECK`: what the check is, what to
    do, which OWASP MCP risks it is evidence of, how to accept it."""
    entry = CHECKS.get(check)
    if entry is None:
        return ""
    refs = "; ".join(f"{r} {OWASP[r]}" for r in entry[1]) or "none"
    return "\n".join((
        f"{check}: {entry[0]}",
        "",
        "What to do:",
        "  " + entry[2],
        "",
        f"OWASP MCP Top 10: {refs}",
        "",
        "To accept it for a while, with a reason, put this in a file and run",
        "with --suppressions FILE (the date is required):",
        '  {"schema": 1, "suppressions": [{"check": "%s",' % check,
        '    "server": "NAME", "reason": "why this is accepted",',
        '    "expires": "YYYY-MM-DD"}]}',
    ))
