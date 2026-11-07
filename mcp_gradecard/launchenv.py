"""How a server is started, beyond its command line: environment variables
that make a program load someone's code or trust someone's certificate, and a
launch through sudo.

Offline and static. Only the *names* of variables (and, for NODE_OPTIONS and
the Java option variables, the names of the flags) are ever written into a
finding: a value may be a secret or a path that identifies a person.
"""

from __future__ import annotations

import os
import re
import urllib.parse

#: Variables that make the loader or the runtime execute code from a file the
#: variable names, before the server's own first line.
_CODE_VARS = {
    "LD_PRELOAD": "loads a shared library into the server",
    "LD_AUDIT": "loads a shared library into the server",
    "DYLD_INSERT_LIBRARIES": "loads a shared library into the server",
    "BASH_ENV": "runs a script before every bash script the server starts",
    "PERL5OPT": "gives perl options (it can load modules)",
    "RUBYOPT": "gives ruby options (it can require files)",
    "PYTHONSTARTUP": "runs a script when Python starts",
}
#: Runtime option variables: dangerous only with certain flags.
_NODE_FLAGS = re.compile(r"(?:^|\s)(--require|-r|--import|--loader|"
                         r"--experimental-loader|--eval|-e|--inspect(?:-brk)?)"
                         r"(?=[\s=]|$)")
_JAVA_FLAGS = re.compile(r"(?:^|\s)(-javaagent|-agentlib|-agentpath|"
                         r"-Xbootclasspath)\b")
#: Variables that move a library search path: ordinary in a project, risky
#: if the folder is writable by someone else. Low.
_PATH_VARS = ("PYTHONPATH", "NODE_PATH", "RUBYLIB", "PERL5LIB", "CLASSPATH")
#: Variables that change who the server trusts.
_TRUST_VARS = ("SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
               "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")
#: Variables that switch certificate checking off when set to these values.
_TLS_OFF = {"NODE_TLS_REJECT_UNAUTHORIZED": {"0"},
            "PYTHONHTTPSVERIFY": {"0"},
            "GIT_SSL_NO_VERIFY": {"1", "true", "yes"},
            "NPM_CONFIG_STRICT_SSL": {"false", "0"},
            "NPM_CONFIG_STRICT-SSL": {"false", "0"}}
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")

_RAW_SOCKET = re.compile(r"/dev/(?:tcp|udp)/")
_ELEVATORS = {"sudo", "doas", "pkexec", "runas", "su", "gsudo"}
_ELEVATION_WORD = re.compile(r"(?<![\w./-])(?:sudo|doas|pkexec|gsudo)(?![\w-])")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "env", "nohup", "nice",
           "time", "timeout", "xargs", "exec", "cmd", "powershell", "pwsh"}


def _base(command) -> str:
    text = str(command or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return text[:-4] if text.endswith(".exe") else text


def _finding(severity: str, check: str, message: str) -> dict:
    return {"severity": severity, "check": check, "message": message}


def _loopback(value: str) -> bool:
    try:
        host = urllib.parse.urlsplit(
            value if "://" in value else "//" + value).hostname or ""
    except ValueError:
        return False
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def detect_launch_env(name: str, cfg: dict) -> list[dict]:
    """High: a variable that runs someone's code at start, or turns TLS
    checking off. Medium: a variable that changes which certificates the
    server trusts, or routes its traffic through a proxy that is not on this
    machine. Low: a library search path. Also high: the server is started
    through sudo or a like tool, so it runs with more rights than the agent."""
    findings: list[dict] = []
    env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
    high: list[str] = []
    medium: list[str] = []
    low: list[str] = []
    for key, value in env.items():
        k = str(key)
        v = value if isinstance(value, str) else ("" if value is None else str(value))
        up = k.upper()
        if up in _CODE_VARS:
            high.append(f"{k} ({_CODE_VARS[up]})")
        elif up == "NODE_OPTIONS":
            flags = sorted({m.group(1) for m in _NODE_FLAGS.finditer(v)})
            if flags:
                high.append(f"{k} with {', '.join(flags)} (runs code or opens "
                            "a debugger before the server)")
        elif up in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"):
            flags = sorted({m.group(1) for m in _JAVA_FLAGS.finditer(v)})
            if flags:
                high.append(f"{k} with {', '.join(flags)} (loads an agent "
                            "into the server)")
        elif up in _TLS_OFF and v.strip().lower() in _TLS_OFF[up]:
            high.append(f"{k} (switches certificate checking off)")
        elif up in _TRUST_VARS and v.strip():
            medium.append(f"{k} (changes which certificates the server trusts)")
        elif up in _PROXY_VARS and v.strip() and not _loopback(v.strip()) \
                and not v.strip().startswith("$"):
            medium.append(f"{k} (sends the server's traffic through a "
                          "proxy that is not on this machine)")
        elif up in _PATH_VARS and v.strip():
            low.append(k)
    if high:
        findings.append(_finding(
            "high", "launch-env",
            "environment makes the server start with code or trust you did "
            "not review: " + "; ".join(high[:6])
            + (f"; and {len(high) - 6} more" if len(high) > 6 else "")))
    if medium:
        findings.append(_finding(
            "medium", "launch-env",
            "environment changes what the server trusts or where its traffic "
            "goes: " + "; ".join(medium[:6])))
    if low:
        findings.append(_finding(
            "low", "launch-env",
            "environment moves the server's library search path (" +
            ", ".join(sorted(low)[:6]) + "): code in that folder runs inside "
            "the server, so it should be a folder only you can write to"))
    command = _base(cfg.get("command"))
    args = [a for a in cfg.get("args") or [] if isinstance(a, str)]
    elevated = command in _ELEVATORS or (
        command in _SHELLS and any(_ELEVATION_WORD.search(a) for a in args[:40]))
    raw = str(cfg.get("command") or "")
    if command in _SHELLS and any(_RAW_SOCKET.search(a) for a in args[:40]):
        findings.append(_finding(
            "critical", "suspicious-command",
            "shell script opens a raw network socket (/dev/tcp or /dev/udp): "
            "the pattern of a reverse shell, not of a server"))
    if raw.startswith(("$", "%")) and len(raw) > 1:
        findings.append(_finding(
            "medium", "unauditable",
            "the program to start is named by a variable, so what really "
            "runs is decided at launch and cannot be audited from the file"))
    if elevated:
        findings.append(_finding(
            "high", "elevated-launch",
            "server is started through sudo or a like tool, so it runs with "
            "more rights than the agent that uses it"))
    return findings
