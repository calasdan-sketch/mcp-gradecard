# Changelog

## 0.4.0 (unreleased)

- New report formats: `--format html` (one self-contained page: no scripts, nothing loaded from the network, a Content-Security-Policy, light/dark and print layouts) and `--format markdown`. Both give the overall grade, what to fix first, per-server findings with what to do about each, the OWASP MCP Top 10 risks they map to, and what the audit does not cover. `--report-title` sets the heading. Untrusted names and messages are sanitized and escaped.
- Rug-pull detection: `--deep --pins FILE` pins a SHA-256 of every tool definition (whole definition, schemas included) and of the server's instructions, and reports `tool-changed` (high), `tool-added` (medium) and `tool-removed` (low) until `--update-pins` accepts the change. Hashes and names only; a broken pins file exits 2.
- Tool shadowing (`--deep`): `tool-shadowing` medium when a server's texts name a distinctive tool that only another server of the same client offers, low when two servers offer the same tool name.
- New static checks: `insecure-transport` (remote server or bridge URL over plain http/ws; high, medium on a LAN address), `credential-in-url` (a `?token=`/`?api_key=` or `user:pass@` in a server URL; high), `plaintext-secret` (a credential written out in `env`; low, high in a project file).
- `credential-in-url` also reads URLs in `args` (high) and `env` values (medium), database URLs with a password, secrets in the path (`fc-...`, token shapes, random segments on `zapier.com` / `firecrawl.dev`), and flags a `?token=${VAR}` reference that still sends the secret in the URL (medium). Placeholders (`YOUR_API_KEY_HERE`, `<YOUR_TOKEN>`, `xxxx`, `changeme`, `REPLACE_ME`) are not secrets. Plain http to `host.docker.internal` is medium.
- Pins are keyed by the config file's real path; a server whose file moved is compared against its old pins (with a note), and pins of servers that are gone are pruned.
- The Markdown report puts names and paths in code spans and defangs URLs and e-mail addresses in messages, so nothing is auto-linked.
- SARIF rules now carry a title, remediation help, OWASP MCP tags and `security-severity`; results carry a stable `partialFingerprints` entry (numbers in the message, such as counts, are left out of it). SARIF and package metadata links point to github.com/calasdan-sketch/mcp-gradecard.
- New module `mcp_gradecard/catalog.py`: title, remediation and OWASP MCP Top 10 mapping for every check.
- Behaviour changes: configs with a plain-http remote server, a token in a URL or a literal secret in `env` now get more findings (and a lower grade) than in 0.3.0. Probed tool entries carry a `digest` key.
- `examples/` holds a demo config and the HTML and Markdown reports it produces.

## 0.3.0

- Renamed the PyPI distribution to **mcp-gradecard** (PyPI rejected `mcp-audit` as too similar to existing projects). The import package is now `mcp_gradecard` and the primary command is `mcp-gradecard`; `python -m mcp_gradecard` replaces `python -m mcp_audit`.
- The old `mcp-audit` command stays as an alias for the same entry point. A thin `mcp_audit` module re-exports the top-level names and warns with `DeprecationWarning`; `python -m mcp_audit` still runs. Submodule imports such as `mcp_audit.cli` are not forwarded.
- User-visible labels (`[mcp-gradecard]` prefixes, SARIF tool name, `.mcp-gradecard.bak-` backup suffix) follow the new name. The `MCP_AUDIT_HOME` and `MCP_AUDIT_DEBUG` environment variables are unchanged.
- The GitHub repository is still named mcp-audit.

## 0.2.4

- Last release under the name mcp-audit.
