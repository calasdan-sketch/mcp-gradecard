# Changelog

## 0.5.0 (unreleased)

- Benchmark: `bench/` holds 234 invented tool definitions (121 malicious in 13 classes, 113 benign) with a dev and a frozen holdout split, a generator, a runner and committed results; a test fails when the files are stale. Recall of the description scan on the whole corpus went from 0.744 to 0.876 at the same false-positive rate (0.027); on the holdout it is 0.730 (was 0.676).
- Description scan: new signals for an order not to ask for approval (`no_consent`), credentials handed to another tool or server (`relay`), moving a user's private data (`user_secrets`), more claims of priority over the user, a persona jailbreak, "do not mention it", and Japanese and Korean overrides.
- `--baseline FILE` / `--write-baseline FILE`: the gate counts only findings that are not in the baseline; findings carry a path-free `id` and `known`. SARIF results carry `baselineState`.
- `--suppressions FILE`: accepted findings with a required reason and expiry date; they leave the grade and the gate, stay listed in every format (SARIF `suppressions`), and count again after their date. A bad file exits 2. Never read unless named.
- `--tools-json FILE`: scan a saved tools/list answer without launching anything; `--pins` works on it. `deep.normalize_tool` is shared with the live probe.
- `--format cyclonedx`: a CycloneDX 1.5 bill of materials of packages (purl, pin state) and remote services (host only).
- New check `typosquat`: a package name one character, one separator or one look-alike away from a well-known MCP package, or under a scope that imitates an official one. Offline list; medium.
- `--explain [CHECK]` and `--advice`: plain-language explanation of a check, and a fix line under each finding in the terminal report.
- `--format json` now has `schema_version` 1, a `policy` object, and per finding `id`, `title`, `owasp`, `fix`; described by `schema/report.schema.json`. Old keys are unchanged.
- Reports: `--prepared-by`, a report id, an inventory of what each server runs or connects to, an "Accepted findings" table, and a statement of what the report does and does not support. `docs/safety-check.md` describes using it as a paid service.
- `action.yml`: a composite GitHub Action (audit, SARIF upload, job summary, gate).
- Discovery: Gemini CLI (documented), Codex CLI (TOML), Amazon Q, LM Studio, Cline, Roo Code, the Microsoft Store package of Claude Desktop, and Windows-side configs when running in WSL (all but Gemini marked unverified in the README). A TOML file on Python 3.10 is a warning, not a skip.
- Behaviour changes: findings of the new description signals and `typosquat` can lower a grade that was higher in 0.4.0.

## 0.4.0 (unreleased)

- New report formats: `--format html` (one self-contained page: no scripts, nothing loaded from the network, a Content-Security-Policy, light/dark and print layouts) and `--format markdown`. Both give the overall grade, what to fix first, per-server findings with what to do about each, the OWASP MCP Top 10 risks they map to, and what the audit does not cover. `--report-title` sets the heading. Untrusted names and messages are sanitized and escaped.
- Rug-pull detection: `--deep --pins FILE` pins a SHA-256 of every tool definition (whole definition, schemas included) and of the server's instructions, and reports `tool-changed` (high), `tool-added` (medium) and `tool-removed` (low) until `--update-pins` accepts the change. Hashes and names only; a broken pins file exits 2.
- Tool shadowing (`--deep`): `tool-shadowing` medium when a server's texts name a distinctive tool that only another server of the same client offers, low when two servers offer the same tool name.
- New static checks: `insecure-transport` (remote server or bridge URL over plain http/ws; high, medium on a LAN address), `credential-in-url` (a `?token=`/`?api_key=` or `user:pass@` in a server URL; high), `plaintext-secret` (a credential written out in `env`; low, high in a project file).
- `credential-in-url` also reads URLs in `args` (high) and `env` values (medium), database URLs with a password, secrets in the path (`fc-...`, token shapes, random segments on `zapier.com` / `firecrawl.dev`), and flags a `?token=${VAR}` reference that still sends the secret in the URL (medium). Placeholders (`YOUR_API_KEY_HERE`, `<YOUR_TOKEN>`, `xxxx`, `changeme`, `REPLACE_ME`) are not secrets. Plain http to `host.docker.internal` is medium.
- Pins are keyed by the config file's real path; a server whose file moved is compared against its old pins (with a note), and pins of servers that are gone are pruned.
- The Markdown report puts names and paths in code spans and defangs URLs and e-mail addresses in messages, so nothing is auto-linked.
- SARIF rules now carry a title, remediation help, OWASP MCP tags and `security-severity`; results carry a stable `partialFingerprints` entry (numbers in the message, such as counts, are left out of it). SARIF and package metadata links, and the README install line, point to github.com/calasdan-sketch/mcp-gradecard; the `mcp-audit` command still works as an alias.
- New module `mcp_gradecard/catalog.py`: title, remediation and OWASP MCP Top 10 mapping for every check.
- Behaviour changes: configs with a plain-http remote server, a token in a URL or a literal secret in `env` now get more findings (and a lower grade) than in 0.3.0. Probed tool entries carry a `digest` key.
- `examples/` holds a demo config and the HTML and Markdown reports it produces.

## 0.3.0

- Renamed the PyPI distribution to **mcp-gradecard** (PyPI rejected `mcp-audit` as too similar to existing projects). The import package is now `mcp_gradecard` and the primary command is `mcp-gradecard`; `python -m mcp_gradecard` replaces `python -m mcp_audit`.
- The old `mcp-audit` command stays as an alias for the same entry point. A thin `mcp_audit` module re-exports the top-level names and warns with `DeprecationWarning`; `python -m mcp_audit` still runs. Submodule imports such as `mcp_audit.cli` are not forwarded.
- User-visible labels (`[mcp-gradecard]` prefixes, SARIF tool name, `.mcp-gradecard.bak-` backup suffix) follow the new name. The `MCP_AUDIT_HOME` and `MCP_AUDIT_DEBUG` environment variables are unchanged.
- The GitHub repository is now calasdan-sketch/mcp-gradecard (formerly mcp-audit).

## 0.2.4

- Last release under the name mcp-audit.
