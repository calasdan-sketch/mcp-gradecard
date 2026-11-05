# MCP Safety Check: demo workstation

Generated 2026-11-05 21:23 UTC by mcp-gradecard 0.4.0 · 1 config file(s) · 4 server(s) · static audit

**Overall grade: F** (the lowest grade of any server)

3 critical finding(s): act on these before you use these servers again.

| Critical | High | Medium | Low |
|---|---|---|---|
| 3 | 2 | 3 | 1 |

## Fix these first

| Severity | Server | Finding |
|---|---|---|
| CRITICAL | quick-setup | **Launch command downloads or runs code through a shell**: server runs 'curl' inside 'bash' — a downloader/shell, not a server binary |
| CRITICAL | quick-setup | **Downloaded script piped straight into a shell**: command pipes content into a shell (classic curl\|sh pattern) |
| CRITICAL | quick-setup | **Remote endpoint baked into the launch**: remote endpoint in args: https://get.tools.example/... |
| HIGH | vendor-crm | **Remote MCP server reached without TLS**: remote MCP server in 'url' is reached over plain http:// (no TLS): anyone on the network path can read its traffic, including any token, and rewrite the tool descriptions your agent reads; use https:// |
| HIGH | vendor-crm | **Credential written into a server URL**: credential written into the server URL in 'url' (api\_key): URLs are kept in logs, proxies and history, and MCP access tokens must not travel in the query string; send it in an Authorization header that references an environment variable |

## Servers

| Grade | Server | Client | Score | Findings |
|---|---|---|---|---|
| F | quick-setup | explicit | 0/100 | 3 |
| D | vendor-crm | explicit | 50/100 | 3 |
| B | github | explicit | 75/100 | 3 |
| A | filesystem | explicit | 100/100 | 0 |

## Findings by server

### [F] quick-setup (explicit, 0/100)

examples/demo-mcp.json

| Severity | Check | Finding | OWASP MCP |
|---|---|---|---|
| CRITICAL | suspicious-command | **Launch command downloads or runs code through a shell**: server runs 'curl' inside 'bash' — a downloader/shell, not a server binary | MCP05, MCP04 |
| CRITICAL | pipe-to-shell | **Downloaded script piped straight into a shell**: command pipes content into a shell (classic curl\|sh pattern) | MCP05, MCP04 |
| CRITICAL | exfiltration-endpoint | **Remote endpoint baked into the launch**: remote endpoint in args: https://get.tools.example/... | MCP10, MCP04 |

What to do:

- **Launch command downloads or runs code through a shell**: Replace the entry with a pinned package (npx pkg@1.2.3, uvx pkg==1.2.3) or a local binary you have reviewed. \`--fix --remove\` can delete it.
- **Downloaded script piped straight into a shell**: Never run \`curl ... \| sh\` from an MCP config: download, review and pin the script, or install the server from a package registry. \`--fix --remove\` can delete it.
- **Remote endpoint baked into the launch**: Confirm the host is one you expect this server to talk to. If it is yours, trust it with \`--allow-host\`; if not, remove the server.

### [D] vendor-crm (explicit, 50/100)

examples/demo-mcp.json

| Severity | Check | Finding | OWASP MCP |
|---|---|---|---|
| HIGH | insecure-transport | **Remote MCP server reached without TLS**: remote MCP server in 'url' is reached over plain http:// (no TLS): anyone on the network path can read its traffic, including any token, and rewrite the tool descriptions your agent reads; use https:// | MCP07, MCP03 |
| HIGH | credential-in-url | **Credential written into a server URL**: credential written into the server URL in 'url' (api\_key): URLs are kept in logs, proxies and history, and MCP access tokens must not travel in the query string; send it in an Authorization header that references an environment variable | MCP01, MCP07 |
| MEDIUM | remote-server | **Remote MCP server (traffic leaves the machine)**: remote MCP server URL (traffic leaves the machine): http://mcp.crm-vendor.example/... | MCP10 |

What to do:

- **Remote MCP server reached without TLS**: Use the server's https:// (or wss://) URL. Over plain http anyone on the network can read tokens and rewrite tool descriptions.
- **Credential written into a server URL**: Rotate the credential, remove it from the URL and send it in an Authorization header that references an environment variable ("Bearer $\{TOKEN\}"), or use the server's OAuth sign-in.
- **Remote MCP server (traffic leaves the machine)**: Check you trust the operator with everything your agent will send. Trust a host of your own with \`--allow-host\`.

### [B] github (explicit, 75/100)

examples/demo-mcp.json

| Severity | Check | Finding | OWASP MCP |
|---|---|---|---|
| MEDIUM | floating-version | **Package version not pinned**: unpinned package '@modelcontextprotocol/server-github' — every launch can pull a different (possibly compromised) release; pin with @modelcontextprotocol/server-github@x.y.z | MCP04 |
| MEDIUM | secret-env | **Secrets handed to the server**: server receives secrets via env: GITHUB\_PERSONAL\_ACCESS\_TOKEN — a compromised server leaks these | MCP01, MCP02 |
| LOW | plaintext-secret | **Credential stored in plain text in the config**: credential stored in plain text in the config file: env GITHUB\_PERSONAL\_ACCESS\_TOKEN — anything that can read this file has it; keep it in your OS keychain or shell environment and reference it | MCP01 |

What to do:

- **Package version not pinned**: Pin an exact version (pkg@1.2.3 / pkg==1.2.3) so a compromised release cannot reach you on the next launch.
- **Secrets handed to the server**: Give the server a token with the narrowest scope and shortest life that works, and only to servers you trust.
- **Credential stored in plain text in the config**: Move the value to your OS keychain or shell environment and reference it ("$\{TOKEN\}" where the client supports it). In a project file: rotate it and make sure the file is not committed.

### [A] filesystem (explicit, 100/100)

examples/demo-mcp.json

No findings.

## OWASP MCP Top 10

| Risk | Findings |
|---|---|
| MCP01 Token Mismanagement &amp; Secret Exposure | 3 |
| MCP02 Privilege Escalation via Scope Creep | 1 |
| MCP03 Tool Poisoning | 1 |
| MCP04 Software Supply Chain Attacks &amp; Dependency Tampering | 4 |
| MCP05 Command Injection &amp; Execution | 2 |
| MCP06 Prompt Injection via Contextual Payloads | 0 |
| MCP07 Insufficient Authentication &amp; Authorization | 2 |
| MCP08 Lack of Audit and Telemetry | 0 |
| MCP09 Shadow MCP Servers | 0 |
| MCP10 Context Injection &amp; Over-Sharing | 2 |

The mapping is mcp-gradecard's reading of which risk each finding is evidence of; a zero means no finding of that kind, not that the risk is absent. Source: https://owasp.org/www-project-mcp-top-10/ (beta).

## What this audit covers

- The static audit reads configuration files only; it does not run or connect to any server.
- With --deep, tool descriptions are read from the servers it was allowed to launch and checked against known prompt-injection patterns. That is a heuristic: a clean scan is not proof that a server is safe, and a match is a lead for a person to read, not a verdict.
- Remote (http/sse) servers are judged by their configuration; their live tool lists are not fetched.
- Known-vulnerable packages are matched against the advisory feed built into this version (and OSV with --online); a package with no published advisory reads as clean.
- Nothing here reviews a server's source code or what its tools do when called.

Secrets found in configs are never printed in this report.

