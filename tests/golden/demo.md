# MCP Safety Check: Example Co

Generated 2026-01-01 00:00 UTC by mcp-gradecard VERSION · 1 config file(s) · 4 server(s) · static audit · prepared by Calas Automations Inc. · report id 98b2ec45ece5

**Overall grade: F** (the lowest grade of any server)

3 critical finding(s): act on these before you use these servers again.

| Critical | High | Medium | Low |
|---|---|---|---|
| 3 | 2 | 3 | 1 |

## Scope and method

- **Prepared for:** Example Co
- **Prepared by:** Calas Automations Inc.
- **Date and tool:** 2026-01-01 00:00 UTC; mcp-gradecard VERSION
- **What was examined:** 1 configuration file(s) (demo) holding 4 MCP server(s). Only the settings written in those files were read.
- **Live tool scan:** Not done. No server was launched and no tool description was read, so poisoned tool text is not covered by this report.
- **Package lookups:** mcp-gradecard sent nothing anywhere. The advisory feed in this version lists 6 known issue(s); a package with no published advisory reads as clean.
- **Engagement scope:** Sample data only.
- **Review by a person:** Critical and high findings were read by A. Reviewer before this report was issued.
- **Grades:** A server starts at 100 and loses 40 per critical, 20 per high, 10 per medium and 5 per low finding (A 90+, B 75+, C 60+, D 40+, F below); any critical caps it at D. The overall grade is the lowest. Grades are comparable only between runs of the same mcp-gradecard version: newer versions add checks.

Severity: critical = the server runs a downloader, pipes content into a shell or is started with encoded code, or a tool description tries to take control of the agent; fix before using it; high = a serious weakness, such as a credential in a URL, a plain-http remote server or a code-injecting launch setting; fix soon; medium = weakens the setup or makes an attack easier, such as an unpinned package; plan a fix; low = hygiene; worth tidying.

## Fix these first

| Severity | Server | Finding |
|---|---|---|
| CRITICAL | `quick-setup` | **Launch command downloads or runs code through a shell**: server runs 'curl' inside 'bash' — a downloader/shell, not a server binary |
| CRITICAL | `quick-setup` | **Downloaded script piped straight into a shell**: command pipes content into a shell (classic curl\|sh pattern) |
| CRITICAL | `quick-setup` | **Remote endpoint baked into the launch**: remote endpoint in args: https\[:\]//get.tools.example/... |
| HIGH | `vendor-crm` | **Remote MCP server reached without TLS**: remote MCP server in 'url' is reached over plain http\[:\]// (no TLS): anyone on the network path can read its traffic, including any token, and rewrite the tool descriptions your agent reads; use https\[:\]// |
| HIGH | `vendor-crm` | **Credential written into a server URL**: credential written into a URL in 'url' (api\_key): URLs are kept in logs, proxies and shell history; keeping credentials out of URLs is standard practice. Send it in an Authorization header that references an environment variable |

## Servers

| Grade | Server | Client | Score | Findings |
|---|---|---|---|---|
| F | `quick-setup` | `demo` | 0/100 | 3 |
| D | `vendor-crm` | `demo` | 50/100 | 3 |
| B | `github` | `demo` | 75/100 | 3 |
| A | `filesystem` | `demo` | 100/100 | 0 |

## Findings by server

### [F] `quick-setup` (`demo`, 0/100)

`(built-in demo - not your machine)`

| Severity | Check | Finding | OWASP MCP |
|---|---|---|---|
| CRITICAL | suspicious-command | **Launch command downloads or runs code through a shell**: server runs 'curl' inside 'bash' — a downloader/shell, not a server binary | MCP05, MCP04 |
| CRITICAL | pipe-to-shell | **Downloaded script piped straight into a shell**: command pipes content into a shell (classic curl\|sh pattern) | MCP05, MCP04 |
| CRITICAL | exfiltration-endpoint | **Remote endpoint baked into the launch**: remote endpoint in args: https\[:\]//get.tools.example/... | MCP10, MCP04 |

What to do:

- **Launch command downloads or runs code through a shell**: Replace the entry with a pinned package (npx pkg@1.2.3, uvx pkg==1.2.3) or a local binary you have reviewed. `--fix --remove` can delete it.
- **Downloaded script piped straight into a shell**: Never run `curl ... | sh` from an MCP config: download, review and pin the script, or install the server from a package registry. `--fix --remove` can delete it.
- **Remote endpoint baked into the launch**: Confirm the host is one you expect this server to talk to. If it is yours, trust it with `--allow-host`; if not, remove the server.

### [D] `vendor-crm` (`demo`, 50/100)

`(built-in demo - not your machine)`

| Severity | Check | Finding | OWASP MCP |
|---|---|---|---|
| HIGH | insecure-transport | **Remote MCP server reached without TLS**: remote MCP server in 'url' is reached over plain http\[:\]// (no TLS): anyone on the network path can read its traffic, including any token, and rewrite the tool descriptions your agent reads; use https\[:\]// | MCP07, MCP03 |
| HIGH | credential-in-url | **Credential written into a server URL**: credential written into a URL in 'url' (api\_key): URLs are kept in logs, proxies and shell history; keeping credentials out of URLs is standard practice. Send it in an Authorization header that references an environment variable | MCP01, MCP07 |
| MEDIUM | remote-server | **Remote MCP server (traffic leaves the machine)**: remote MCP server URL (traffic leaves the machine): http\[:\]//mcp.crm-vendor.example/... | MCP10 |

What to do:

- **Remote MCP server reached without TLS**: Use the server's https\[:\]// (or wss\[:\]//) URL. Over plain http anyone on the network can read tokens and rewrite tool descriptions.
- **Credential written into a server URL**: Rotate the credential, remove it from the URL and send it in an Authorization header that references an environment variable ("Bearer $\{TOKEN\}"), or use the server's OAuth sign-in.
- **Remote MCP server (traffic leaves the machine)**: Check you trust the operator with everything your agent will send. Trust a host of your own with `--allow-host`.

### [B] `github` (`demo`, 75/100)

`(built-in demo - not your machine)`

| Severity | Check | Finding | OWASP MCP |
|---|---|---|---|
| MEDIUM | floating-version | **Package version not pinned**: unpinned package '@modelcontextprotocol/server-github' — every launch can pull a different (possibly compromised) release; pin with @modelcontextprotocol/server-github@x.y.z | MCP04 |
| MEDIUM | secret-env | **Secrets handed to the server**: server receives secrets via env: GITHUB\_PERSONAL\_ACCESS\_TOKEN — a compromised server leaks these | MCP01, MCP02 |
| LOW | plaintext-secret | **Credential stored in plain text in the config**: credential stored in plain text in the config file: env GITHUB\_PERSONAL\_ACCESS\_TOKEN — anything that can read this file has it; keep it in your OS keychain or shell environment and reference it | MCP01 |

What to do:

- **Package version not pinned**: Pin an exact version (pkg@1.2.3 / pkg==1.2.3) so a compromised release cannot reach you on the next launch.
- **Secrets handed to the server**: Give the server a token with the narrowest scope and shortest life that works, and only to servers you trust.
- **Credential stored in plain text in the config**: Move the value to your OS keychain or shell environment and reference it ("$\{TOKEN\}" where the client supports it). In a project file: rotate it and make sure the file is not committed.

### [A] `filesystem` (`demo`, 100/100)

`(built-in demo - not your machine)`

No findings.

## Inventory

| Server | Client | Runs or connects to |
|---|---|---|
| `filesystem` | `demo` | npm @modelcontextprotocol/server-filesystem 2026.1.14 |
| `github` | `demo` | npm @modelcontextprotocol/server-github (not pinned) |
| `vendor-crm` | `demo` | remote http\[:\]//mcp.crm-vendor.example |
| `quick-setup` | `demo` | local command |

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
- What this report supports: on the date shown, this version of mcp-gradecard found the findings listed in the configuration files and tool lists named in it.
- What it does not support: that any server is safe, secure or compliant with a standard. It is not a certification, a penetration test or a code review.

Secrets found in configs are never printed in this report.

