# Using mcp-gradecard for a paid "MCP safety check"

What the tool can honestly support, what a buyer of a one-off audit expects to
receive, and a procedure that keeps every claim inside what the tool did.
Prices are not set here: that is the seller's decision. Have a lawyer read your
engagement letter and any liability wording before you send the first one;
nothing in this file is legal advice.

A finished example is [`examples/demo-report.html`](../examples/demo-report.html)
(and [`.md`](../examples/demo-report.md)), made from a made-up config.

## What a paying customer expects in the report

A one-off security audit report is usually read by two people: someone who
decides (a manager, a CISO) and someone who fixes (an engineer). They look for
the same eight things, and the report has each:

| They expect | Where it is in the report |
|---|---|
| One sentence on how bad it is, and what to do first | The grade and verdict at the top; "Fix these first" |
| Who it was done for, by whom, when, with which tool version | "Scope and method" (needs `--client`, `--prepared-by`) |
| What was and was not looked at | "Scope and method": files read, whether any server was launched, whether anything went online; "What this audit covers" at the end |
| How severity and grade are decided | "Scope and method": the score formula and what each severity means |
| Every finding with the evidence and what to do about it | "Findings by server" (finding text, then "What to do") |
| What the customer already accepted | "Accepted findings" (reason and expiry date for each) |
| A way to check it later | The report id (same findings, same id), the tool version, `--format json` for the machine copy |
| A retest | `--compare first.json` ("Since the previous check") |

A buyer also expects a person to have stood behind it. The report says "Not
recorded" under "Review by a person" until you pass `--reviewed-by NAME`, so do
that only after you have read every critical and high finding yourself.

## Scope statement to put in the engagement letter

Copy, then fill in the brackets. It matches what the report says, so the two
cannot disagree.

> **Scope.** [Company] asks [Seller] to audit the Model Context Protocol (MCP)
> server configuration of [N] named machines / repositories: the MCP client
> configuration files listed in the report, and, only where [Company] agrees
> in writing, the tool lists those servers return.
>
> **Method.** The audit uses mcp-gradecard [version], an automatic rule-based
> tool, run [offline / with package lookups against OSV]. [No server is
> launched. / With the written agreement of [Company], the servers listed in
> the annex are launched on [machine] to read their tool descriptions.] A
> person at [Seller] reads every critical and high finding before the report
> is issued.
>
> **Deliverables.** One report (HTML, plus Markdown or JSON if wanted), and
> [one retest after fixes, using the same tool version / the then-current
> version].
>
> **Not in scope.** Reading the source code of any server; testing what a
> server does when its tools are called; penetration testing; certification or
> compliance with any standard; servers or machines not named; anything that
> changes after the date on the report.

## Options you can offer (no prices here)

1. **Configuration audit.** `mcp-gradecard --format html --client "<client>" --prepared-by "<you>" --scope-note "<one sentence>" --reviewed-by "<name>" -o report.html`. Nothing is launched.
2. **Plus tool descriptions from a saved list.** The customer exports a `tools/list` answer; you run `--tools-json FILE`. Nothing is launched and nothing leaves their network.
3. **Plus a live tool scan.** `--deep`, only with the customer's written agreement: it starts their servers on the machine it runs on, with the safeguards listed in the README.
4. **Retest.** Keep the first run's `--format json` output; after the fixes run again with `--compare first.json`. Grades are comparable only between runs of the same tool version (newer versions add checks: the same config can grade lower), so retest with the version you used the first time, or say so in the report. A report from mcp-gradecard 0.3.0 or earlier cannot be compared (it numbered no findings); run the first check again.
5. **A gate they keep.** `--write-baseline`, then `--baseline` with `--fail-on high` in their CI, or the GitHub Action in this repository.

## Procedure

- Run on the customer's own machine, or on copies of their config files.
- Read every `critical` and `high` yourself before the report goes out. A match
  from the description scan is a lead, not a verdict.
- Agree suppressions with the customer in writing; each needs a reason and a date.
- The report lists server names, config file paths and host names, and never a
  secret value. It can still hold a user name inside a path or a customer
  host name: read it once for that before it leaves, and share it by the
  channel the customer chose.
- Keep the JSON copy and the report id with your notes: they let you show later
  what you found and on which date.

## What you can say

- "On <date>, mcp-gradecard <version> found these findings in the files and tool
  lists named in the report."
- "This is the list of what your configs download and connect to."

## What you cannot say

- That a server is safe, secure or certified; that the description scan finds
  all poisoning (first-contact recall on new attack sets written by its author:
  0.49, 0.41 and 0.37, see the benchmark); that a package is not malicious
  (there is no registry lookup, and the advisory feed holds six entries); that
  any standard is met.
- Anything about servers that were not launched or whose tool lists were not
  read: the report says which were which.
- Anything about what a server's tools do when called, or about its source code.

## Costs

mcp-gradecard is free and runs on the customer's or your own machine: no
account, no API key, no paid service. `--online` sends package names and
versions to OSV (free, no key); leave it off for an air-gapped customer.
