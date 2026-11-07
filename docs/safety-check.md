# Using mcp-gradecard for a paid "MCP safety check"

What the tool can honestly support, and a procedure that keeps the claims
inside it. Prices are not set here: that is the seller's decision.

## What the client gets

1. `mcp-gradecard --format html --report-title "MCP Safety Check: <client>" --prepared-by "<you>"`
   (add `--deep` only with the client's written agreement: it launches their
   servers on the machine it runs on).
2. The report has: an overall grade and plain sentence, what to fix first,
   every server with its findings and what to do, an inventory (packages with
   pin state, remote hosts), accepted findings with reasons and dates, the
   OWASP MCP Top 10 mapping, a report id, and what the audit does not cover.
3. Optionally `--format cyclonedx` (a bill of materials) and a baseline file,
   so the client's CI can keep the gate after you leave
   (`--write-baseline`, then `--baseline` with `--fail-on high`).

## Procedure

- Run on the client's own machine or on copies of their config files and, if
  they can export it, a saved `tools/list` answer (`--tools-json`): nothing
  has to be launched and nothing leaves their network.
- Read every `critical` and `high` yourself before the report goes out. A match
  from the description scan is a lead, not a verdict.
- Agree suppressions with the client in writing; each needs a reason and a date.
- Re-run after they fix things and send both reports.

## What you can say

- "On <date>, mcp-gradecard <version> found these findings in the files and tool
  lists listed in the report."
- "This is the list of what your configs download and connect to."

## What you cannot say

- That a server is safe, secure or certified; that the description scan finds
  all poisoning (measured recall on the author's holdout set: 0.73); that a
  package is not malicious (there is no registry lookup, and the advisory feed
  is small); that any standard is met.
- Anything about servers that were not launched or whose tool lists were not
  read: the report says which were which.
