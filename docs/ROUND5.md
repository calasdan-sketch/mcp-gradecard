# Round 5: the one-off paid MCP safety check

Branch `expert-2`. Nothing was published, uploaded, tagged or pushed.

## How the review was done (read this first)

This tool set could not start sub-agents. One reviewer played each specialist
in turn and ran real commands for each. They are not independent opinions: the
same person who wrote the code attacked it. The new benchmark set (`r5`) was
written by that person too.

## Author line

The author and maintainer is "Calas Automations Inc." in `pyproject.toml`
(`authors` and `maintainers`, name only, no e-mail), `mcp_gradecard.__author__`,
`LICENSE`, `action.yml`, SARIF (`organization`), CycloneDX (tool `author`) and
`--help`. `tests/test_round5.py::TestAuthorLine` pins every one, and checks the
old name is gone from the shipped text files. Proof from a freshly built wheel
(`python -m build`, in a scratch folder):

```
$ unzip -p dist/*.whl '*/METADATA' | grep -E '^(Author|Maintainer)'
Author: Calas Automations Inc.
Maintainer: Calas Automations Inc.
```

`twine check --strict` passed for the wheel and the sdist. The project URLs
still point at github.com/calasdan-sketch/mcp-gradecard; whether that
repository is public could not be checked from here (the read of its settings
was refused), so `PUBLISH-CHECKLIST.md` asks Dan to decide.

## Baseline (before any change)

| | |
|---|---|
| Tests (Python 3.13) | 910 passed, 1 failed: `TestTimeIsLinear::test_no_shape_is_quadratic` (3.5 s against a 3 s bound while the machine had a load average of 14; passes alone) |
| Benchmark | dev recall 0.940 / FPR 0.024; holdout 0.784 / 0.036; r3 1.000 / 0.000; r3b 1.000 / 0.067 (356 definitions) |
| Registry (`pip index versions`) | `mcp-gradecard` 0.3.0 only |

## Specialists and what each found

1. **MCP security researcher.** Ran nine hostile configs through the CLI
   (`mcp-remote@0.1.5`, Inspector 0.14.0, `mcp-server-git==2025.9.25`, an old
   Filesystem server, a `uvx --from git+...`, a privileged `docker run -v /:/host`,
   `cmd /c npx pkg@latest`, ...). **Defect:** the advisory feed held three entries,
   so a config pinned to the Inspector with its unauthenticated-proxy RCE
   (CVE-2025-49596), the Filesystem server with its symlink and prefix escapes
   (CVE-2025-53109/53110) or `mcp-server-git` with its three 2025 CVEs graded
   100/100. NVD records were read with `curl` on 2026-11-08 and three entries
   added, quoting the record and the advisory it names. The Filesystem server
   changed its numbering (0.6.4, then 2025.7.1), and a plain "fixed in" would
   have called 2025.3.28 patched (2025 > 0.6): the new optional `fixed_lines`
   handles it (`tests/test_round5.py::TestAdvisoriesFromCveRecords`). `mcp-remote`
   CVE-2025-6514 was **not** added: the NVD text names no fixed version and the
   vendor page was not readable here. Not guessed. The `git+https://example.com`
   source being "critical remote endpoint" is the documented behaviour (only
   known forges are `git-source`), left alone.
2. **Prompt-injection specialist.** Wrote 27 malicious and 14 benign definitions
   in attack families the earlier sets lacked (instructions inside a tool
   result, an image or a fetched page; writing to agent memory, `CLAUDE.md`, the
   user's MCP settings or shell profile; a markdown image that carries data out;
   a chain into another tool; disabling a filter; a cover story; "this server
   wins"), without reading the patterns. First measurement, before any change:
   **recall 0.370, 17 of 27 missed, 0 false alarms** (`bench/r5_before.json`).
   Then added patterns for the families (`poisoning._round5`) and reached 1.000;
   that number no longer measures new attacks. A first draft of the patterns
   flagged 2 of 17 ordinary sentences ("Do what it says in the help text", "The
   operator has allowed you to use this tool"), and a cover-story pattern as
   first written would have flagged any "If the user asks ..., tell them ...";
   all three were narrowed. On re-reading three more were judged too broad
   ("the discount rules do not apply", "Everything is encrypted" next to "to
   memory", "without asking first") and narrowed. All 21 ordinary sentences now
   sit in a test that must stay clean. Whole
   corpus after: recall 0.946, precision 0.981, FPR 0.023 (397 definitions);
   holdout recall 0.784 to 0.811 as a side effect; no false alarm added.
3. **CISO reviewing a purchased report.** Asked for: scope and method up front,
   who and when, what was *not* done, how severity is defined, whether a human
   stood behind it, and a way to check it later. The report had the last of
   these (report id) and the limits at the very end, but no scope statement,
   no severity definitions and no statement about review. Added "Scope and
   method" (both formats), `--client`, `--scope-note`, `--reviewed-by`; without
   `--reviewed-by` the report says "Not recorded" rather than implying review.
   Also noted: a paid report can carry user names inside paths; the seller guide
   now says to read for that.
4. **Sales / packaging.** What a buyer of a one-off audit expects (table in
   `docs/safety-check.md`), a scope statement to copy into an engagement letter,
   four options without prices (config only; plus a saved tool list; plus a
   live scan with written consent; retest), honest limits with the measured
   first-contact numbers (0.49, 0.41, 0.37), and a sample report
   (`examples/demo-report.html`, regenerated with the new section). Price,
   naming and any liability wording are left to Dan and a lawyer.
5. **Upgrade-path tester.** `pip download mcp-gradecard==0.3.0 --no-deps`, built
   in its own venv. Same `examples/demo-mcp.json` through 0.3.0 and this tree:
   `vendor-crm` went A to D, `github` 2 to 3 findings; others equal. A 0.3.0
   `--format json` report has no `tool`, no `schema_version` and no finding ids,
   so `--compare` answered "not an mcp-gradecard report". Not migrated on
   purpose: wording and severities moved between versions, so id-matching an
   old report would invent "resolved" and "new". It now says it is a 0.3.0 or
   earlier report and to rerun the first check. Documented that grades are only
   comparable within one version. The `mcp-audit` alias, `MCP_AUDIT_HOME` and
   the `.mcp-gradecard.bak-` suffix are unchanged from 0.3.0.
6. **QA / test methodology.** Golden files for every output format (text, JSON,
   SARIF, CycloneDX, Markdown, HTML) from a fixed-time demo run
   (`tests/golden`, refresh with `UPDATE_GOLDEN=1`). **Defect found by it:** the
   SARIF of `--demo` carried a file path invented under the current directory,
   and its fingerprints changed with the directory; fixed (`urn:mcp-gradecard:demo`).
   Seeded property tests: `scan()` never raises and is deterministic over 400
   random hostile strings; a known attack stays flagged inside 60 random
   wrappers; no report format ever prints ESC, BEL, DEL or a bidi control for 25
   random hostile server names. `hypothesis` is not installed, so a seeded
   generator was used.
   **Mutation-style check** (`/tmp` script, 14 one-line changes, targeted tests):
   12 killed, 2 survived. Survivors were fixed: "installed == fixed version is
   patched" had no test (added), and the markdown-image rule was masked by
   another signal (a test now checks the signal itself). Re-run: all 14 killed.
7. **Release engineer.** Built the wheel and sdist, installed the wheel in a
   clean venv in a folder with a space in its name, ran `--version`,
   `mcp-audit --version`, `--demo`, `--demo --format html -o "my report.html"
   --client ...`, `--compare`. **Defect:** the sdist left out `CHANGELOG.md`,
   `action.yml`, `docs/` and `examples/`, so 6 tests fail when run from the sdist
   (the CI step "the tests pass from the sdist" would have failed since round 4).
   Fixed in `MANIFEST.in`; the sdist now runs 940 tests, all passing.
8. **Hostile input, locale, concurrency, no network.** `LC_ALL=C
   PYTHONIOENCODING=ascii` with a client name holding accents, CJK and an emoji,
   written with `-o` to a path with spaces: correct UTF-8 file. Blank `--client
   "   "` gave the title "MCP Safety Check: " (fixed). Eight processes writing the
   same `-o` file at once left one complete HTML file and no temporary files.
   `--demo` with no proxy variables: 1 s, exit 0. Ruff passes.

## Pass B: attacking the new code

Re-read the diff for: a regex that could flag ordinary text (3 more narrowed; see 2),
an untrusted string reaching a report unescaped (`--client`, `--scope-note`,
`--reviewed-by` go through the same `_h`/`_m` as everything else; hostile
values tested in both formats), a claim in the report that is not true ("Offline:
nothing was sent anywhere" was wrong with `--deep`, whose servers may contact
their own services: reworded), a wording that implies review that did not
happen (it says "Not recorded"). Every README, CHANGELOG and checklist claim was
checked from the built wheel (see 7); the advisory count in the README and the
seller guide is held to the feed by a test.

## Tests and benchmark, before and after

| | Before | After |
|---|---|---|
| Tests | 910 passed, 1 failed (timing) | 939 passed, 1 skipped (built wheel absent in the tree), 0 failed |
| Sdist test run | 6 errors | 940 tests, OK |
| dev | 0.940 / 0.975 / 0.024 | 0.940 / 0.975 / 0.024 |
| holdout | 0.784 / 0.967 / 0.036 | 0.811 / 0.968 / 0.036 |
| r3, r3b | 1.000 / 1.000 / 0.000, 1.000 / 0.967 / 0.067 | unchanged |
| r5 (new) | **0.370 / 1.000 / 0.000** first measurement | 1.000 / 1.000 / 0.000 (tuned on, so not evidence) |
| whole corpus | 0.934 / 0.979 / 0.025 (356) | 0.946 / 0.981 / 0.023 (397) |

(Recall / precision / false-positive rate, any finding.)

## Competitors (read-only)

`pip index versions` on 2026-11-08: `snyk-agent-scan` 0.6.11 and
`cisco-ai-mcp-scanner` 4.8.7, the versions the README comparison was measured
against. Their pages and code were not re-read, and Cisco's analyzer was not
re-run on the new `r5` set (unverified). The README comparison is unchanged and
labelled as measured on the first four parts.

## Scored ideas

Scores 1 to 5; for effort and risk, 1 is cheap or safe.

| # | Idea | Value | Differs from rivals | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | "Scope and method" section in both reports | 5 | 4 | 2 | 1 | DONE |
| 2 | `--client`, `--scope-note`, `--reviewed-by` (was round 4 #16) | 5 | 4 | 2 | 1 | DONE |
| 3 | Seller guide: buyer expectations, scope statement, options, limits | 5 | 4 | 2 | 1 | DONE |
| 4 | Sample report regenerated with the new section | 4 | 2 | 1 | 1 | DONE |
| 5 | Advisories for Inspector, Filesystem server, `mcp-server-git` | 5 | 3 | 2 | 2 | DONE |
| 6 | `fixed_lines` for packages that changed numbering | 3 | 2 | 2 | 2 | DONE |
| 7 | Description signals for results, memory, rules files, images, chaining | 5 | 5 | 4 | 3 | DONE |
| 8 | Fresh unseen benchmark part `r5`, first measurement kept | 4 | 4 | 2 | 1 | DONE |
| 9 | Golden files for every output format | 4 | 1 | 2 | 1 | DONE |
| 10 | Seeded property tests, mutation sanity run | 3 | 1 | 2 | 1 | DONE (mutation run is a scratch script, not in the repo) |
| 11 | Plain message for a 0.3.0 report given to `--compare` | 3 | 1 | 1 | 1 | DONE |
| 12 | Demo SARIF no longer invents a path | 2 | 1 | 1 | 1 | DONE |
| 13 | Sdist ships the files the tests read | 3 | 1 | 1 | 1 | DONE |
| 14 | Author line "Calas Automations Inc." everywhere, pinned by a test | 5 | 1 | 1 | 1 | DONE |
| 15 | `mcp-remote` CVE-2025-6514 in the feed | 4 | 3 | 1 | 2 | NOT-DONE (no readable source for the fixed version) |
| 16 | Migrate a 0.3.0 report for `--compare` by matching on check and server | 2 | 2 | 3 | 4 | NOT-DONE (would invent resolved and new findings) |
| 17 | Redact user names in paths (`--redact-paths`) for a customer copy | 4 | 4 | 3 | 2 | NOT-DONE |
| 18 | Remediation table: owner and due date per finding, as a CSV | 3 | 3 | 3 | 1 | NOT-DONE |
| 19 | PDF output | 3 | 2 | 4 | 3 | NOT-DONE (needs a dependency; the HTML prints to PDF) |
| 20 | Cut the 90 KB README into `docs/` (round 4 #15) | 4 | 1 | 3 | 3 | NOT-DONE (tests quote README text) |
| 21 | Better recall of the description scan on unseen wording | 5 | 5 | 5 | 3 | NOT-DONE (0.37 on first contact stays the honest number; an LLM-based second reader would need a key and a cost) |
| 22 | Package age and maintainer lookup | 4 | 4 | 4 | 4 | NOT-DONE (network and privacy trade-off) |
| 23 | Trusted-publishing release workflow | 3 | 1 | 2 | 3 | NOT-DONE (needs PyPI-side settings) |
| 24 | Hosted CI run of the Action and the Windows and macOS legs | 4 | 1 | 1 | 1 | NOT-DONE (cannot from here) |
| 25 | Automatic advisory refresh from OSV for the whole feed | 4 | 3 | 4 | 4 | NOT-DONE (the offline feed is a selling point; `--online` exists) |
| 26 | Sign the report (detached signature) | 2 | 3 | 3 | 3 | NOT-DONE |
| 27 | Move the look-alike token out of `examples/demo-mcp.json` (round 4 #26) | 2 | 1 | 2 | 1 | NOT-DONE |
| 28 | `--where`: list the places searched and which exist (round 4 #19) | 3 | 2 | 2 | 1 | NOT-DONE |

## Could not test

- Windows and macOS: never run. The CI matrix lists them; no hosted run was seen.
- Python 3.10 and 3.14 (not installed); 3.11 to 3.13 were run in earlier rounds,
  this round used 3.13 only.
- Whether the GitHub repository is public (the read was refused).
- The vendor write-up for `mcp-remote` CVE-2025-6514 (access to the page was
  refused; no workaround was tried).
- Cisco's and Snyk's current pages and a re-run of Cisco's analyzer on `r5`.
- The GitHub Action on a hosted runner.
- The advisory entries were checked against NVD only, not against OSV records;
  the Filesystem server's second fixed version is written "2025.7.01" in the
  records and is read as 2025.7.1.
- Timing tests fail when the machine is busy (one did at baseline); they pass alone.
