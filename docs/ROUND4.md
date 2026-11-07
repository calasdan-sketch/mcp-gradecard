# Round 4: the first hour of someone who types `pip install mcp-gradecard`

Branch `expert-2`. Nothing was published, uploaded, tagged or pushed.

## How the review was done (read this first)

The tooling for this round could not start sub-agents. One reviewer ran every
specialist role in turn, each with real commands against a freshly built
wheel in a scratch virtual environment (not editable), in a directory whose
name contains spaces. These are not independent opinions: the same person
who wrote the code attacked it. Two earlier rounds did the same and skipped
the written list; this file is that list.

## Baseline (before any change)

| | |
|---|---|
| Tests (Python 3.13) | 876 passed, 3 skipped, 1486 subtests |
| Benchmark, whole corpus | unchanged this round: dev recall 0.940 / FPR 0.024; holdout recall 0.784 / FPR 0.036; r3 1.000 / 0.000; r3b 1.000 / 0.067 |
| Registry (read-only `pip index versions`) | PyPI has `mcp-gradecard` **0.3.0** only. Repo is 0.5.0 (0.4.0 was never published) |
| Packaging | `python -m build` and `twine check --strict` pass; wheel has LICENSE, entry points for both commands, `advisories.json`; no tests, no personal paths |

## Specialists and what each found

Every finding names the command that showed it.

1. **First-time user, README only, clean machine.**
   `mcp-gradecard` on a machine with no MCP clients printed one warning and
   stopped: a dead end, and the only way to see output was to already own a
   config. The README told people to install from a Git URL. The terminal
   report ended on a bare "N servers, N findings" line with no overall grade
   and no next step. (`HOME=<empty> mcp-gradecard`.) Fixed: `--demo`, the
   empty-machine help, the "Overall / Fix first / Next" ending.
2. **Release / packaging engineer.**
   Metadata lacked Python-version classifiers, a Source and a Changelog link
   (`unzip -p *.whl '*/METADATA'`). The sdist ships tests and the benchmark,
   which CI uses on purpose. On the system Python 3.12, whose setuptools is
   older than 77, `pip install` without build isolation fails on the
   `license = "MIT"` expression; with normal isolation it builds. Documented in
   the checklist, not changed (the build requirement is already
   `setuptools>=77`). 0.4.0 is in the changelog but was never published.
3. **Supply-chain reviewer.**
   No runtime dependencies (`pip list` in the clean venv shows only pip and
   the package). The only network use is `--online`. The new demo builds its
   look-alike token at run time (a test fails if a whole token appears in the
   source). `-o` could have overwritten a client's own config if pointed at
   it: now refused, tested (`-o ~/.claude.json` style).
   `examples/demo-mcp.json` still holds a literal look-alike token, written
   in an earlier round; secret scanners may flag it. Not changed because the
   committed demo reports are generated from it.
4. **Docs / DX writer.**
   `--help` was 100 lines of options with no starting point and no exit codes.
   Now ends with first-run commands and exit codes. "1 servers" fixed. The
   README is 87 KB and is the PyPI page; the first screen is now value line,
   install, `--demo`. Splitting the long reference into `docs/` is NOT-DONE.
5. **CI/CD integrator.**
   PowerShell's `>` writes UTF-16, which breaks the documented
   `--format html > report.html`. Added `-o FILE` (UTF-8, LF, atomic). Exit
   codes verified from the installed command: unreadable config 2, bad flag 2,
   `--fail-on high` on the demo 1, empty machine 0 (and 2 with
   `--require-servers`). `summary.overall_grade` added to the JSON.
6. **Hostile-input fuzzer.**
   Run from the installed wheel: empty file, `{bad`, 3000-deep nesting, UTF-8
   BOM, Latin-1 file, a server name holding ESC and a right-to-left override,
   a directory given as `--config`, no `HOME`, `LC_ALL=C`, a closed pipe
   (`| head -1`). All ended with a plain message or a clean report, none with
   a traceback. **Defect found:** an expired suppression crashed the terminal
   report (`TypeError at scoring.py:178`): the function reused the name of its
   sanitizer for the totals. Fixed, tested.
7. **Performance engineer.**
   20,000 servers in one file: 19 s, about 1 ms a server, linear (2,000: 2.7 s;
   4,000: 3.8 s including start-up). Profile is spread over the launch
   scanner and the typosquat check; no hot spot worth the risk. Not changed.
8. **Windows reviewer (static only; never run on Windows).**
   Read for path separators, `os.replace`, console encoding, CRLF, `shell=True`
   and signals. Earlier rounds had already handled most: no `shell=True`;
   `taskkill /T` for process trees; `SIGBREAK`; ASCII stand-ins for the
   report glyphs on cp1252; UTF-8 for every text file. Gap fixed:
   `os.replace` over a file another program holds open raises
   `PermissionError` on Windows; now retried (baseline, pins, `-o`), simulated
   in tests. Terminal colour is off by default on Windows unless a terminal
   that shows it is detected. **Not run on Windows.**
9. **Competitor's maintainer.**
   `pip index versions` today: snyk-agent-scan 0.6.11 and cisco-ai-mcp-scanner
   4.8.7, the versions the README comparison was measured against, so the
   table is not stale. Their pages were not re-read this round (unverified).
   Where they lead stays as the README says: Cisco on source and binary
   analysis and an LLM engine, Snyk on hosted analysis.

## Scored ideas

Scores 1 (low) to 5 (high); for effort and risk, 1 is cheap or safe.

| # | Idea | User value | Differs from rivals | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | `--demo`: report on a built-in sample | 5 | 4 | 2 | 1 | DONE |
| 2 | Report ending: overall grade, fix first, next commands | 5 | 3 | 2 | 1 | DONE |
| 3 | Empty-machine guidance instead of a bare warning | 4 | 2 | 1 | 1 | DONE |
| 4 | `-o FILE`: UTF-8, atomic, plain-English failure | 4 | 2 | 2 | 1 | DONE |
| 5 | `-o` refuses to replace a file the audit reads | 4 | 2 | 1 | 1 | DONE |
| 6 | Colour on a terminal, `--color`, `NO_COLOR` | 3 | 1 | 2 | 1 | DONE |
| 7 | `--help` epilog: first run and exit codes | 3 | 1 | 1 | 1 | DONE |
| 8 | Fix expired-suppression crash | 4 | 1 | 1 | 1 | DONE |
| 9 | Retry `os.replace` on a busy file (Windows) | 2 | 1 | 1 | 1 | DONE (simulated only) |
| 10 | Metadata: classifiers, Source and Changelog links, description | 3 | 1 | 1 | 1 | DONE |
| 11 | README quick start from the registry name, with a removable release note | 4 | 1 | 1 | 2 | DONE |
| 12 | Singular and plural in the summary line | 1 | 1 | 1 | 1 | DONE |
| 13 | "Nothing new" when every serious finding is in the baseline | 3 | 3 | 1 | 1 | DONE |
| 14 | `summary.overall_grade` in JSON | 3 | 2 | 1 | 1 | DONE |
| 15 | Cut the README to a one-screen page, move the reference to `docs/` | 4 | 1 | 3 | 3 | NOT-DONE (tests quote README text; do as its own change) |
| 16 | `--client "Name"` shortcut: title, prepared-by and file name for a paid check | 4 | 4 | 2 | 1 | NOT-DONE |
| 17 | PDF output | 3 | 2 | 4 | 3 | NOT-DONE (needs a dependency; the HTML already prints to PDF) |
| 18 | `--open` to show the HTML report in a browser | 2 | 1 | 1 | 2 | NOT-DONE (starts a program) |
| 19 | `--where`: list the places searched and which exist | 3 | 2 | 2 | 1 | NOT-DONE |
| 20 | Better recall of the description scan (holdout 0.784) | 5 | 5 | 5 | 3 | NOT-DONE (round 3 territory; every pattern added so far fits the texts it was added for) |
| 21 | Trusted-publishing release workflow | 3 | 1 | 2 | 3 | NOT-DONE (needs settings on the PyPI side; nothing to publish from here) |
| 22 | Package age and maintainer lookup (npm, PyPI) | 4 | 4 | 4 | 4 | NOT-DONE (network and privacy trade-off; offline is the selling point) |
| 23 | Config file for `--allow-host` and defaults | 3 | 1 | 3 | 3 | NOT-DONE (README says "no config file" on purpose) |
| 24 | Type hints, `py.typed`, mypy in CI | 1 | 1 | 4 | 1 | NOT-DONE (no typed API is promised) |
| 25 | Run the Action and the CI matrix on hosted runners | 4 | 1 | 1 | 1 | NOT-DONE (cannot from here; the Windows leg has never run) |
| 26 | Move the demo token out of `examples/demo-mcp.json` | 2 | 1 | 2 | 1 | NOT-DONE (reports are generated from it) |

## Changes with tests

- New: `mcp_gradecard/demo.py`, `mcp_gradecard/_fsutil.py`, `tests/test_round4.py` (31 tests).
- Changed: `cli.py` (`--demo`, `-o`, `--color`, epilog, JSON grade), `scoring.py`
  (ending block, colour, bug fix), `baseline.py` and `toolset.py` (retrying
  replace), `pyproject.toml`, README, CHANGELOG, schema (one optional field).
- One existing test changed: `test_hostile_input` counts how often a hostile
  name is printed; the new "Fix first" block prints it twice more (still
  escaped, still no forged line).

## Could not test

- Windows, macOS: not run. The CI matrix lists them; no hosted run was seen.
- Python 3.10 (not installed here) and 3.14. 3.11, 3.12 and 3.13 were run.
- A read-only file system and permission errors: the sandbox runs as root, so
  permission checks pass. Write failures were tested with a missing folder, a
  folder given as the file, and a simulated full disk.
- `pip install mcp-gradecard` from the real registry: 0.5.0 is not there. The
  wheel was installed from the built file; `uvx --from` and `pipx run --spec`
  against that file work; the bare-name forms in the README cannot be tried
  until release.
- The competitors' current pages were not re-read.
- The GitHub Action on a hosted runner.
- Timing tests (`TestTimeIsLinear`, the redaction one) fail when the machine
  is busy: they did when two test suites ran at once on this shared machine,
  and pass alone.
