# Publish checklist for mcp-gradecard (read it, then do it yourself)

Nothing here has been run for you. Nobody has uploaded, tagged or pushed.
The upload step is yours: you are signed in to PyPI, this checklist is not.

## Which version

**0.5.0.** PyPI has 0.3.0 only (checked on 2026-11-08 with
`pip index versions mcp-gradecard`). 0.4.0 was never published, so 0.5.0
carries both. Round 5 changed behaviour (new advisories, more description
patterns, a new "Scope and method" section in reports), but 0.5.0 has not been
published yet, so it stays 0.5.0. If you ever publish and then change
something, the next number is 0.5.1: PyPI never lets you replace a file.

Two things people may notice after upgrading from 0.3.0: new checks can give a
server a lower grade (a config that was an A can be a D), and the terminal
report is a few lines longer. Both are in `CHANGELOG.md`.

## Decide first (two minutes)

1. **Is the GitHub repository public?** The package page links to
   `github.com/calasdan-sketch/mcp-gradecard` (Homepage, Source, Issues,
   Changelog in `pyproject.toml`). If the repository is private, delete the
   whole `[project.urls]` block in `pyproject.toml` before you build, or the
   package page will show links that do not open for anyone else. This was not
   checked from here.
2. The author shown on PyPI is "Calas Automations Inc." with no e-mail. That
   is deliberate; add an e-mail line only if you want one public.

## Check first

1. You are on branch `expert-2` and the tests pass: `python -m pytest -q`.
   (Two tests measure speed and can fail when the computer is busy; run them
   alone: `python -m pytest -q tests/test_description_scanner.py tests/test_redaction.py`.)
2. Open `README.md`. Under "Quick start" there is a "Release note" box saying
   0.5.0 is not on PyPI yet. **Delete that box and the "see the release note"
   words in the Install section after you publish**, in the same commit that
   goes to the main branch.
3. `CHANGELOG.md`: change "0.5.0 (unreleased)" to "0.5.0 (2026-MM-DD)" with the
   real date, and the same for "0.4.0 (unreleased)" (it says it ships in 0.5.0).
4. `pyproject.toml`, `mcp_gradecard/__init__.py` and the changelog all say
   0.5.0 (a test checks this).
5. Look at `examples/demo-report.html` in a browser once. It is the sample you
   can show a customer.

## Build and look (nothing is uploaded)

```bash
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
unzip -p dist/*.whl '*/METADATA' | grep -E '^(Version|Author|Maintainer)'
#   Author: Calas Automations Inc.      Maintainer: Calas Automations Inc.
python -m venv /tmp/try && /tmp/try/bin/pip install dist/*.whl
/tmp/try/bin/mcp-gradecard --version      # mcp-gradecard 0.5.0
/tmp/try/bin/mcp-gradecard --demo         # a report with grade F
/tmp/try/bin/mcp-gradecard --demo --format html --client "Example" -o demo.html
```

On Windows use `\tmp\try\Scripts\mcp-gradecard` or `py -m venv`. That is the
one place nobody has run it: please do it once on a Windows computer, open the
HTML from the last command in a browser, and check the terminal report shows
no garbled characters.

## Upload

Use a PyPI API token limited to this project (not your account password):

```bash
python -m twine upload dist/*
```

Then, in a fresh folder: `pip install mcp-gradecard`, `mcp-gradecard --version`,
`mcp-gradecard --demo`. If that works, tag it: `git tag v0.5.0`.

## After

- Remove the README release note (check 2) and push.
- Do not publish a second time under the same number. If something is wrong,
  release 0.5.1.

## Before you sell a paid check

Read `docs/safety-check.md`. In short: read every critical and high finding
yourself and then pass `--reviewed-by "<your name>"`; never promise that a
server is "safe"; do not use `--deep` without the customer's written
agreement. A lawyer should read your engagement letter. The price is yours to
set; the tool itself costs nothing to run and calls no paid service.

## Things only you can decide

- The price and name of the paid check (this repository sets none).
- Whether `examples/demo-mcp.json` should keep its look-alike token (secret
  scanners may flag it; it is not a real secret).
- Whether to add `mcp-remote` (CVE-2025-6514) to the advisory feed once you
  have a source that states its fixed version.
