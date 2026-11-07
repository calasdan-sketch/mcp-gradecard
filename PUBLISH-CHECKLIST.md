# Publish checklist for mcp-gradecard (read it, then do it yourself)

Nothing here has been run for you. Nobody has uploaded, tagged or pushed.

## Which version

**0.5.0.** PyPI has 0.3.0. 0.4.0 was never published, so 0.5.0 carries both.
It is a minor step, not a breaking one: the commands and the JSON keys are
the same, and `mcp_audit` / `mcp-audit` still work. Two things people may
notice: new checks can give a server a lower grade than 0.3.0 did, and the
terminal report is a few lines longer. Both are in the changelog.

## Check first

1. You are on branch `expert-2` and the tests pass: `python -m pytest -q`.
   (Two timing tests can fail if the computer is busy; run them alone.)
2. Open `README.md`. Under "Quick start" there is a "Release note" box.
   It says 0.5.0 is not on PyPI yet. **Delete that box and the
   "see the release note" words in the Install section after you publish**,
   in the same commit that goes to the main branch. Do not leave it in.
3. `CHANGELOG.md`: change "0.5.0 (unreleased)" to "0.5.0 (2026-MM-DD)" with the
   real date, and the same for "0.4.0 (unreleased)" (it says it ships in 0.5.0).
4. `pyproject.toml` version, `mcp_gradecard/__init__.py` and the changelog all say
   0.5.0 (a test checks this).

## Build and look (nothing is uploaded)

```bash
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
python -m venv /tmp/try && /tmp/try/bin/pip install dist/*.whl
/tmp/try/bin/mcp-gradecard --version      # mcp-gradecard 0.5.0
/tmp/try/bin/mcp-gradecard --demo         # a report with grade F
```

On Windows use `\tmp\try\Scripts\mcp-gradecard` or `py -m venv`. That is the
one place nobody has run it: please do it once on a Windows computer, and open
the HTML from `--demo --format html -o demo.html` in a browser.

## Upload

Use a PyPI API token limited to this project (not your account password):

```bash
python -m twine upload dist/*
```

Then, in a fresh folder: `pip install mcp-gradecard`, `mcp-gradecard --version`,
`mcp-gradecard --demo`. If that works, tag it: `git tag v0.5.0`.

## After

- Remove the README release note (step 2) and push.
- Do not publish a second time under the same number: PyPI never lets you
  replace a file. If something is wrong, release 0.5.1.

## Things only you can decide

- Whether to keep the name `mcp-gradecard` in marketing, and the price of a
  paid MCP safety check (see `docs/safety-check.md`; this repo sets no price).
- Whether `examples/demo-mcp.json` should keep its look-alike token (secret
  scanners may flag it; it is not a real secret).
