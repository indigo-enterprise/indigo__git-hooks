# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run full test suite
tox

# Run tests directly
pytest tests

# Run single test file
pytest tests/detect_secrets_test.py

# Run with coverage
coverage run -m pytest tests && coverage report

# Run pre-commit linting on all files
tox -e pre-commit
# or:
pre-commit run --all-files --show-diff-on-failure

# Install in dev mode
pip install -e .
```

## Architecture

Fork of [pre-commit/pre-commit-hooks](https://github.com/pre-commit/pre-commit-hooks) extended with Indigo-specific hooks. All hooks are Python CLI scripts in `pre_commit_hooks/`, registered as console entry points in `setup.cfg`, and declared for the pre-commit framework in `.pre-commit-hooks.yaml`.

### Custom Indigo hooks

| File | Hook ID | Purpose |
|------|---------|---------|
| `detect_secrets.py` | `detect-secrets` | Scans staged files for hardcoded credentials |
| `commit_message_uppercase.py` | `commit-message-uppercase` | Validates commit msg starts uppercase |
| `custom-check.py` | `custom-check` | Placeholder for custom validation |
| `pre_commit.py` / `post_commit.py` | stubs | Pre/post commit hook stubs |

Only `detect-secrets` is active in `.pre-commit-config.yaml`; others are commented out.

### detect_secrets flow

1. Get staged files via `git diff --cached --name-only` (filters: Added/Copied/Modified/Renamed)
2. Filter by extension (`.cs`, `.js`, `.json`, `.go`, `.env`, etc.) and skip certain dirs
3. Read file content from git index (`git show :path`), not disk
4. Scan with 20+ regex patterns (AWS, GCP, GitHub, Stripe, JWT, DB connection strings, etc.)
5. Output masked findings as `file:line [type] => masked_value`; return exit code `1` to block commit

### Adding a new secret pattern

Patterns live in `detect_secrets.py` as a list of `(pattern_name, compiled_regex)` tuples. Add a new entry there — no other file changes needed unless the hook should also apply to new file extensions.

### Adding a new hook

1. Create `pre_commit_hooks/my_hook.py` with a `main()` function
2. Add console entry point in `setup.cfg` under `[options.entry_points] console_scripts`
3. Add hook definition in `.pre-commit-hooks.yaml`
4. Add test file `tests/my_hook_test.py` using the `temp_git_dir` fixture from `conftest.py`

## Testing

- One test file per hook: `tests/*_test.py`
- `tests/conftest.py` provides `temp_git_dir` fixture (real git repo in temp dir)
- `tests/testing/resources/` has sample JSON/YAML/XML files for format-checker tests
- CI runs tox on Windows (py39) and Linux (py39–py312) via `.github/workflows/main.yml`
