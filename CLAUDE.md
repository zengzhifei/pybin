# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Release

```sh
./setup.sh              # Full install (Python + venv + deps + deploy to ~/.pybin/)
./setup.sh --env-only   # Only prepare Python and venv, skip deploying pybin
./setup.sh --force      # Wipe .python/ and .venv/, rebuild from scratch

make push               # git add -A + commit + push origin main
make release            # Bump patch version in __about__.py, tag, push, trigger CI
make release BUMP=false # Tag and push without bumping version
```

The project has **no test suite** and **no linter setup**.

## Architecture

pybin is an ops/devops CLI toolkit. There are 4 source files in `pybin/`:

| File | Role |
|------|------|
| `__about__.py` | Package metadata (version, author) |
| `ann.py` | `@runtime` decorator and enums (`RuntimeEnv`, `RuntimeMode`, `RuntimeKey`) |
| `sdk.py` | All shared utilities: file I/O, process management, SSH, crypto, HTTP server, `Sql2EsConverter`, concurrency helpers, `HttpServer` class |
| `cli.py` | All 50+ CLI command functions. Each is decorated with `@runtime(env=...)`. Entry point is `pybin()`; all others are dispatched by name via `sdk.run_main()` |

### Two execution modes (the `@runtime` annotation)

Every CLI function is tagged with one of two environments:

- **`RuntimeEnv.PYTHON`** — Runs directly in Python. `install.py` creates a symlink `~/.pybin/<funcname>` → `cli.py`, and `sdk.run_main()` looks up `sys.argv[0]` to dispatch.

- **`RuntimeEnv.SHELL`** (`shell_exit_code=250`) — The function prints a shell command to stdout and calls `sys.exit(250)`. `install.py` generates a shell wrapper function in `~/.pybin/cli.sh` that captures the output and `eval`s it when the exit code is 250. This is how commands like `scd`, `gomysql`, and `goserver` inject shell commands (e.g., `cd`) into the user's shell session.

The entry point `pybin()` (the `pybin` command itself) has no decorator and always runs in Python.

### Installation flow

1. `install.py` copies `{cli,sdk,ann,__about__}.py` + `config.json` to `~/.pybin/`
2. For `PYTHON`-mode functions: creates symlinks (`<funcname>` → `cli.py`)
3. For `SHELL`-mode functions: generates shell wrapper in `cli.sh`
4. Writes `pybin_profile` that adds `~/.pybin` to `PATH`, sets env vars (`PYBIN_CLIS`, `PYBIN_RUNTIME_PATH`), and sources `cli.sh`
5. Appends a source line to the user's shell profile (.zshrc/.bashrc) to load `pybin_profile`

### Config system

`sdk.get_config(key)` uses `inspect.stack()` to get the **caller's function name** and looks up that name in `config.json`. So each command's config section is its function name. Users can create `~/.pybin_config.json` which gets merged in via `sdk.merge_two_levels_dict()`.

The `__extend_clis` key in config allows loading additional CLI modules from arbitrary paths.

### Key SDK utilities

- `sdk.run_main()` — The dispatcher: reads `sys.argv[0]` as the function name, logs to `~/.pybin_history`, and calls the matching function from the CLI module
- `sdk.concurrent_execute()` — Thread-pool-based parallel execution with a callback+lock pattern
- `sdk.iterate_process()` — Iterates over running processes matching a condition, used by `goserver`/`javaserver`/`pkiller`
- `sdk.HttpServer` — Lightweight HTTP server wrapper around stdlib, supports threading, custom request handlers, and daemon mode
- `sdk.TransactionalReplacer` — Context manager that backs up files, applies text replacements, and restores on exit (used by `file_deploy` for pre-processing)
- `sdk.Sql2EsConverter` — Converts a subset of SQL SELECT statements to Elasticsearch DSL using `sqlglot`
