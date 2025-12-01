# system32-orchestrator

A small orchestration toolset for running Ghidra headless over large sets of Windows System32 binaries. The Go orchestrator feeds Ghidra jobs from a SQLite database, while the bundled Python and Rust utilities handle JSON exports that downstream pipelines already consume.

## Components
- **Go orchestrator (`orchestrator.go`)**: manages job state in SQLite, spawns worker goroutines, calls Ghidra headless, and records success/failure. Compatible with existing `orchestrator_state.sqlite` files.
- **Ghidra export script (`export_full_json.py`)**: runs inside Ghidra to write `export.v5.json` per binary (schema unchanged).
- **Rust builder (`src/main.rs`)**: post-processes NDJSON exports into `export_full.json`, with pause/stop flags for long builds.

## Configuration
All arguments are positional to keep backward compatibility. Defaults are in `defaultConfig()`.

```
<ghidra_exe> <project_root> <project_name> <script_path> <out_root> <binlist.txt> <db_path> <workers> <max_retries>
```

- `ghidra_exe`: Path to `analyzeHeadless.bat`.
- `project_root`: Folder for Ghidra projects (created if missing).
- `project_name`: Base name; each worker appends `_w<id>`.
- `script_path`: Location of `export_full_json.py` for Ghidra.
- `out_root`: Output root where `export.v5.json` is written per binary.
- `binlist.txt`: Text file with one binary path per line (supports trailing comments after `#`).
- `db_path`: SQLite state file (existing files remain compatible; no migrations needed).
- `workers`: Number of concurrent workers.
- `max_retries`: Maximum attempts per binary (defaults to 3 if omitted).

Example (Windows paths):
```
orchestrator.exe "C:\\ghidra\\support\\analyzeHeadless.bat" "C:\\GhidraProjectsUser" Sys32Proj "C:\\ghidra\\scripts" "C:\\ghidra_exports" "C:\\binlist.txt" "C:\\orchestrator_state.sqlite" 6 3
```

### Paths and directories
- `ProjectRoot` and `OutRoot` are created if absent.
- Each binary export lives under `<OutRoot>/<binary_name>/export.v5.json`.

## Database lifecycle and resume behavior
- Schema is unchanged: `bins(id, path UNIQUE, status, has_json, last_result, last_error, retries, updated_at)`.
- On start, any `running` rows are marked `pending` with `last_result='interrupted'`.
- Existing `error` rows with `retries < max_retries` are automatically reset to `pending` for retry.
- Jobs are claimed atomically, marked `running`, and increment `retries` on each attempt.
- Successful runs set `status='done'` and `has_json=1`.
- Failures store `last_error`, and if the retry limit is reached the job remains `status='error'` with `last_result='retry_limit'`.
- Pending selection skips jobs whose `retries` have reached the limit to avoid thrashing.

## Running the orchestrator
1. Prepare `binlist.txt` with full binary paths (comments allowed after `#`).
2. Ensure Ghidra headless and `export_full_json.py` paths are correct.
3. Run the orchestrator with the arguments above.
4. Logs go to `orchestrator_log.txt` (and stdout) and include worker IDs, commands executed, start/finish status, and errors.

The orchestrator is designed to be restarted safely; completed jobs are not reprocessed, interrupted ones are reset to `pending`, and retryable errors resume until the limit is reached.

## Building
- **Go**: `go build -o orchestrator.exe orchestrator.go`
- **Rust** (optional utility): `cargo build --release`

## Ghidra export script
`export_full_json.py` keeps the existing JSON schema intact. It accepts the output root and optional flags (include decompiled code, asm, strings, xrefs, CFG) but all defaults preserve the current output. The orchestrator always invokes it with the output root only.

## Logs and troubleshooting
- Look at `orchestrator_log.txt` for worker-level events.
- `status` and `last_error` in SQLite explain failures; `retry_limit` indicates the attempt cap was hit.
- Temporary SQLite lock contention is handled internally with busy timeouts and backoff retries; occasional warnings may appear but should not interrupt processing.
