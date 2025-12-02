package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	GhidraExe     string
	ProjectRoot   string
	ProjectName   string
	ScriptPath    string
	PostScript    string
	OutRoot       string
	ListFile      string
	DBPath        string
	Workers       int
	MaxRetries    int
	ValidatePaths bool
	GhidraRetries int
}

// extensões suportadas pelo Ghidra (para este pipeline)
var allowedExt = map[string]bool{
	".exe": true,
	".dll": true,
	".sys": true,
	".ocx": true,
	".cpl": true,
	".efi": true,
	".drv": true,
}

func defaultConfig() *Config {
	return &Config{
		GhidraExe:     `C:\work\ghidrainstall\ghidra_11.4.2_PUBLIC\support\analyzeHeadless.bat`,
		ProjectRoot:   `C:\GhidraProjectsUser`,
		ProjectName:   `Sys32Proj`,
		ScriptPath:    `C:\ghidra\scripts`,
		PostScript:    `export_full_json.py`,
		OutRoot:       `C:\ghidra_exports`,
		ListFile:      `C:\binlist.txt`,
		DBPath:        `orchestrator_state.sqlite`,
		Workers:       4,
		MaxRetries:    3,
		ValidatePaths: false,
		GhidraRetries: 0,
	}
}

func main() {
	cfg := buildConfigFromArgs()

	logFile, err := os.OpenFile("orchestrator_log.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.SetOutput(os.Stdout)
	} else {
		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
		defer logFile.Close()
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("========== Orchestrator v2 start ==========")

	if cfg.ValidatePaths {
		validateListPaths(cfg)
	}

	if err := os.MkdirAll(cfg.ProjectRoot, 0755); err != nil {
		log.Fatalf("ERRO: não consegui criar ProjectRoot %s: %v", cfg.ProjectRoot, err)
	}
	if err := os.MkdirAll(cfg.OutRoot, 0755); err != nil {
		log.Fatalf("ERRO: não consegui criar OutRoot %s: %v", cfg.OutRoot, err)
	}

	db, err := initDB(cfg.DBPath, cfg.Workers)
	if err != nil {
		log.Fatalf("ERRO initDB: %v", err)
	}
	defer db.Close()

	store, err := prepareBinStore(db)
	if err != nil {
		log.Fatalf("ERRO prepareBinStore: %v", err)
	}
	defer store.Close()

	// Corrigir bins que ficaram em 'running' de runs anteriores → 'pending'
	if err := resetRunningToPending(store); err != nil {
		log.Fatalf("ERRO resetRunningToPending: %v", err)
	}
	if err := resetRetryableErrors(store, cfg.MaxRetries); err != nil {
		log.Fatalf("ERRO resetRetryableErrors: %v", err)
	}

	// Seed inicial / refresh: lê binlist.txt, aplica filtro de extensões, sincroniza com disco (JSON existe ou não)
	if err := seedFromList(store, cfg); err != nil {
		log.Fatalf("ERRO seedFromList: %v", err)
	}

	// workers
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			workerLoop(id, store, cfg)
		}(i)
	}

	wg.Wait()
	log.Println("========== Orchestrator v2 end ==========")
}

// ==== CONFIG / CLI ====

func buildConfigFromArgs() *Config {
	cfg := defaultConfig()
	args := os.Args[1:]

	if envVal := os.Getenv("VALIDATE_BIN_PATHS"); envVal != "" {
		cfg.ValidatePaths = parseEnvBool(envVal)
	}
	if envVal := os.Getenv("GHIDRA_RETRIES"); envVal != "" {
		if retries, err := strconv.Atoi(envVal); err == nil && retries >= 0 {
			cfg.GhidraRetries = retries
		}
	}

	if len(args) >= 1 {
		cfg.GhidraExe = args[0]
	}
	if len(args) >= 2 {
		cfg.ProjectRoot = args[1]
	}
	if len(args) >= 3 {
		cfg.ProjectName = args[2]
	}
	if len(args) >= 4 {
		cfg.ScriptPath = args[3]
	}
	if len(args) >= 5 {
		cfg.OutRoot = args[4]
	}
	if len(args) >= 6 {
		cfg.ListFile = args[5]
	}
	if len(args) >= 7 {
		cfg.DBPath = args[6]
	}
	if len(args) >= 8 {
		if w, err := strconv.Atoi(args[7]); err == nil && w > 0 {
			cfg.Workers = w
		}
	}
	if len(args) >= 9 {
		if mr, err := strconv.Atoi(args[8]); err == nil && mr > 0 {
			cfg.MaxRetries = mr
		}
	}

	log.Printf("Config: %#v", *cfg)
	return cfg
}

func parseEnvBool(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

// ==== DB SETUP ====

func initDB(path string, workerCount int) (*sql.DB, error) {
	busyTimeoutMs := 5000
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path, busyTimeoutMs)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	// Limit and recycle connections to reduce lock contention noise when many workers compete.
	maxConns := workerCount*2 + 2
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(workerCount)
	db.SetConnMaxLifetime(30 * time.Minute)

	schema := `
CREATE TABLE IF NOT EXISTS bins (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  path        TEXT NOT NULL UNIQUE,
  status      TEXT NOT NULL,
  has_json    INTEGER NOT NULL DEFAULT 0,
  last_result TEXT,
  last_error  TEXT,
  retries     INTEGER NOT NULL DEFAULT 0,
  updated_at  TEXT NOT NULL
);
`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	return db, nil
}

type BinStore struct {
	db *sql.DB

	stmtResetRunning      *sql.Stmt
	stmtResetRetryable    *sql.Stmt
	stmtUpsertUnsupported *sql.Stmt
	stmtUpsertBin         *sql.Stmt
	stmtSelectPending     *sql.Stmt
	stmtClaimPending      *sql.Stmt
	stmtUpdateSuccess     *sql.Stmt
	stmtUpdateError       *sql.Stmt
}

func prepareBinStore(db *sql.DB) (*BinStore, error) {
	resetRunning := `
UPDATE bins
SET status = 'pending',
    last_result = 'interrupted',
    updated_at = ?
WHERE status = 'running';`

	resetRetryable := `
UPDATE bins
SET status = 'pending',
    last_result = 'retry_pending',
    updated_at = ?
WHERE status = 'error'
  AND retries < ?;`

	upsertUnsupported := `
INSERT INTO bins (path, status, has_json, last_result, last_error, retries, updated_at)
VALUES (?, 'skipped', 0, 'unsupported_ext', NULL, 0, ?)
ON CONFLICT(path) DO UPDATE SET
  status      = 'skipped',
  has_json    = 0,
  last_result = 'unsupported_ext',
  last_error  = NULL,
  updated_at  = excluded.updated_at;`

	upsertBin := `
INSERT INTO bins (path, status, has_json, last_result, last_error, retries, updated_at)
VALUES (?, ?, ?, ?, NULL, 0, ?)
ON CONFLICT(path) DO UPDATE SET
  status      = excluded.status,
  has_json    = excluded.has_json,
  last_result = excluded.last_result,
  updated_at  = excluded.updated_at;`

	selectPending := `
SELECT id, path, retries
FROM bins
WHERE status = 'pending'
  AND retries < ?
ORDER BY id
LIMIT 1;`

	claimPending := `
UPDATE bins
SET status = 'running',
    retries = retries + 1,
    updated_at = ?
WHERE id = ?
  AND status = 'pending'
  AND retries = ?;`

	updateSuccess := `
UPDATE bins
SET status = 'done',
    has_json = 1,
    last_result = 'ok',
    last_error = NULL,
    updated_at = ?
WHERE id = ?;`

	updateError := `
UPDATE bins
SET status = ?,
    has_json = ?,
    last_result = ?,
    last_error = ?,
    updated_at = ?
WHERE id = ?;`

	// Prepare all statements once so workers and helpers reuse the compiled plans.
	store := &BinStore{db: db}
	stmts := []struct {
		ptr   **sql.Stmt
		query string
	}{
		{&store.stmtResetRunning, resetRunning},
		{&store.stmtResetRetryable, resetRetryable},
		{&store.stmtUpsertUnsupported, upsertUnsupported},
		{&store.stmtUpsertBin, upsertBin},
		{&store.stmtSelectPending, selectPending},
		{&store.stmtClaimPending, claimPending},
		{&store.stmtUpdateSuccess, updateSuccess},
		{&store.stmtUpdateError, updateError},
	}

	for _, def := range stmts {
		stmt, err := db.Prepare(def.query)
		if err != nil {
			store.Close()
			return nil, err
		}
		*def.ptr = stmt
	}

	return store, nil
}

func (s *BinStore) Close() {
	stmts := []*sql.Stmt{
		s.stmtResetRunning,
		s.stmtResetRetryable,
		s.stmtUpsertUnsupported,
		s.stmtUpsertBin,
		s.stmtSelectPending,
		s.stmtClaimPending,
		s.stmtUpdateSuccess,
		s.stmtUpdateError,
	}
	for _, stmt := range stmts {
		if stmt != nil {
			_ = stmt.Close()
		}
	}
}

func nowStr() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func resetRunningToPending(store *BinStore) error {
	_, err := execStmtWithRetry(store.stmtResetRunning, nowStr())
	if err != nil {
		return err
	}
	return nil
}

// resetRetryableErrors recoloca em pending erros anteriores que ainda não atingiram o limite de tentativas.
func resetRetryableErrors(store *BinStore, maxRetries int) error {
	_, err := execStmtWithRetry(store.stmtResetRetryable, nowStr(), maxRetries)
	if err != nil {
		return err
	}
	return nil
}

func validateListPaths(cfg *Config) {
	f, err := os.Open(cfg.ListFile)
	if err != nil {
		log.Printf("WARN: validateListPaths open %s: %v", cfg.ListFile, err)
		return
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 {
			parts := strings.SplitN(line, "#", 2)
			path := filepath.Clean(strings.TrimSpace(parts[0]))
			if path != "" {
				if _, statErr := os.Stat(path); statErr != nil {
					if os.IsNotExist(statErr) {
						log.Printf("WARN: bin path missing (validate only): %s", path)
					} else {
						log.Printf("WARN: bin path stat failed (validate only) %s: %v", path, statErr)
					}
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("WARN: validateListPaths read error: %v", err)
			return
		}
	}
}

// ==== SEED A PARTIR DO BINLIST, COM FILTRO DE EXTENSÕES E REFRESH ====

func seedFromList(store *BinStore, cfg *Config) error {
	f, err := os.Open(cfg.ListFile)
	if err != nil {
		return err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	count := 0

	for {
		line, err := r.ReadString('\n')
		// mesmo que não haja '\n' (última linha), ainda processamos o que veio
		if len(line) > 0 {
			line = strings.TrimSpace(line)
			if line != "" {
				parts := strings.SplitN(line, "#", 2)
				path := filepath.Clean(strings.TrimSpace(parts[0]))
				if path != "" {
					if upErr := upsertBinFromPath(store, cfg, path); upErr != nil {
						log.Printf("WARN: upsertBinFromPath(%s): %v", path, upErr)
					} else {
						count++
					}
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			// qualquer outro erro interrompe
			return err
		}
	}

	log.Printf("seedFromList: processadas %d entradas do binlist (sem limite de tamanho de linha).", count)
	return nil
}

func upsertBinFromPath(store *BinStore, cfg *Config, path string) error {
	ext := strings.ToLower(filepath.Ext(path))
	now := nowStr()

	// se extensão não é suportada → SKIPPED
	if !allowedExt[ext] {
		_, err := execStmtWithRetry(store.stmtUpsertUnsupported, path, now)
		return err
	}

	binName := filepath.Base(path)
	exportPath := filepath.Join(cfg.OutRoot, binName, "export.v5.json")
	_, statErr := os.Stat(exportPath)
	jsonExists := statErr == nil

	status := "pending"
	hasJSON := 0
	lastResult := sql.NullString{}

	if jsonExists {
		status = "done"
		hasJSON = 1
		lastResult = sql.NullString{String: "ok", Valid: true}
	}

	// Se já existe row, isto força o estado a bater certo com o disco:
	// - se JSON existe → done
	// - se JSON não existe → pending
	_, err := execStmtWithRetry(store.stmtUpsertBin, path, status, hasJSON, lastResult, now)

	return err
}

// ==== WORKER / SCHEDULER ====

type BinJob struct {
	ID      int64
	Path    string
	Retries int
}

func workerLoop(id int, store *BinStore, cfg *Config) {
	ctx := context.Background()
	for {
		job, ok, err := claimPendingBin(ctx, store, cfg.MaxRetries)
		if err != nil {
			log.Printf("[worker %d] ERRO claimPendingBin: %v", id, err)
			time.Sleep(2 * time.Second)
			continue
		}
		if !ok {
			log.Printf("[worker %d] Sem mais bins pendentes, a terminar.", id)
			return
		}

		jobStart := time.Now()
		startStamp := jobStart.UTC().Format(time.RFC3339Nano)
		log.Printf("[worker %d] JOB START ts=%s id=%d path=%s attempt=%d/%d", id, startStamp, job.ID, job.Path, job.Retries, cfg.MaxRetries)

		projectName := fmt.Sprintf("%s_w%d", cfg.ProjectName, id)
		cmdCtx := context.Background() // sem timeout; pode ser ajustado no futuro

		exitCode, err := runGhidraForBin(cmdCtx, cfg, job.Path, id, projectName)
		jsonExists := false

		binName := filepath.Base(job.Path)
		exportPath := filepath.Join(cfg.OutRoot, binName, "export.v5.json")
		if _, statErr := os.Stat(exportPath); statErr == nil {
			jsonExists = true
		}

		shouldRetry := job.Retries < cfg.MaxRetries
		hitLimit := !shouldRetry
		elapsed := time.Since(jobStart)

		if err != nil {
			log.Printf("[worker %d] JOB END ts=%s id=%d path=%s attempt=%d/%d exit=%d elapsed=%s status=error err=%v", id, time.Now().UTC().Format(time.RFC3339Nano), job.ID, job.Path, job.Retries, cfg.MaxRetries, exitCode, elapsed, err)
			if upErr := updateBinError(ctx, store, job.ID, jsonExists, err, shouldRetry, hitLimit); upErr != nil {
				log.Printf("[worker %d] ERRO updateBinError: %v", id, upErr)
			}
			if hitLimit {
				log.Printf("[worker %d] Limite de tentativas atingido para id=%d path=%s", id, job.ID, job.Path)
			}
			if shouldRetry {
				time.Sleep(2 * time.Second)
			}
			continue
		}

		if !jsonExists {
			log.Printf("[worker %d] JOB END ts=%s id=%d path=%s attempt=%d/%d exit=%d elapsed=%s status=error err=json_missing", id, time.Now().UTC().Format(time.RFC3339Nano), job.ID, job.Path, job.Retries, cfg.MaxRetries, exitCode, elapsed)
			if upErr := updateBinError(ctx, store, job.ID, false, fmt.Errorf("json_missing"), shouldRetry, hitLimit); upErr != nil {
				log.Printf("[worker %d] ERRO updateBinError(json_missing): %v", id, upErr)
			}
			if hitLimit {
				log.Printf("[worker %d] Limite de tentativas atingido para id=%d path=%s", id, job.ID, job.Path)
			}
			if shouldRetry {
				time.Sleep(2 * time.Second)
			}
			continue
		}

		if upErr := updateBinSuccess(ctx, store, job.ID); upErr != nil {
			log.Printf("[worker %d] ERRO updateBinSuccess: %v", id, upErr)
		} else {
			log.Printf("[worker %d] JOB END ts=%s id=%d path=%s attempt=%d/%d exit=%d elapsed=%s status=done", id, time.Now().UTC().Format(time.RFC3339Nano), job.ID, job.Path, job.Retries, cfg.MaxRetries, exitCode, elapsed)
		}
	}
}
func isBusyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "database is busy")
}

func claimPendingBin(ctx context.Context, store *BinStore, maxRetries int) (*BinJob, bool, error) {
	const maxAttempts = 8
	backoff := 200 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		tx, err := store.db.BeginTx(ctx, &sql.TxOptions{})
		if err != nil {
			if isBusyError(err) {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return nil, false, err
		}

		row := tx.StmtContext(ctx, store.stmtSelectPending).QueryRowContext(ctx, maxRetries)

		var id int64
		var path string
		var retries int
		err = row.Scan(&id, &path, &retries)
		if err == sql.ErrNoRows {
			_ = tx.Rollback()
			return nil, false, nil
		}
		if err != nil {
			_ = tx.Rollback()
			if isBusyError(err) {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return nil, false, err
		}

		res, err := tx.StmtContext(ctx, store.stmtClaimPending).ExecContext(ctx, nowStr(), id, retries)
		if err != nil {
			_ = tx.Rollback()
			if isBusyError(err) {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return nil, false, err
		}

		affected, _ := res.RowsAffected()
		if affected == 0 {
			_ = tx.Rollback()
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		if err := tx.Commit(); err != nil {
			if isBusyError(err) {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return nil, false, err
		}

		return &BinJob{ID: id, Path: path, Retries: retries + 1}, true, nil
	}

	return nil, false, fmt.Errorf("não consegui claim pendente depois de %d tentativas", maxAttempts)
}

func updateBinSuccess(ctx context.Context, store *BinStore, id int64) error {
	return runUpdateTx(ctx, store, func(tx *sql.Tx) error {
		_, err := tx.StmtContext(ctx, store.stmtUpdateSuccess).ExecContext(ctx, nowStr(), id)
		return err
	})
}

func updateBinError(ctx context.Context, store *BinStore, id int64, hasJSON bool, cause error, retryPending bool, hitLimit bool) error {
	h := 0
	if hasJSON {
		h = 1
	}
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	status := "error"
	result := "ghidra_error"
	if retryPending {
		status = "pending"
		result = "retry_pending"
	} else if hitLimit {
		result = "retry_limit"
	}

	return runUpdateTx(ctx, store, func(tx *sql.Tx) error {
		_, err := tx.StmtContext(ctx, store.stmtUpdateError).ExecContext(ctx, status, h, result, msg, nowStr(), id)
		return err
	})
}

func runUpdateTx(ctx context.Context, store *BinStore, fn func(tx *sql.Tx) error) error {
	const maxAttempts = 8
	backoff := 200 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		tx, err := store.db.BeginTx(ctx, &sql.TxOptions{})
		if err != nil {
			if isBusyError(err) {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return err
		}

		if err := fn(tx); err != nil {
			_ = tx.Rollback()
			if isBusyError(err) {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return err
		}

		if err := tx.Commit(); err != nil {
			if isBusyError(err) {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return err
		}

		return nil
	}

	return fmt.Errorf("update transaction retry limit exceeded")
}

// ==== GHIDRA CALL ====

func runGhidraForBin(ctx context.Context, cfg *Config, binPath string, workerID int, projectName string) (int, error) {
	binName := filepath.Base(binPath)
	args := []string{
		cfg.ProjectRoot,
		projectName,
		"-import", binPath,
		"-overwrite",
		"-scriptPath", cfg.ScriptPath,
		"-postScript", cfg.PostScript,
		cfg.OutRoot,
	}

	log.Printf("[worker %d] CMD %q args=%q", workerID, cfg.GhidraExe, args)

	maxAttempts := cfg.GhidraRetries + 1
	var lastExit int
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attemptStart := time.Now()
		attemptTs := attemptStart.UTC().Format(time.RFC3339Nano)
		log.Printf("[worker %d] GHIDRA START ts=%s bin=%s attempt=%d/%d", workerID, attemptTs, binName, attempt, maxAttempts)

		exitCode, err := runSingleGhidra(ctx, cfg, workerID, binName, args)

		elapsed := time.Since(attemptStart)
		endTs := time.Now().UTC().Format(time.RFC3339Nano)

		if err == nil {
			log.Printf("[worker %d] GHIDRA END ts=%s bin=%s attempt=%d/%d exit=%d elapsed=%s", workerID, endTs, binName, attempt, maxAttempts, exitCode, elapsed)
			return exitCode, nil
		}

		log.Printf("[worker %d] GHIDRA END ts=%s bin=%s attempt=%d/%d exit=%d elapsed=%s err=%v", workerID, endTs, binName, attempt, maxAttempts, exitCode, elapsed, err)

		lastExit = exitCode
		lastErr = err

		if exitCode <= 0 || attempt == maxAttempts {
			return exitCode, err
		}

		time.Sleep(2 * time.Second)
	}

	return lastExit, lastErr
}

func runSingleGhidra(ctx context.Context, cfg *Config, workerID int, binName string, args []string) (int, error) {
	cmd := exec.CommandContext(ctx, cfg.GhidraExe, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return -1, fmt.Errorf("pipe stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		if stdout != nil {
			_ = stdout.Close()
		}
		return -1, fmt.Errorf("pipe stderr: %w", err)
	}

	cleanup := func() {
		if stdout != nil {
			_ = stdout.Close()
		}
		if stderr != nil {
			_ = stderr.Close()
		}
	}

	if err := cmd.Start(); err != nil {
		cleanup()
		return -1, fmt.Errorf("start ghidra: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go streamCmdOutput(&wg, stdout, func(line string) {
		log.Printf("[worker %d] Ghidra stdout (%s): %s", workerID, binName, line)
	})
	go streamCmdOutput(&wg, stderr, func(line string) {
		log.Printf("[worker %d] Ghidra stderr (%s): %s", workerID, binName, line)
	})

	wg.Wait()

	waitErr := cmd.Wait()
	cleanup()

	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			return exitErr.ExitCode(), fmt.Errorf("Ghidra exit code %d: %w", exitErr.ExitCode(), waitErr)
		}
		return -1, fmt.Errorf("Ghidra exit error: %w", waitErr)
	}

	return 0, nil
}

// streamCmdOutput lê de r sem limite de tamanho de linha e envia cada linha para sink.
func streamCmdOutput(wg *sync.WaitGroup, r io.Reader, sink func(string)) {
	defer wg.Done()

	reader := bufio.NewReader(r)
	for {
		chunk, err := reader.ReadString('\n')
		if len(chunk) > 0 {
			sink(strings.TrimRight(chunk, "\r\n"))
		}
		if err != nil {
			if err != io.EOF {
				sink(fmt.Sprintf("[stream error: %v]", err))
			}
			return
		}
	}
}

// execStmtWithRetry repete execuções em caso de "database is locked/busy" para maior robustez com SQLite.
func execStmtWithRetry(stmt *sql.Stmt, args ...any) (sql.Result, error) {
	const maxAttempts = 8
	backoff := 200 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		res, err := stmt.Exec(args...)
		if err == nil {
			return res, nil
		}
		if !isBusyError(err) {
			return nil, err
		}

		time.Sleep(backoff)
		backoff *= 2
	}

	return nil, fmt.Errorf("exec retry limit exceeded for prepared statement")
}
