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
	GhidraExe   string
	ProjectRoot string
	ProjectName string
	ScriptPath  string
	PostScript  string
	OutRoot     string
	ListFile    string
	DBPath      string
	Workers     int
	MaxRetries  int
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
		GhidraExe:   `C:\work\ghidrainstall\ghidra_11.4.2_PUBLIC\support\analyzeHeadless.bat`,
		ProjectRoot: `C:\GhidraProjectsUser`,
		ProjectName: `Sys32Proj`,
		ScriptPath:  `C:\ghidra\scripts`,
		PostScript:  `export_full_json.py`,
		OutRoot:     `C:\ghidra_exports`,
		ListFile:    `C:\binlist.txt`,
		DBPath:      `orchestrator_state.sqlite`,
		Workers:     4,
		MaxRetries:  3,
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

	// Corrigir bins que ficaram em 'running' de runs anteriores → 'pending'
	if err := resetRunningToPending(db); err != nil {
		log.Fatalf("ERRO resetRunningToPending: %v", err)
	}
	if err := resetRetryableErrors(db, cfg.MaxRetries); err != nil {
		log.Fatalf("ERRO resetRetryableErrors: %v", err)
	}

	// Seed inicial / refresh: lê binlist.txt, aplica filtro de extensões, sincroniza com disco (JSON existe ou não)
	if err := seedFromList(db, cfg); err != nil {
		log.Fatalf("ERRO seedFromList: %v", err)
	}

	// workers
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			workerLoop(id, db, cfg)
		}(i)
	}

	wg.Wait()
	log.Println("========== Orchestrator v2 end ==========")
}

// ==== CONFIG / CLI ====

func buildConfigFromArgs() *Config {
	cfg := defaultConfig()
	args := os.Args[1:]

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

// ==== DB SETUP ====

func initDB(path string, workerCount int) (*sql.DB, error) {
	busyTimeoutMs := 5000
	dsn := fmt.Sprintf("%s?_busy_timeout=%d&_journal_mode=WAL", path, busyTimeoutMs)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	// Limit and recycle connections to reduce lock contention noise when many workers compete.
	maxConns := workerCount*2 + 2
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(workerCount)
	db.SetConnMaxLifetime(30 * time.Minute)

	if _, err := db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		log.Printf("WARN: PRAGMA busy_timeout falhou: %v", err)
	}
	// Pragmas básicos para melhor concorrência
	if _, err := db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		log.Printf("WARN: PRAGMA journal_mode=WAL falhou: %v", err)
	}
	if _, err := db.Exec(`PRAGMA synchronous = NORMAL;`); err != nil {
		log.Printf("WARN: PRAGMA synchronous=NORMAL falhou: %v", err)
	}

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

func nowStr() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func resetRunningToPending(db *sql.DB) error {
	_, err := execWithRetry(db, `
UPDATE bins
SET status = 'pending',
    last_result = 'interrupted',
    updated_at = ?
WHERE status = 'running';
`, nowStr())
	if err != nil {
		return err
	}
	return nil
}

// resetRetryableErrors recoloca em pending erros anteriores que ainda não atingiram o limite de tentativas.
func resetRetryableErrors(db *sql.DB, maxRetries int) error {
	_, err := execWithRetry(db, `
UPDATE bins
SET status = 'pending',
    last_result = 'retry_pending',
    updated_at = ?
WHERE status = 'error'
  AND retries < ?;
`, nowStr(), maxRetries)
	if err != nil {
		return err
	}
	return nil
}

// ==== SEED A PARTIR DO BINLIST, COM FILTRO DE EXTENSÕES E REFRESH ====

func seedFromList(db *sql.DB, cfg *Config) error {
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
					if upErr := upsertBinFromPath(db, cfg, path); upErr != nil {
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

func upsertBinFromPath(db *sql.DB, cfg *Config, path string) error {
	ext := strings.ToLower(filepath.Ext(path))
	now := nowStr()

	// se extensão não é suportada → SKIPPED
	if !allowedExt[ext] {
		_, err := execWithRetry(db, `
INSERT INTO bins (path, status, has_json, last_result, last_error, retries, updated_at)
VALUES (?, 'skipped', 0, 'unsupported_ext', NULL, 0, ?)
ON CONFLICT(path) DO UPDATE SET
  status      = 'skipped',
  has_json    = 0,
  last_result = 'unsupported_ext',
  last_error  = NULL,
  updated_at  = excluded.updated_at;
`, path, now)
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
	_, err := execWithRetry(db, `
INSERT INTO bins (path, status, has_json, last_result, last_error, retries, updated_at)
VALUES (?, ?, ?, ?, NULL, 0, ?)
ON CONFLICT(path) DO UPDATE SET
  status      = excluded.status,
  has_json    = excluded.has_json,
  last_result = excluded.last_result,
  updated_at  = excluded.updated_at;
`, path, status, hasJSON, lastResult, now)

	return err
}

// ==== WORKER / SCHEDULER ====

type BinJob struct {
	ID      int64
	Path    string
	Retries int
}

func workerLoop(id int, db *sql.DB, cfg *Config) {
	ctx := context.Background()
	for {
		job, err := claimNextPending(ctx, db, cfg.MaxRetries)
		if err != nil {
			log.Printf("[worker %d] ERRO claimNextPending: %v", id, err)
			time.Sleep(2 * time.Second)
			continue
		}
		if job == nil {
			log.Printf("[worker %d] Sem mais bins pendentes, a terminar.", id)
			return
		}

		log.Printf("[worker %d] START id=%d path=%s (tentativa %d/%d)", id, job.ID, job.Path, job.Retries, cfg.MaxRetries)

		projectName := fmt.Sprintf("%s_w%d", cfg.ProjectName, id)
		cmdCtx := context.Background() // sem timeout; pode ser ajustado no futuro

		err = runGhidraForBin(cmdCtx, cfg, job.Path, id, projectName)
		jsonExists := false

		binName := filepath.Base(job.Path)
		exportPath := filepath.Join(cfg.OutRoot, binName, "export.v5.json")
		if _, statErr := os.Stat(exportPath); statErr == nil {
			jsonExists = true
		}

		shouldRetry := job.Retries < cfg.MaxRetries
		hitLimit := !shouldRetry

		if err != nil {
			log.Printf("[worker %d] ERRO Ghidra id=%d path=%s (tentativa %d/%d): %v", id, job.ID, job.Path, job.Retries, cfg.MaxRetries, err)
			if upErr := updateBinError(db, job.ID, jsonExists, err, shouldRetry, hitLimit); upErr != nil {
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
			log.Printf("[worker %d] ERRO: sem JSON depois de Ghidra para id=%d path=%s (tentativa %d/%d)", id, job.ID, job.Path, job.Retries, cfg.MaxRetries)
			if upErr := updateBinError(db, job.ID, false, fmt.Errorf("json_missing"), shouldRetry, hitLimit); upErr != nil {
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

		if upErr := updateBinSuccess(db, job.ID); upErr != nil {
			log.Printf("[worker %d] ERRO updateBinSuccess: %v", id, upErr)
		} else {
			log.Printf("[worker %d] DONE id=%d path=%s (tentativa %d/%d)", id, job.ID, job.Path, job.Retries, cfg.MaxRetries)
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

func claimNextPending(ctx context.Context, db *sql.DB, maxRetries int) (*BinJob, error) {
	const maxAttempts = 8
	backoff := 200 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		tx, err := db.BeginTx(ctx, &sql.TxOptions{})
		if err != nil {
			if isBusyError(err) {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return nil, err
		}

		row := tx.QueryRow(`
SELECT id, path, retries
FROM bins
WHERE status = 'pending'
  AND retries < ?
ORDER BY id
LIMIT 1;
`, maxRetries)

		var id int64
		var path string
		var retries int
		err = row.Scan(&id, &path, &retries)
		if err == sql.ErrNoRows {
			_ = tx.Rollback()
			return nil, nil
		}
		if err != nil {
			_ = tx.Rollback()
			if isBusyError(err) {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return nil, err
		}

		res, err := tx.Exec(`
UPDATE bins
SET status = 'running',
    retries = retries + 1,
    updated_at = ?
WHERE id = ?
  AND status = 'pending'
  AND retries = ?;
`, nowStr(), id, retries)
		if err != nil {
			_ = tx.Rollback()
			if isBusyError(err) {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return nil, err
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
			return nil, err
		}

		return &BinJob{ID: id, Path: path, Retries: retries + 1}, nil
	}

	return nil, fmt.Errorf("não consegui claim pendente depois de %d tentativas", maxAttempts)
}

func updateBinSuccess(db *sql.DB, id int64) error {
	_, err := execWithRetry(db, `
UPDATE bins
SET status = 'done',
    has_json = 1,
    last_result = 'ok',
    last_error = NULL,
    updated_at = ?
WHERE id = ?;
`, nowStr(), id)
	return err
}

func updateBinError(db *sql.DB, id int64, hasJSON bool, cause error, retryPending bool, hitLimit bool) error {
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

	_, err := execWithRetry(db, `
UPDATE bins
SET status = ?,
    has_json = ?,
    last_result = ?,
    last_error = ?,
    updated_at = ?
WHERE id = ?;
`, status, h, result, msg, nowStr(), id)
	return err
}

// ==== GHIDRA CALL ====

func runGhidraForBin(ctx context.Context, cfg *Config, binPath string, workerID int, projectName string) error {
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

	cmd := exec.CommandContext(ctx, cfg.GhidraExe, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("pipe stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("pipe stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start ghidra: %w", err)
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

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("Ghidra exit code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("Ghidra exit error: %w", err)
	}

	return nil
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

// execWithRetry repete execuções em caso de "database is locked/busy" para maior robustez com SQLite.
func execWithRetry(db *sql.DB, query string, args ...any) (sql.Result, error) {
	const maxAttempts = 8
	backoff := 200 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		res, err := db.Exec(query, args...)
		if err == nil {
			return res, nil
		}
		if !isBusyError(err) {
			return nil, err
		}

		time.Sleep(backoff)
		backoff *= 2
	}

	return nil, fmt.Errorf("exec retry limit exceeded for query: %s", strings.SplitN(strings.TrimSpace(query), "\n", 2)[0])
}
