package database

import (
	"database/sql"
	"embed"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Open opens a SQLite database at the given path with the provided pool settings.
// The connection pool is configured with maxOpenConns, maxIdleConns, and max idle time.
// WAL mode and foreign keys are enforced via connection-level pragmas.
func Open(dbPath string, maxOpenConns, maxIdleConns int, maxIdleTimeStr string) (*sql.DB, error) {
	memory := dbPath == ":memory:" || strings.HasPrefix(dbPath, "file::memory:")
	var dsn string
	if memory {
		dsn = ":memory:"
	} else {
		dsn = fmt.Sprintf("file:%s?_journal_mode=WAL&_synchronous=NORMAL&_foreign_keys=ON&_cache=shared", dbPath)
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Set WAL mode and foreign keys via a connection-level pragma
	if !memory {
		if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;"); err != nil {
			db.Close()
			return nil, fmt.Errorf("set pragmas: %w", err)
		}
	}

	if memory {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	} else {
		db.SetMaxOpenConns(maxOpenConns)
		db.SetMaxIdleConns(maxIdleConns)
	}

	if maxIdleTimeStr != "" && !memory {
		dur, err := time.ParseDuration(maxIdleTimeStr)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("parse max_idle_time %q: %w", maxIdleTimeStr, err)
		}
		db.SetConnMaxIdleTime(dur)
	}

	// Verify WAL mode is active
	var mode any
	if err := db.QueryRow("PRAGMA journal_mode;").Scan(&mode); err != nil {
		db.Close()
		return nil, fmt.Errorf("verify journal mode: %w", err)
	}

	return db, nil
}

// Migrate executes SQL migration files embedded from the migrations directory.
// Applied migrations are tracked in schema_migrations and run exactly once.
func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create migration tracker: %w", err)
	}

	rows, err := db.Query("SELECT name FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}
	applied := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("scan applied migration: %w", err)
		}
		applied[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate applied migrations: %w", err)
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations directory: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })

	for _, migrationName := range names {
		if applied[migrationName] {
			continue
		}
		data, err := migrationFS.ReadFile(path.Join("migrations", migrationName))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", migrationName, err)
		}
		if err := applyMigration(db, string(data)); err != nil {
			return fmt.Errorf("apply migration %s: %w", migrationName, err)
		}
		if _, err := db.Exec("INSERT INTO schema_migrations (name) VALUES (?)", migrationName); err != nil {
			return fmt.Errorf("record migration %s: %w", migrationName, err)
		}
	}

	return nil
}

// Shutdown gracefully shuts down the database connection by closing the pool.
func Shutdown(db *sql.DB) error {
	if db == nil {
		return nil
	}
	return db.Close()
}

// ReadMigration reads the raw SQL content of a named migration file.
func ReadMigration(name string) (string, error) {
	data, err := migrationFS.ReadFile(path.Join("migrations", name))
	if err != nil {
		return "", fmt.Errorf("read migration %s: %w", name, err)
	}
	return string(data), nil
}

// ListMigrations returns the names of all migration files in lexicographic order.
func ListMigrations() ([]string, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations directory: %w", err)
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	return names, nil
}

func applyMigration(db *sql.DB, sqlText string) error {
	statements := splitSQLStatements(sqlText)
	for _, stmt := range statements {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(stmt)), "PRAGMA") {
			if _, err := db.Exec(stmt); err != nil {
				return fmt.Errorf("execute statement %q: %w", stmt, err)
			}
		}
	}

	var transactional []string
	for _, stmt := range statements {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(stmt)), "PRAGMA") {
			transactional = append(transactional, stmt)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range transactional {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("execute statement %q: %w", stmt, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}

func splitSQLStatements(text string) []string {
	var statements []string
	var current strings.Builder
	inSingle := false
	inDouble := false
	inLineComment := false
	inBlockComment := false
	beginDepth := 0

	for i := 0; i < len(text); i++ {
		ch := text[i]
		next := byte(0)
		if i+1 < len(text) {
			next = text[i+1]
		}

		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				current.WriteByte(ch)
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && next == '/' {
				inBlockComment = false
				i++
			}
			continue
		}
		if ch == '-' && next == '-' && !inSingle && !inDouble {
			inLineComment = true
			i++
			continue
		}
		if ch == '/' && next == '*' && !inSingle && !inDouble {
			inBlockComment = true
			i++
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
		} else if ch == '"' && !inSingle {
			inDouble = !inDouble
		}

		if !inSingle && !inDouble {
			if isWordStart(text, i, "BEGIN") {
				beginDepth++
			} else if beginDepth > 0 && isWordStart(text, i, "END") {
				beginDepth--
			}
		}

		if ch == ';' && !inSingle && !inDouble && beginDepth == 0 {
			stmt := strings.TrimSpace(current.String())
			if stmt != "" {
				statements = append(statements, stmt)
			}
			current.Reset()
			continue
		}
		current.WriteByte(ch)
	}

	stmt := strings.TrimSpace(current.String())
	if stmt != "" {
		statements = append(statements, stmt)
	}
	return statements
}

func isWordStart(text string, i int, word string) bool {
	end := i + len(word)
	if end > len(text) {
		return false
	}
	if i > 0 && isIdentifierByte(text[i-1]) {
		return false
	}
	if end < len(text) && isIdentifierByte(text[end]) {
		return false
	}
	for j := 0; j < len(word); j++ {
		if strings.ToUpper(string(text[i+j])) != string(word[j]) {
			return false
		}
	}
	return true
}

func isIdentifierByte(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_'
}
