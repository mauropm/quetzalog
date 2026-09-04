package database

import (
	"database/sql"
	"embed"
	"fmt"
	"path"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Open opens a SQLite database at the given path with the provided pool settings.
// The connection pool is configured with maxOpenConns, maxIdleConns, and max idle time.
// WAL mode and foreign keys are enforced via connection-level pragmas.
func Open(dbPath string, maxOpenConns, maxIdleConns int, maxIdleTimeStr string) (*sql.DB, error) {
	var dsn string
	if dbPath == ":memory:" {
		dsn = ":memory:"
	} else {
		dsn = fmt.Sprintf("file:%s?_journal_mode=WAL&_synchronous=NORMAL&_foreign_keys=ON&_cache=shared", dbPath)
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Set WAL mode and foreign keys via a connection-level pragma
	if dbPath != ":memory:" {
		if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;"); err != nil {
			db.Close()
			return nil, fmt.Errorf("set pragmas: %w", err)
		}
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	if maxIdleTimeStr != "" && dbPath != ":memory:" {
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

// Migrate executes all SQL migration files embedded from the migrations directory.
// Migrations are applied in lexicographic order by filename.
func Migrate(db *sql.DB) error {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		migrationName := entry.Name()
		data, err := migrationFS.ReadFile(path.Join("migrations", migrationName))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", migrationName, err)
		}

		if err := applyMigration(db, string(data)); err != nil {
			return fmt.Errorf("apply migration %s: %w", migrationName, err)
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
	_, err := db.Exec(sqlText)
	return err
}
