package otlp_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quetzalog/internal/config"
	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/internal/ingestion"
	"quetzalog/internal/ingestion/otlp"
)

func testConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.OTel.HttpPort = 0 // ephemeral: the test must not fight the developer's ports
	cfg.OTel.GrpcPort = 0
	return &cfg
}

func TestManagerToggle(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(db); err != nil {
		db.Close()
		t.Fatalf("migrate (requires FTS5 CGO env): %v", err)
	}
	defer db.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	pipeline := ingestion.NewPipeline(events.NewStore(db), 1, 10, logger)
	if err := pipeline.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer pipeline.Stop(context.Background())

	cfg := testConfig()
	mgr := otlp.NewManager(cfg, "", pipeline, logger)

	st := mgr.Status()
	if st.Enabled || st.Running {
		t.Fatalf("fresh manager should be off: %+v", st)
	}

	st, err = mgr.SetEnabled(true)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !st.Running || !st.Enabled {
		t.Fatalf("after enable: %+v", st)
	}

	// Idempotent re-enable must not error or double-bind.
	if st, err = mgr.SetEnabled(true); err != nil || !st.Running {
		t.Fatalf("re-enable: running=%v err=%v", st.Running, err)
	}

	st, err = mgr.SetEnabled(false)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if st.Running || st.Enabled {
		t.Fatalf("after disable: %+v", st)
	}
	// Toggling back on re-binds cleanly (ports were released).
	if _, err := mgr.SetEnabled(true); err != nil {
		t.Fatalf("re-enable after disable: %v", err)
	}
	mgr.Stop()
	mgr.Stop() // idempotent
}

func TestManagerPersistsToConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  port: 9099\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(db); err != nil {
		db.Close()
		t.Fatalf("migrate (requires FTS5 CGO env): %v", err)
	}
	defer db.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	pipeline := ingestion.NewPipeline(events.NewStore(db), 1, 10, logger)
	if err := pipeline.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer pipeline.Stop(context.Background())

	cfg := testConfig()
	mgr := otlp.NewManager(cfg, path, pipeline, logger)
	defer mgr.Stop()

	if _, err := mgr.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "enabled: true") {
		t.Errorf("config file did not record the enabled flag:\n%s", data)
	}
	if !strings.Contains(string(data), "port: 9099") {
		t.Errorf("config save dropped the unrelated server section:\n%s", data)
	}
	if _, err := mgr.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	if data, _ = os.ReadFile(path); strings.Contains(string(data), "enabled: true") {
		t.Errorf("disable not persisted:\n%s", data)
	}
}
