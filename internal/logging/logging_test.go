package logging_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quetzalog/internal/config"
	"quetzalog/internal/logging"
)

func TestParseLevel(t *testing.T) {
	for name, want := range map[string]slog.Level{
		"": slog.LevelInfo, "events": slog.LevelInfo, "info": slog.LevelInfo,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn,
		"error": slog.LevelError, "debug": slog.LevelDebug, "verbose": slog.LevelDebug,
		"DEBUG": slog.LevelDebug,
	} {
		got, err := logging.ParseLevel(name)
		if err != nil {
			t.Errorf("ParseLevel(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", name, got, want)
		}
	}
	if _, err := logging.ParseLevel("loud"); err == nil {
		t.Error("ParseLevel(\"loud\") should fail")
	}
}

func TestSetLevelAppliesAndPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  port: 9099\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	var lv slog.LevelVar
	c := logging.NewController(&lv, &cfg, path)
	defer c.SetLevel("info")

	if got := c.Level(); got != "info" {
		t.Fatalf("initial level = %q, want info", got)
	}

	got, err := c.SetLevel("debug")
	if err != nil {
		t.Fatalf("set debug: %v", err)
	}
	if got != "debug" || lv.Level() != slog.LevelDebug {
		t.Fatalf("after set debug: got=%q live=%v", got, lv.Level())
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "level: debug") {
		t.Errorf("level not persisted:\n%s", data)
	}
	if !strings.Contains(string(data), "port: 9099") {
		t.Errorf("unrelated section dropped:\n%s", data)
	}

	// "events" is the UI name for info; the file stores the canonical form.
	if got, err := c.SetLevel("events"); err != nil || got != "info" {
		t.Fatalf("set events: got=%q err=%v", got, err)
	}
	if data, _ = os.ReadFile(path); !strings.Contains(string(data), "level: info") {
		t.Errorf("canonical level not persisted:\n%s", data)
	}
}

func TestSetLevelRejectsUnknown(t *testing.T) {
	var lv slog.LevelVar
	lv.Set(slog.LevelWarn)
	c := logging.NewController(&lv, nil, "")

	if _, err := c.SetLevel("nope"); err == nil {
		t.Fatal("unknown level accepted")
	}
	if lv.Level() != slog.LevelWarn {
		t.Fatalf("live level changed on rejected set: %v", lv.Level())
	}
}

// A config path that cannot be written must not undo the applied level; the
// caller gets the warning in the returned error.
func TestSetLevelReportsUnpersisted(t *testing.T) {
	var lv slog.LevelVar
	cfg := config.DefaultConfig()
	c := logging.NewController(&lv, &cfg, t.TempDir()) // directory as config path
	if _, err := c.SetLevel("debug"); err == nil {
		t.Fatal("expected persistence warning")
	}
	if lv.Level() != slog.LevelDebug {
		t.Fatal("level not applied when persistence failed")
	}
}
