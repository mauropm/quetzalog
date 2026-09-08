package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"quetzalog/internal/config"
)

func TestDefaults(t *testing.T) {
	c := config.DefaultConfig()
	if c.Server.Host != "0.0.0.0" || c.Server.Port != 8080 {
		t.Errorf("server defaults: %+v", c.Server)
	}
	if c.Ingestion.Workers <= 0 || c.Ingestion.BatchSize <= 0 {
		t.Errorf("ingestion defaults invalid: %+v", c.Ingestion)
	}
	if c.Database.Path == "" || c.Database.MaxOpenConns <= 0 {
		t.Errorf("db defaults: %+v", c.Database)
	}
	if c.Server.ReadTimeout <= 0 || c.Server.WriteTimeout <= 0 || c.Server.ShutdownTimeout <= 0 {
		t.Errorf("server timeouts unset: %+v", c.Server)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg", "config.yaml")

	orig := config.DefaultConfig()
	orig.Server.Port = 9999
	orig.Database.Path = filepath.Join(dir, "x.db")
	orig.Syslog.UDPPort = 1514
	orig.Syslog.TCPPort = 1515
	orig.Splunk.HECEnabled = true
	orig.Splunk.HECTokens = []config.HECToken{{ID: "a", Token: "tok-a"}}
	orig.Ingestion.Workers = 7
	orig.Server.ReadTimeout = 11 * time.Second

	if err := orig.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saved file missing: %v", err)
	}

	back, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if back.Server.Port != 9999 {
		t.Errorf("port lost in round trip: %d", back.Server.Port)
	}
	if back.Database.Path != orig.Database.Path {
		t.Errorf("db path lost: %q", back.Database.Path)
	}
	if back.Ingestion.Workers != 7 {
		t.Errorf("workers lost: %d", back.Ingestion.Workers)
	}
	if !back.Splunk.HECEnabled || len(back.Splunk.HECTokens) != 1 || back.Splunk.HECTokens[0].Token != "tok-a" {
		t.Errorf("hec tokens lost: %+v", back.Splunk)
	}
	if back.Syslog.UDPPort != 1514 || back.Syslog.TCPPort != 1515 {
		t.Errorf("syslog ports lost: %+v", back.Syslog)
	}
	if back.Server.ReadTimeout != 11*time.Second {
		t.Errorf("read timeout lost: %v", back.Server.ReadTimeout)
	}
}

func TestLoadMissingFileErrors(t *testing.T) {
	if _, err := config.LoadConfig("/nonexistent/path.yaml"); err == nil {
		t.Error("missing config file should error")
	}
}

func TestLoadEmptyPathDefaults(t *testing.T) {
	c, err := config.LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	d := config.DefaultConfig()
	if c.Server.Port != d.Server.Port {
		t.Error("empty path should return defaults")
	}
}

func TestLoadInvalidYaml(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.yaml")
	os.WriteFile(p, []byte("server: [unclosed\n"), 0o644)
	if _, err := config.LoadConfig(p); err == nil {
		t.Error("invalid yaml should error")
	}
}
