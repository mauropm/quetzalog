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
	if back.AIAnalyst.Provider != "openai-compatible" || back.AIAnalyst.MinimumSeverity != "medium" {
		t.Errorf("ai_analyst defaults lost in round trip: %+v", back.AIAnalyst)
	}
}

func TestAIAnalystDefaults(t *testing.T) {
	c := config.DefaultConfig()
	if c.AIAnalyst.Enabled {
		t.Error("AI Analyst must default to disabled")
	}
	if c.AIAnalyst.Provider != "openai-compatible" {
		t.Errorf("provider default: %q", c.AIAnalyst.Provider)
	}
	if c.AIAnalyst.MinimumSeverity != "medium" {
		t.Errorf("minimum_severity default: %q", c.AIAnalyst.MinimumSeverity)
	}
	if c.AIAnalyst.MaxRequestsPerMinute != 10 || c.AIAnalyst.TimeoutSeconds != 60 ||
		c.AIAnalyst.MaxContextEvents != 100 || c.AIAnalyst.RetryCount != 1 {
		t.Errorf("cost controls defaults: %+v", c.AIAnalyst)
	}
}

func TestAIAnalystRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	orig := config.DefaultConfig()
	orig.AIAnalyst.Enabled = true
	orig.AIAnalyst.Provider = "ollama"
	orig.AIAnalyst.Endpoint = "http://192.168.1.50:11434/v1"
	orig.AIAnalyst.APIKey = "secret-key"
	orig.AIAnalyst.Model = "qwen3.8"
	orig.AIAnalyst.MinimumSeverity = "high"
	orig.AIAnalyst.MaxRequestsPerMinute = 30
	orig.AIAnalyst.TimeoutSeconds = 120
	orig.AIAnalyst.MaxContextEvents = 50
	orig.AIAnalyst.RetryCount = 2

	if err := orig.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	back, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if back.AIAnalyst != orig.AIAnalyst {
		t.Errorf("ai_analyst lost in round trip:\n got %+v\nwant %+v", back.AIAnalyst, orig.AIAnalyst)
	}
}

func TestLoadConfigExpandsEnvVars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
ai_analyst:
  enabled: true
  endpoint: "http://localhost:11434/v1"
  api_key: "${TEST_AI_ANALYST_KEY}"
  model: "qwen3.8"
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_AI_ANALYST_KEY", "expanded-secret")
	c, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.AIAnalyst.APIKey != "expanded-secret" {
		t.Errorf("env var not expanded: %q", c.AIAnalyst.APIKey)
	}
}

func TestLoadConfigUnsetEnvExpandsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
ai_analyst:
  api_key: "${TEST_UNSET_KEY_THAT_DOES_NOT_EXIST_9x}"
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.AIAnalyst.APIKey != "" {
		t.Errorf("unset env var should expand to empty: %q", c.AIAnalyst.APIKey)
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
