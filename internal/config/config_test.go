package config_test

import (
	"os"
	"path/filepath"
	"strings"
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
	if c.AIAnalyst.MaxRequestsPerMinute != 10 || c.AIAnalyst.TimeoutSeconds != 300 ||
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

// SaveAIAnalyst must persist only the ai_analyst section, keeping every
// other section and operator comment in the file verbatim.
func TestSaveAIAnalystPreservesOtherSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	hand := `# operator notes stay
server:
  port: 9443   # custom

database:
  path: ./x.db
  # keep this comment

ai_analyst:
  enabled: false
  model: "old-model"
`
	if err := os.WriteFile(path, []byte(hand), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.AIAnalyst.Enabled = true
	cfg.AIAnalyst.Provider = "openai-compatible"
	cfg.AIAnalyst.Endpoint = "http://10.0.0.1:8000"
	cfg.AIAnalyst.Model = "new-model"
	cfg.AIAnalyst.TimeoutSeconds = 300
	if err := cfg.SaveAIAnalyst(path); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, keep := range []string{"# operator notes stay", "port: 9443   # custom", "path: ./x.db", "# keep this comment"} {
		if !strings.Contains(s, keep) {
			t.Errorf("lost content %q after SaveAIAnalyst:\n%s", keep, s)
		}
	}
	for _, gone := range []string{"old-model", "enabled: false"} {
		if strings.Contains(s, gone) {
			t.Errorf("stale ai_analyst value %q still present:\n%s", gone, s)
		}
	}
	back, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if back.Server.Port != 9443 {
		t.Errorf("other section changed: %+v", back.Server)
	}
	if back.AIAnalyst.Model != "new-model" || back.AIAnalyst.Endpoint != "http://10.0.0.1:8000" || !back.AIAnalyst.Enabled {
		t.Errorf("ai_analyst not updated: %+v", back.AIAnalyst)
	}
}

func TestSaveAIAnalystAppendsMissingSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  port: 9443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.AIAnalyst.Enabled = true
	cfg.AIAnalyst.Model = "m"
	if err := cfg.SaveAIAnalyst(path); err != nil {
		t.Fatal(err)
	}
	back, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Server.Port != 9443 || back.AIAnalyst.Model != "m" || !back.AIAnalyst.Enabled {
		t.Errorf("round trip: server=%+v ai=%+v", back.Server, back.AIAnalyst)
	}
}

func TestSaveAIAnalystCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.yaml")
	cfg := config.DefaultConfig()
	cfg.AIAnalyst.Model = "m"
	if err := cfg.SaveAIAnalyst(path); err != nil {
		t.Fatal(err)
	}
	back, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.AIAnalyst.Model != "m" || back.Server.Port != 8080 {
		t.Errorf("full-config write: server=%+v ai=%+v", back.Server, back.AIAnalyst)
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
