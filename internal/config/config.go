package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration.
type Config struct {
	Server        `yaml:"server"`
	Database      `yaml:"database"`
	Ingestion     `yaml:"ingestion"`
	HTTP          `yaml:"http"`
	OTel          `yaml:"otel"`
	Syslog        `yaml:"syslog"`
	Splunk        `yaml:"splunk"`
	Logging       `yaml:"logging"`
	FileIngestion `yaml:"file_ingestion"`
	Auth          `yaml:"auth"`
	Detections    `yaml:"detections"`
	AIAnalyst     `yaml:"ai_analyst"`
}

// AIAnalyst configures the AI-assisted investigation capability. The analyst
// analyzes findings through an external model endpoint and only ever records
// recommendations — consequential actions require explicit human approval.
type AIAnalyst struct {
	// Enabled turns on automatic analysis of new findings.
	Enabled bool `yaml:"enabled"`
	// Provider is one of "openai-compatible", "ollama" or "opencode".
	// Ollama is served through its OpenAI-compatible API (/v1).
	Provider string `yaml:"provider"`
	// Endpoint is the model server base URL. OpenAI-compatible examples:
	// "http://localhost:11434/v1", "http://192.168.1.50:11434/v1",
	// "https://my-model.example.com/v1". For OpenCode this is the
	// `opencode serve` base URL (no /v1), e.g. "http://127.0.0.1:4096".
	Endpoint string `yaml:"endpoint"`
	// APIKey is the optional bearer key (OpenAI-compatible) or the
	// OPENCODE_SERVER_PASSWORD (OpenCode). Supports ${ENV_VAR} expansion.
	APIKey string `yaml:"api_key"`
	// Username is only used by the OpenCode provider (HTTP basic auth;
	// defaults to "opencode").
	Username string `yaml:"username"`
	// Model is an arbitrary model identifier passed to the provider.
	// OpenCode models use the "provider/model" form, e.g. "opencode/...".
	Model string `yaml:"model"`
	// MinimumSeverity gates automatic analysis (critical/high/medium/low).
	// Manual analysis requests are not gated. Defaults to "medium".
	MinimumSeverity string `yaml:"minimum_severity"`
	// MaxRequestsPerMinute caps model requests (0 = default 10).
	MaxRequestsPerMinute int `yaml:"max_requests_per_minute"`
	// TimeoutSeconds bounds a single model request (0 = default 300).
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// MaxContextEvents caps the surrounding events included in the
	// analysis context (0 = default 100).
	MaxContextEvents int `yaml:"max_context_events"`
	// RetryCount is the number of retries after a transient provider
	// failure (timeout / unavailable / rate limited).
	RetryCount int `yaml:"retry_count"`
}

// Detections configures scheduled evaluation of detection rules. When
// scheduled is true, enabled rules run every Interval and materialize findings.
type Detections struct {
	Scheduled bool          `yaml:"scheduled"`
	Interval  time.Duration `yaml:"interval"`
}

// Server configures the HTTP server.
type Server struct {
	Host            string        `yaml:"host"`
	Port            int           `yaml:"port"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// Database configures the SQLite database.
type Database struct {
	Path         string `yaml:"path"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
	MaxIdleTime  string `yaml:"max_idle_time"`
}

// Ingestion configures the message ingestion pipeline.
type Ingestion struct {
	Workers    int   `yaml:"workers"`
	BatchSize  int   `yaml:"batch_size"`
	MaxMsgSize int64 `yaml:"max_message_size"`
}

// HTTP configures the HTTP API.
type HTTP struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
}

// OTel configures OpenTelemetry instrumentation.
type OTel struct {
	Enabled  bool `yaml:"enabled"`
	GrpcPort int  `yaml:"grpc_port"`
	HttpPort int  `yaml:"http_port"`
}

// Syslog configures the syslog receivers.
type Syslog struct {
	UDPPort    int  `yaml:"udp_port"`
	TCPPort    int  `yaml:"tcp_port"`
	UDPEnabled bool `yaml:"udp_enabled"`
	TCPEnabled bool `yaml:"tcp_enabled"`
}

// Splunk configures Splunk HEC integration.
type Splunk struct {
	HECEnabled bool       `yaml:"hec_enabled"`
	HECPort    int        `yaml:"hec_port"`
	HECTokens  []HECToken `yaml:"hec_tokens"`
}

// HECToken is a Splunk HEC authentication token.
type HECToken struct {
	ID    string `yaml:"id"`
	Token string `yaml:"token"`
}

// Logging configures application logging.
type Logging struct {
	Level string `yaml:"level"`
}

// FileIngestion configures file-based log ingestion.
type FileIngestion struct {
	Sources []FileSource `yaml:"sources"`
}

// FileSource defines a file to ingest.
type FileSource struct {
	Name   string `yaml:"name"`
	Path   string `yaml:"path"`
	Format string `yaml:"format"`
}

// Auth configures authentication.
type Auth struct {
	Enabled          bool       `yaml:"enabled"`
	LocalAuthEnabled bool       `yaml:"local_auth_enabled"`
	APIToken         string     `yaml:"api_token"`
	HECTokens        []HECToken `yaml:"hec_tokens"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Server: Server{
			Host:            "0.0.0.0",
			Port:            8080,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			ShutdownTimeout: 15 * time.Second,
		},
		Database: Database{
			Path:         "./data/siem.db",
			MaxOpenConns: 25,
			MaxIdleConns: 10,
			MaxIdleTime:  "5m",
		},
		Ingestion: Ingestion{
			Workers:    4,
			BatchSize:  100,
			MaxMsgSize: 10 * 1024 * 1024, // 10 MB
		},
		HTTP: HTTP{
			Enabled: true,
		},
		OTel: OTel{
			Enabled:  false,
			GrpcPort: 4317,
			HttpPort: 4318,
		},
		Syslog: Syslog{
			UDPPort:    514,
			TCPPort:    1514,
			UDPEnabled: true,
			TCPEnabled: true,
		},
		Splunk: Splunk{
			HECEnabled: false,
			HECPort:    8088,
		},
		Logging: Logging{
			Level: "info",
		},
		Auth: Auth{
			Enabled:          true,
			LocalAuthEnabled: true,
		},
		Detections: Detections{
			Scheduled: false,
			Interval:  5 * time.Minute,
		},
		AIAnalyst: AIAnalyst{
			Enabled:              false,
			Provider:             "openai-compatible",
			MinimumSeverity:      "medium",
			MaxRequestsPerMinute: 10,
			TimeoutSeconds:       300,
			MaxContextEvents:     100,
			RetryCount:           1,
		},
	}
}

// LoadConfig reads and parses a YAML config file from path.
// If path is empty, returns DefaultConfig without error.
//
// ${VAR} and $VAR references are expanded from the environment before
// parsing, so secrets can live outside the config file, e.g.
//
//	ai_analyst:
//	  api_key: "${AI_ANALYST_API_KEY}"
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file %q: %w", path, err)
	}

	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file %q: %w", path, err)
	}

	return cfg, nil
}

// Save writes the configuration to the given path as YAML.
func (c Config) Save(path string) error {
	data, err := yaml.Marshal(&c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory %q: %w", dir, err)
	}

	// Config files routinely contain tokens/credentials — owner-only perms.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config file %q: %w", path, err)
	}

	return nil
}

// SaveAIAnalyst persists the ai_analyst section into the config file at
// path while preserving every other section — including operator comments —
// verbatim. If the file exists without an ai_analyst section, the section
// is appended; if the file does not exist at all, the full configuration
// is written.
func (c Config) SaveAIAnalyst(path string) error {
	existing, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c.Save(path)
	}
	if err != nil {
		return fmt.Errorf("read config file %q: %w", path, err)
	}

	section, err := yaml.Marshal(&c.AIAnalyst)
	if err != nil {
		return fmt.Errorf("marshal ai_analyst section: %w", err)
	}
	block := "ai_analyst:\n" + indentLines(string(section), "  ")

	lines := strings.Split(string(existing), "\n")
	topKey := regexp.MustCompile(`^[A-Za-z_][\w-]*:(\s|$)`)
	start, end := -1, len(lines)
	for i, l := range lines {
		if l == "ai_analyst:" || strings.HasPrefix(l, "ai_analyst:") {
			start = i
			continue
		}
		if start != -1 && topKey.MatchString(l) {
			end = i
			break
		}
	}

	var out []string
	if start == -1 {
		// No ai_analyst section yet: append it (keep one blank line apart).
		out = append(lines, "")
		out = append(out, strings.Split(block, "\n")...)
	} else {
		out = append(lines[:start], strings.Split(block, "\n")...)
		out = append(out, lines[end:]...)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory %q: %w", dir, err)
	}
	// Owner-only perms: the file may contain a model API key.
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		return fmt.Errorf("write config file %q: %w", path, err)
	}
	return nil
}

// indentLines prefixes every non-empty line of s with prefix.
func indentLines(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}
