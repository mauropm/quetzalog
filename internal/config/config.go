package config

import (
	"fmt"
	"os"
	"path/filepath"
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
	}
}

// LoadConfig reads and parses a YAML config file from path.
// If path is empty, returns DefaultConfig without error.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create config directory %q: %w", dir, err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write config file %q: %w", path, err)
	}

	return nil
}
