// Package logging owns the application's live log verbosity. The server
// builds one slog.LevelVar shared by every handler, so the level can be
// flipped at runtime (Settings → Logging or PUT /api/v1/settings/logging)
// without restarting; the choice is persisted to the config file so it
// survives restarts.
package logging

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"quetzalog/internal/config"
)

// Levels are the verbosity names accepted by the settings API, ordered
// quietest to loudest. "info" (shown as "Events" in the UI) is the normal
// operating mode — what the server logs today; "debug" turns on the
// per-request and per-export detail used to watch functionality.
var Levels = []string{"error", "warn", "info", "debug"}

// Controller mutates the live log level and mirrors it into the config.
type Controller struct {
	mu      sync.Mutex
	level   *slog.LevelVar
	cfg     *config.Config
	cfgPath string // config file to persist the level ("" = memory only)
}

func NewController(level *slog.LevelVar, cfg *config.Config, cfgPath string) *Controller {
	return &Controller{level: level, cfg: cfg, cfgPath: cfgPath}
}

// ParseLevel maps a settings name onto a slog level. "events" behaves as
// info but skips the routine per-request chatter (middleware logs those at
// debug); accept "info"/"verbose" too so hand-written configs work.
func ParseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "events", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	case "debug", "verbose":
		return slog.LevelDebug, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (want one of: events, warn, info, debug)", name)
	}
}

// canonicalLevel turns the slog.Level back into the config name so the UI
// and the config file always agree.
func canonicalLevel(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}

// Level returns the current verbosity name.
func (c *Controller) Level() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return canonicalLevel(c.level.Level())
}

// SetLevel validates the name, applies it to the live logger and persists
// it to the config file. A failed write keeps the live change (the operator
// asked for it) but reports the warning.
func (c *Controller) SetLevel(name string) (string, error) {
	lvl, err := ParseLevel(name)
	if err != nil {
		return c.Level(), err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.level.Set(lvl)
	if c.cfg != nil {
		c.cfg.Logging.Level = canonicalLevel(lvl)
	}
	var warn error
	if c.cfgPath != "" && c.cfg != nil {
		if err := c.cfg.SaveLogging(c.cfgPath); err != nil {
			warn = fmt.Errorf("level applied but not persisted: %w", err)
		}
	}
	return canonicalLevel(lvl), warn
}
