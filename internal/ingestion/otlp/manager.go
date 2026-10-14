package otlp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"quetzalog/internal/config"
	"quetzalog/internal/ingestion"
)

// Manager owns the OTLP receivers (HTTP + gRPC) and lets them be started
// and stopped at runtime — the settings API turns ingestion on and off
// without restarting the server. Receivers bind synchronously on Start so a
// port conflict surfaces to the operator instead of failing in a goroutine.
//
// The enabled/disabled state is config.OTel.Enabled; Start is honored at
// boot and SetEnabled applies the toggle, persists it when a config file is
// in use, and keeps running state in sync with it.
type Manager struct {
	cfg      *config.Config
	cfgPath  string // config file to persist the enabled flag ("" = memory only)
	pipeline *ingestion.Pipeline
	logger   *slog.Logger

	mu      sync.Mutex
	running bool
	detail  string
	httpSrv *http.Server
	grpcSrv *GRPCServer
}

// ManagerStatus is the settings/UI view of the receivers.
type ManagerStatus struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	HTTPPort int    `json:"http_port"`
	GRPCPort int    `json:"grpc_port"`
	Detail   string `json:"detail,omitempty"`
}

func NewManager(cfg *config.Config, cfgPath string, pipeline *ingestion.Pipeline, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{cfg: cfg, cfgPath: cfgPath, pipeline: pipeline, logger: logger}
}

// Enabled reports the persisted switch state.
func (m *Manager) Enabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabledLocked()
}

func (m *Manager) enabledLocked() bool {
	return m.cfg != nil && m.cfg.OTel.Enabled
}

// Status returns the current switch, run and port state.
func (m *Manager) Status() ManagerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := ManagerStatus{Enabled: m.enabledLocked(), Running: m.running, Detail: m.detail}
	if m.cfg != nil {
		st.HTTPPort = m.cfg.OTel.HttpPort
		st.GRPCPort = m.cfg.OTel.GrpcPort
	}
	return st
}

// Start binds both receivers if not already running. A failed HTTP bind is
// returned as the error and nothing stays running; if only gRPC fails the
// HTTP receiver keeps running and the failure is reported in Status.Detail.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil
	}
	ports := config.OTel{}
	if m.cfg != nil {
		ports = m.cfg.OTel
	}

	httpAddr := fmt.Sprintf(":%d", ports.HttpPort)
	ln, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w (is another process using the port?)", httpAddr, err)
	}

	handler := NewHandler(m.pipeline, m.logger)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.Handle(w, r)
		}),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	if m.cfg != nil {
		if m.cfg.Server.ReadTimeout > 0 {
			srv.ReadTimeout = m.cfg.Server.ReadTimeout
		}
		if m.cfg.Server.WriteTimeout > 0 {
			srv.WriteTimeout = m.cfg.Server.WriteTimeout
		}
	}

	m.detail = ""
	m.httpSrv = srv
	go func() {
		m.logger.Info("OTLP server starting", "addr", httpAddr)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			m.logger.Error("OTLP server error", "error", err)
		}
	}()

	g := NewGRPCReceiver(m.pipeline, ports.GrpcPort, m.logger)
	if err := g.Start(context.Background()); err != nil {
		// HTTP is serving; report the degraded half instead of rolling back.
		m.detail = fmt.Sprintf("gRPC receiver failed to start: %v", err)
		m.logger.Warn("OTLP gRPC server failed", "error", err)
	}

	m.grpcSrv = g
	m.running = true
	return nil
}

// Stop closes both receivers. Safe to call when not running.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

// SetEnabled starts or stops ingestion and persists the flag to the config
// file (when one is in use). A failed start leaves both the running state
// and the persisted flag unchanged. The new status is always returned.
func (m *Manager) SetEnabled(enabled bool) (ManagerStatus, error) {
	m.mu.Lock()
	if enabled == m.enabledLocked() && m.running == enabled {
		st := m.statusLocked()
		m.mu.Unlock()
		return st, nil
	}
	if enabled {
		m.mu.Unlock()
		err := m.Start()
		m.mu.Lock()
		if err != nil {
			return m.statusLocked(), fmt.Errorf("OTLP start failed: %w", err)
		}
	} else {
		m.stopLocked()
	}
	if m.cfg != nil {
		m.cfg.OTel.Enabled = enabled
	}
	if m.cfgPath != "" {
		if err := m.cfg.SaveOTel(m.cfgPath); err != nil {
			m.logger.Warn("OTLP setting applied but not persisted", "error", err)
		}
	}
	st := m.statusLocked()
	m.mu.Unlock()
	return st, nil
}

func (m *Manager) statusLocked() ManagerStatus {
	st := ManagerStatus{Enabled: m.enabledLocked(), Running: m.running, Detail: m.detail}
	if m.cfg != nil {
		st.HTTPPort = m.cfg.OTel.HttpPort
		st.GRPCPort = m.cfg.OTel.GrpcPort
	}
	return st
}

// stopLocked shuts the receivers down; callers must hold m.mu.
func (m *Manager) stopLocked() {
	if !m.running {
		return
	}
	if m.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.httpSrv.Shutdown(ctx)
	}
	if m.grpcSrv != nil {
		_ = m.grpcSrv.Stop(context.Background())
	}
	m.httpSrv = nil
	m.grpcSrv = nil
	m.running = false
	m.detail = ""
}
