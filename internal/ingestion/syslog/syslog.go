package syslog

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"quetzalog/internal/ingestion"
	"quetzalog/internal/parsers"
	"quetzalog/pkg/event"
)

// Config holds configuration for the syslog receiver.
type Config struct {
	UDPEnabled bool
	UDPPort    int
	TCPEnabled bool
	TCPPort    int
}

// Receiver listens for syslog messages on TCP and UDP ports.
type Receiver struct {
	pipeline *ingestion.Pipeline
	config   Config
	logger   *slog.Logger
	ctx      context.Context
	cancel   context.CancelFunc
	running  bool
	tcpConn  net.Listener
	udpConn  *net.UDPConn
}

// NewReceiver creates a new syslog receiver.
func NewReceiver(pipeline *ingestion.Pipeline, config Config, logger *slog.Logger) *Receiver {
	return &Receiver{
		pipeline: pipeline,
		config:   config,
		logger:   logger,
	}
}

// Start begins listening on configured TCP and UDP ports.
func (r *Receiver) Start(ctx context.Context) error {
	r.ctx, r.cancel = context.WithCancel(ctx)

	if r.config.TCPEnabled {
		addr := fmt.Sprintf(":%d", r.config.TCPPort)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("start TCP syslog listener: %w", err)
		}
		r.tcpConn = listener
		r.logger.Info("syslog TCP listener started", "addr", addr)
		go r.handleTCP(r.ctx)
	}

	if r.config.UDPEnabled {
		addr := fmt.Sprintf(":%d", r.config.UDPPort)
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: r.config.UDPPort})
		if err != nil {
			return fmt.Errorf("start UDP syslog listener: %w", err)
		}
		r.udpConn = conn
		r.logger.Info("syslog UDP listener started", "addr", addr)
		go r.handleUDP(r.ctx)
	}

	r.running = true
	return nil
}

// Stop gracefully shuts down the syslog receiver.
func (r *Receiver) Stop(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}

	if r.tcpConn != nil {
		r.tcpConn.Close()
	}
	if r.udpConn != nil {
		r.udpConn.Close()
	}

	r.running = false
	r.logger.Info("syslog receiver stopped")
	return nil
}

// handleTCP accepts incoming TCP connections and processes syslog messages.
func (r *Receiver) handleTCP(ctx context.Context) error {
	for {
		conn, err := r.tcpConn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				r.logger.Error("syslog TCP accept error", "error", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		go func(c net.Conn) {
			defer c.Close()
			r.logger.Debug("syslog TCP connection accepted", "remote", c.RemoteAddr())
			scanner := bufio.NewScanner(c)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					continue
				}
				ev := r.processMessage(line)
				if ev != nil {
					if err := r.pipeline.Ingest(ctx, ev); err != nil {
						r.logger.Warn("syslog ingest failed", "error", err)
					}
				}
			}
			r.logger.Debug("syslog TCP connection closed", "remote", c.RemoteAddr())
		}(conn)
	}
}

// handleUDP reads UDP datagrams and processes syslog messages.
func (r *Receiver) handleUDP(ctx context.Context) error {
	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := r.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				r.logger.Error("syslog UDP read error", "error", err)
				continue
			}
		}

		if n == 0 {
			continue
		}

		msg := string(buf[:n])
		r.logger.Debug("syslog UDP message received", "remote", remoteAddr, "size", n)
		ev := r.processMessage(msg)
		if ev != nil {
			if err := r.pipeline.Ingest(ctx, ev); err != nil {
				r.logger.Warn("syslog ingest failed", "error", err)
			}
		}
	}
}

// processMessage parses a syslog message string and returns an event.Event.
// Format parsing (RFC 3164 / 5424 incl. structured data, CEF-over-syslog)
// lives in the parsers package; the receiver only handles transport.
func (r *Receiver) processMessage(msg string) *event.Event {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return nil
	}

	ev := event.NewEvent()
	ev.SourceType = "syslog"
	ev.ReceivedAt = time.Now()

	parsed, name := parsers.Default.Auto([]byte(msg))
	parsers.Fill(ev, parsed)

	// CEF-over-syslog: a CEF body nested in the syslog message field.
	// Re-parse the body so its structured fields reach the event.
	if strings.HasPrefix(strings.TrimSpace(parsed.Message), "CEF:") {
		if p, ok := parsers.Default.Get("cef"); ok {
			if cef, matched := p.Parse([]byte(parsed.Message)); matched {
				parsers.Fill(ev, cef)
				name = name + "+cef"
			}
		}
	}

	event.Provenance(ev, []byte(msg), "syslog", name, "1", "syslog")
	return ev
}
