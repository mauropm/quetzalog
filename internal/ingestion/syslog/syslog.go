package syslog

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/ingestion"
	"quetzalog/pkg/event"
)

// RFC3164 and RFC5424 syslog parsers.
var rfc3164Regex = regexp.MustCompile(
	`^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)`,
)

var rfc5424Regex = regexp.MustCompile(
	`^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+?)\s*(?:\[(\d+)\])?\s*(?:<(\d+)>)?\s*(.*)`,
)

// Config holds configuration for the syslog receiver.
type Config struct {
	UDPEnabled  bool
	UDPPort     int
	TCPEnabled  bool
	TCPPort     int
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
func (r *Receiver) processMessage(msg string) *event.Event {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return nil
	}

	ev := event.NewEvent()
	ev.SourceType = "syslog"
	ev.ReceivedAt = time.Now()

	// Try RFC5424 first
	if m := rfc5424Regex.FindStringSubmatch(msg); m != nil {
		r.fillFromSyslog(ev, m, 2)
		return ev
	}

	// Fall back to RFC3164
	if m := rfc3164Regex.FindStringSubmatch(msg); m != nil {
		r.fillFromSyslog(ev, m, 1)
		return ev
	}

	// Unparseable syslog: use raw message
	ev.Message = msg
	return ev
}

// fillFromSyslog populates an event from parsed syslog capture groups.
func (r *Receiver) fillFromSyslog(ev *event.Event, m []string, version int) {
	// Priority (facility * 8 + severity)
	priority, err := strconv.Atoi(m[1])
	if err == nil {
		facility := priority / 8
		severity := priority % 8
		ev.Attributes["priority"] = priority
		ev.Attributes["facility"] = facilityName(facility)
		ev.Severity = severityName(severity)
	}

	// Timestamp
	if version == 2 {
		// RFC5424 timestamp
		ev.Timestamp = event.ParseTimestamp(m[3])
	} else {
		// RFC3164 timestamp (no year)
		t := event.ParseTimestamp(m[2])
		if !t.IsZero() && t.Year() == time.Now().Year() {
			ev.Timestamp = t
		} else if !t.IsZero() {
			ev.Timestamp = t.Add(time.Date(time.Now().Year(), 1, 1, 0, 0, 0, 0, t.Location()).Sub(time.Date(1, 1, 1, 0, 0, 0, 0, t.Location())))
		}
	}

	// Hostname
	if hostname := m[4]; hostname != "" && hostname != "-" {
		ev.Host = hostname
	}

	// App name / source
	if appName := m[5]; appName != "" && appName != "-" {
		ev.Source = appName
	}

	// PID
	if pid := m[6]; pid != "" {
		ev.ProcessID = pid
		if ev.Attributes == nil {
			ev.Attributes = make(map[string]any)
		}
		ev.Attributes["pid"] = pid
	}

	// Message
	msg := m[len(m)-1]
	if msg != "" && msg != "-" {
		ev.Message = msg
	}

	// RFC5424 structured data (m[8] is SDID, m[9] is message)
	if version == 2 {
		if sdid := m[8]; sdid != "" {
			if ev.Attributes == nil {
				ev.Attributes = make(map[string]any)
			}
			ev.Attributes["sdid"] = sdid
		}
	}
}

// facilityName returns the textual name of a syslog facility code.
func facilityName(code int) string {
	facilities := []string{
		"kernel", "user-level", "mail", "daemon",
		"auth", "syslog", "line printer", "news",
		"uucp", "cron", "authpriv", "ftp",
		"ntp", "audit", "alert", "clock",
		"local0", "local1", "local2", "local3",
		"local4", "local5", "local6", "local7",
	}
	if code < 0 || code > 23 {
		return fmt.Sprintf("unknown(%d)", code)
	}
	return facilities[code]
}

// severityName returns the textual name of a syslog severity level.
func severityName(code int) string {
	severities := []string{
		"emergency", "alert", "critical", "error",
		"warning", "notice", "informational", "debug",
	}
	if code < 0 || code > 7 {
		return fmt.Sprintf("unknown(%d)", code)
	}
	return severities[code]
}
