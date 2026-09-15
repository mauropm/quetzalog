package syslog_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/internal/ingestion"
	"quetzalog/internal/ingestion/syslog"
	"quetzalog/pkg/event"
)

func startReceiver(t *testing.T, udpPort, tcpPort int) (*syslog.Receiver, *events.Store, func()) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		db.Close()
		t.Fatalf("migrate (needs FTS5 CGO flags per Makefile): %v", err)
	}
	store := events.NewStore(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	p := ingestion.NewPipeline(store, 2, 50, logger)
	if err := p.Start(context.Background()); err != nil {
		db.Close()
		t.Fatalf("pipeline start: %v", err)
	}
	r := syslog.NewReceiver(p, syslog.Config{
		UDPEnabled: udpPort > 0, UDPPort: udpPort,
		TCPEnabled: tcpPort > 0, TCPPort: tcpPort,
	}, logger)
	if err := r.Start(context.Background()); err != nil {
		db.Close()
		t.Fatalf("receiver start: %v", err)
	}
	return r, store, func() {
		r.Stop(context.Background())
		p.Stop(context.Background())
		db.Close()
	}
}

func waitForEvents(t *testing.T, store *events.Store, want int, timeout time.Duration) []*event.Event {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, _ := store.Count(context.Background(), events.Query{})
		if n >= want {
			list, err := store.Search(context.Background(), events.Query{Limit: want + 10})
			if err != nil {
				t.Fatalf("search: %v", err)
			}
			return list
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d events", want)
	return nil
}

func TestSyslogUDP_RFC3164(t *testing.T) {
	r, store, cleanup := startReceiver(t, 17514, 0)
	defer cleanup()
	_ = r

	conn, err := net.Dial("udp", "127.0.0.1:17514")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := "<134>Sep  3 18:30:00 server01 sshd: Failed password for admin"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}

	got := waitForEvents(t, store, 1, 5*time.Second)
	ev := got[0]
	if ev.Host != "server01" {
		t.Errorf("host: got %q want server01", ev.Host)
	}
	if ev.Source != "sshd" {
		t.Errorf("source: got %q want sshd", ev.Source)
	}
	if !strings.Contains(ev.Message, "Failed password") {
		t.Errorf("message: got %q", ev.Message)
	}
	// priority 134: facility 16 (local0), severity 2 => notice
	if ev.Severity != "notice" && ev.Severity != "info" {
		t.Errorf("severity mapping: got %q (want notice/info)", ev.Severity)
	}
	if string(ev.Raw) != msg {
		t.Errorf("raw payload not preserved: got %q", string(ev.Raw))
	}
	if ev.RawFormat != "syslog" {
		t.Errorf("raw_format: got %q", ev.RawFormat)
	}
	if ev.Attributes["parser"] != "syslog3164" {
		t.Errorf("parser provenance: got %v", ev.Attributes["parser"])
	}
}

func TestSyslogTCP_RFC5424(t *testing.T) {
	_, store, cleanup := startReceiver(t, 0, 17515)
	defer cleanup()

	conn, err := net.Dial("tcp", "127.0.0.1:17515")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := fmt.Sprintf("<165>1 2026-01-01T00:00:00Z web01 nginx - ID[728] - GET /admin returned 403\n")
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}

	got := waitForEvents(t, store, 1, 5*time.Second)
	ev := got[0]
	if ev.Host != "web01" {
		t.Errorf("RFC5424 host field-shift bug: got %q want web01", ev.Host)
	}
	if ev.Source != "nginx" {
		t.Errorf("RFC5424 source field-shift bug: got %q want nginx", ev.Source)
	}
	if !strings.Contains(ev.Message, "403") {
		t.Errorf("RFC5424 message: got %q", ev.Message)
	}
}

func TestSyslogTCP_MultipleLines(t *testing.T) {
	_, store, cleanup := startReceiver(t, 0, 17516)
	defer cleanup()

	conn, err := net.Dial("tcp", "127.0.0.1:17516")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var b strings.Builder
	for i := 0; i < 5; i++ {
		b.WriteString(fmt.Sprintf("<14>Jan  1 00:00:0%d host%d appd: line %d\n", i, i, i))
	}
	if _, err := conn.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	got := waitForEvents(t, store, 5, 5*time.Second)
	if len(got) != 5 {
		t.Errorf("want 5 events, got %d", len(got))
	}
}

func TestSyslogCEFOverSyslog(t *testing.T) {
	_, store, cleanup := startReceiver(t, 0, 17518)
	defer cleanup()
	conn, _ := net.Dial("tcp", "127.0.0.1:17518")
	defer conn.Close()
	msg := `<134>Oct  5 09:00:00 fw01 fw: CEF:8|Quetzalog|FW|1.0|210|Blocked TCP|7|src=10.1.2.3 dst=8.8.8.8 dpt=22 suser=alice msg=blocked by policy`
	conn.Write([]byte(msg + "\n"))
	got := waitForEvents(t, store, 1, 5*time.Second)
	ev := got[0]
	if ev.Attributes["parser"] != "syslog3164+cef" {
		t.Errorf("cef-over-syslog parser provenance: %v", ev.Attributes["parser"])
	}
	if ev.Message != "Blocked TCP" {
		t.Errorf("cef message: %q", ev.Message)
	}
	if ev.SourceIP != "10.1.2.3" || ev.DestinationIP != "8.8.8.8" || ev.DestinationPort != 22 {
		t.Errorf("cef fields: %q %q %d", ev.SourceIP, ev.DestinationIP, ev.DestinationPort)
	}
	if ev.User != "alice" {
		t.Errorf("cef user: %q", ev.User)
	}
	if ev.Host != "fw01" {
		t.Errorf("syslog envelope host should remain: %q", ev.Host)
	}
}

func TestSyslogGarbageStillIngested(t *testing.T) {
	_, store, cleanup := startReceiver(t, 0, 17517)
	defer cleanup()
	conn, _ := net.Dial("tcp", "127.0.0.1:17517")
	defer conn.Close()
	conn.Write([]byte("this is not syslog at all\n"))
	got := waitForEvents(t, store, 1, 5*time.Second)
	if !strings.Contains(got[0].Message, "not syslog") {
		t.Errorf("garbage fallback failed: %q", got[0].Message)
	}
}
