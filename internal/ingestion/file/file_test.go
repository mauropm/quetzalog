package file_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/internal/ingestion"
	ingestfile "quetzalog/internal/ingestion/file"
	"quetzalog/pkg/event"
)

func setupTail(t *testing.T, dir string, sources []ingestfile.Source) (*ingestfile.Ingestor, *events.Store, func()) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		db.Close()
		t.Fatalf("migrate (requires FTS5 CGO env from Makefile): %v", err)
	}
	store := events.NewStore(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	p := ingestion.NewPipeline(store, 2, 50, logger)
	if err := p.Start(context.Background()); err != nil {
		db.Close()
		t.Fatalf("pipeline: %v", err)
	}
	in := ingestfile.NewIngestor(p, sources, logger)
	return in, store, func() {
		in.Stop(context.Background())
		p.Stop(context.Background())
		db.Close()
	}
}

func waitFor(t *testing.T, store *events.Store, want int, timeout time.Duration) []*event.Event {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, _ := store.Count(context.Background(), events.Query{})
		if n >= want {
			list, err := store.Search(context.Background(), events.Query{Limit: want + 20})
			if err != nil {
				t.Fatalf("search: %v", err)
			}
			return list
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d events", want)
	return nil
}

func TestTail_PlainFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte("pre-existing line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	in, store, cleanup := setupTail(t, dir, []ingestfile.Source{{Name: "app", Path: path, Format: "plain"}})
	defer cleanup()

	if err := in.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Tailer starts at EOF: pre-existing content is not ingested.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		fmt.Fprintf(f, "tailed line %d\n", i)
	}
	f.Close()

	got := waitFor(t, store, 3, 10*time.Second)
	if got[0].Message == "" || !strings.Contains(got[0].Message, "tailed line") {
		t.Errorf("plain tail lost message content: %q", got[0].Message)
	}
}

func TestTail_JSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.json.log")
	os.WriteFile(path, []byte(""), 0o644)

	in, store, cleanup := setupTail(t, dir, []ingestfile.Source{{Name: "j", Path: path, Format: "json"}})
	defer cleanup()
	if err := in.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	fmt.Fprintf(f, `{"message":"disk almost full","host":"db01","severity":"warning","level":"warn","user":"tom","custom_field":"xx"}`)
	fmt.Fprintf(f, "\n")
	f.Close()

	got := waitFor(t, store, 1, 10*time.Second)
	ev := got[0]
	if ev.Message != "disk almost full" {
		t.Errorf("json message parse: %q", ev.Message)
	}
	if ev.Host != "db01" || ev.User != "tom" {
		t.Errorf("json field mapping: %+v", ev)
	}
	if ev.Severity != "warning" {
		t.Errorf("json severity: %q", ev.Severity)
	}
	if ev.Attributes == nil || ev.Attributes["custom_field"] != "xx" {
		t.Errorf("json extra attributes dropped: %#v", ev.Attributes)
	}
	if !strings.Contains(string(ev.Raw), "disk almost full") {
		t.Errorf("raw line not preserved: %q", string(ev.Raw))
	}
	if ev.RawFormat != "ndjson" {
		t.Errorf("raw_format: got %q", ev.RawFormat)
	}
	if ev.Attributes["parser"] != "file-json" {
		t.Errorf("parser provenance: got %v", ev.Attributes["parser"])
	}
	if ev.Attributes["collector"] != "j" {
		t.Errorf("collector provenance: got %v", ev.Attributes["collector"])
	}
}

func TestTail_SyslogLineMessageNotEmpty(t *testing.T) {
	// The RFC3164/RFC5424 version flags in the file tailer were swapped, which
	// made RFC3164 lines resolve to an empty message. Regression test.
	dir := t.TempDir()
	path := filepath.Join(dir, "sys.log")
	os.WriteFile(path, []byte(""), 0o644)

	in, store, cleanup := setupTail(t, dir, []ingestfile.Source{{Name: "s", Path: path, Format: "syslog"}})
	defer cleanup()
	if err := in.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	fmt.Fprintf(f, "<134>Sep  3 18:30:00 server01 sshd: Failed password for admin\n")
	fmt.Fprintf(f, "<165>1 2026-01-01T00:00:00Z web01 nginx - ID[728] - GET /admin 403\n")
	f.Close()

	got := waitFor(t, store, 2, 10*time.Second)
	var rfc3164, rfc5424 int
	for _, ev := range got {
		if strings.Contains(ev.Message, "Failed password") {
			rfc3164++
			if ev.Host != "server01" {
				t.Errorf("rfc3164 host: %q", ev.Host)
			}
			if ev.Attributes["parser"] != "file-syslog" {
				t.Errorf("file-syslog parser provenance: got %v", ev.Attributes["parser"])
			}
			if string(ev.Raw) == "" {
				t.Error("raw line not preserved for file syslog")
			}
		}
		if strings.Contains(ev.Message, "403") {
			rfc5424++
			if ev.Host != "web01" {
				t.Errorf("rfc5424 host field-shift: %q", ev.Host)
			}
			if ev.Source != "nginx" {
				t.Errorf("rfc5424 source field-shift: %q", ev.Source)
			}
		}
	}
	if rfc3164 != 1 {
		t.Errorf("RFC3164 message lost (version-flag swap bug): got %d matching events", rfc3164)
	}
	if rfc5424 != 1 {
		t.Errorf("RFC5424 message lost: %d", rfc5424)
	}
}

func TestTail_CEFFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fw.cef")
	os.WriteFile(path, []byte(""), 0o644)

	in, store, cleanup := setupTail(t, dir, []ingestfile.Source{{Name: "fw", Path: path, Format: "cef"}})
	defer cleanup()
	if err := in.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	fmt.Fprintf(f, "CEF:8|Quetzalog|FW|1.0|210|Blocked TCP|7|src=10.1.2.3 dst=8.8.8.8 dpt=22 suser=alice\n")
	f.Close()

	got := waitFor(t, store, 1, 10*time.Second)
	ev := got[0]
	if ev.Message != "Blocked TCP" {
		t.Errorf("cef message: %q", ev.Message)
	}
	if ev.SourceIP != "10.1.2.3" || ev.DestinationIP != "8.8.8.8" || ev.DestinationPort != 22 {
		t.Errorf("cef fields: %q %q %d", ev.SourceIP, ev.DestinationIP, ev.DestinationPort)
	}
	if ev.RawFormat != "cef" {
		t.Errorf("raw_format: %q", ev.RawFormat)
	}
	if ev.Attributes["parser"] != "file-cef" {
		t.Errorf("parser provenance: %v", ev.Attributes["parser"])
	}
}

func TestTail_PlainAutoDetectsSpecialFormats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.log")
	os.WriteFile(path, []byte(""), 0o644)

	in, store, cleanup := setupTail(t, dir, []ingestfile.Source{{Name: "m", Path: path, Format: "plain"}})
	defer cleanup()
	if err := in.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	fmt.Fprintf(f, "CEF:8|Quetzalog|FW|1.0|210|Blocked TCP|7|src=10.1.2.3\n")
	fmt.Fprintf(f, "just a plain line\n")
	f.Close()

	got := waitFor(t, store, 2, 10*time.Second)
	byMsg := map[string]*event.Event{}
	for _, ev := range got {
		byMsg[ev.Message] = ev
	}
	cef := byMsg["Blocked TCP"]
	if cef == nil {
		t.Fatalf("cef line not auto-detected: %#v", got)
	}
	if cef.Attributes["parsed_as"] != "cef" {
		t.Errorf("parsed_as: %v", cef.Attributes["parsed_as"])
	}
	if cef.SourceIP != "10.1.2.3" {
		t.Errorf("cef src: %q", cef.SourceIP)
	}
	plain := byMsg["just a plain line"]
	if plain == nil || plain.Attributes["parsed_as"] != nil {
		t.Errorf("plain line mishandled: %#v", plain)
	}
}

func TestTail_MissingFileDoesNotCrash(t *testing.T) {
	dir := t.TempDir()
	in, _, cleanup := setupTail(t, dir, []ingestfile.Source{{Name: "nope", Path: filepath.Join(dir, "nope.log"), Format: "plain"}})
	defer cleanup()
	// Start tolerates missing files (logs and continues).
	if err := in.Start(context.Background()); err != nil {
		t.Fatalf("start with missing file errored: %v", err)
	}
}

// The rewritten watchFile must not ingest partial lines and must not
// duplicate a completed prefix: previously the offset advanced before the
// ingest succeeded, so a failed read lost data, and the naive tail replayed
// incomplete lines.
func TestTail_PartialLineConsumedOnceWhenCompleted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	in, store, cleanup := setupTail(t, dir, []ingestfile.Source{{Name: "app", Path: path, Format: "plain"}})
	defer cleanup()
	if err := in.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Incomplete line: the tailer polls at 1s; after two intervals it must
	// still have ingested nothing.
	if _, err := f.WriteString("alpha"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2200 * time.Millisecond)
	if n, _ := store.Count(context.Background(), events.Query{}); n != 0 {
		t.Fatalf("partial line ingested before completion: %d events", n)
	}

	// Complete the line and add one more.
	if _, err := f.WriteString(" beta\ngamma\n"); err != nil {
		t.Fatal(err)
	}
	got := waitFor(t, store, 2, 10*time.Second)

	// Let a few more poll cycles pass: the same bytes must not be replayed.
	time.Sleep(2200 * time.Millisecond)
	n, _ := store.Count(context.Background(), events.Query{})
	if n != 2 {
		t.Fatalf("expected exactly 2 events, got %d (duplicate or replay?)", n)
	}

	msgs := map[string]bool{}
	for _, ev := range got {
		msgs[ev.Message] = true
	}
	if !msgs["alpha beta"] || !msgs["gamma"] {
		t.Errorf("unexpected messages: %v", msgs)
	}
}
