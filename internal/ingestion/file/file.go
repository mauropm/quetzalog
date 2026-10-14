package file

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"quetzalog/internal/ingestion"
	"quetzalog/internal/parsers"
	"quetzalog/pkg/event"
)

// maxTailRead caps how many bytes a single poll reads per file, so a bursty
// log cannot make one poll loop run away.
const maxTailRead = 8 << 20

// Source defines a file to tail and how to parse its lines.
type Source struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Format string `json:"format"` // "syslog", "json", "plain", "regex"
	Regex  string `json:"regex"`  // for "regex" format
}

// Ingestor tails files and ingests parsed events through the pipeline.
type Ingestor struct {
	pipeline *ingestion.Pipeline
	sources  []Source
	logger   *slog.Logger
	mu       sync.Mutex
	tails    map[string]*fileTail
	ctx      context.Context
	cancel   context.CancelFunc
	running  bool

	// reMu guards the compiled-regex cache so a regex format source does not
	// recompile its pattern on every line.
	reMu    sync.Mutex
	reCache map[string]*regexp.Regexp
}

// fileTail tracks state for a single tailed file.
type fileTail struct {
	file   *os.File
	inode  uint64
	offset int64
	buf    []byte // reused read buffer
	source Source
}

// NewIngestor creates a new file ingestor.
func NewIngestor(pipeline *ingestion.Pipeline, sources []Source, logger *slog.Logger) *Ingestor {
	return &Ingestor{
		pipeline: pipeline,
		sources:  sources,
		logger:   logger,
		tails:    make(map[string]*fileTail),
		reCache:  make(map[string]*regexp.Regexp),
	}
}

// Start begins tailing all configured sources.
func (i *Ingestor) Start(ctx context.Context) error {
	i.ctx, i.cancel = context.WithCancel(ctx)

	for _, source := range i.sources {
		if err := i.tailFile(i.ctx, source); err != nil {
			i.logger.Error("failed to start tailing file", "source", source.Name, "path", source.Path, "error", err)
			continue
		}
		i.logger.Info("started tailing file", "source", source.Name, "path", source.Path, "format", source.Format)
	}

	return nil
}

// Stop gracefully shuts down all file tails.
func (i *Ingestor) Stop(ctx context.Context) error {
	if i.cancel != nil {
		i.cancel()
	}

	i.mu.Lock()
	for name, tail := range i.tails {
		if tail.file != nil {
			tail.file.Close()
			delete(i.tails, name)
		}
	}
	i.mu.Unlock()

	i.running = false
	i.logger.Info("file ingestor stopped")
	return nil
}

// tailFile opens a file and begins reading from the end, monitoring for changes.
func (i *Ingestor) tailFile(ctx context.Context, source Source) error {
	// Open the file and get its initial inode.
	file, err := os.Open(source.Path)
	if err != nil {
		return fmt.Errorf("open file %s: %w", source.Path, err)
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("stat file %s: %w", source.Path, err)
	}

	inode := getInode(info)
	offset := int64(0)

	// Seek to end for new files (tail -F behavior)
	if info.IsDir() {
		file.Close()
		return fmt.Errorf("%s is a directory", source.Path)
	}

	// Start from end of file
	if offset, err = file.Seek(0, 2); err != nil {
		file.Close()
		return fmt.Errorf("seek file %s: %w", source.Path, err)
	}

	tail := &fileTail{
		file:   file,
		inode:  inode,
		offset: offset,
		source: source,
	}

	i.mu.Lock()
	i.tails[source.Name] = tail
	i.mu.Unlock()

	go i.watchFile(ctx, tail)

	return nil
}

// watchFile monitors a file for changes, rotating when the inode changes.
func (i *Ingestor) watchFile(ctx context.Context, tail *fileTail) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Check if file has been rotated (inode changed).
		info, err := os.Stat(tail.source.Path)
		if err != nil {
			// File might not exist yet; wait and retry.
			i.logger.Warn("file not found, waiting", "path", tail.source.Path)
			time.Sleep(5 * time.Second)
			continue
		}

		newInode := getInode(info)
		if newInode != tail.inode {
			i.logger.Info("file rotation detected", "path", tail.source.Path)
			tail.file.Close()

			newFile, err := os.Open(tail.source.Path)
			if err != nil {
				i.logger.Error("failed to open rotated file", "path", tail.source.Path, "error", err)
				time.Sleep(5 * time.Second)
				continue
			}

			tail.file = newFile
			tail.inode = newInode
			tail.offset = 0
			tail.buf = tail.buf[:0]
			continue
		}

		// Check for new content. Read exactly the bytes beyond the stored
		// offset and advance the offset only past complete lines. (The
		// previous per-poll bufio.Scanner read ahead past parsed lines,
		// losing buffered-but-unparsed bytes and duplicating partial
		// trailing lines.)
		curInfo, _ := tail.file.Stat()
		if curInfo == nil {
			time.Sleep(time.Second)
			continue
		}
		curSize := curInfo.Size()

		if curSize < tail.offset {
			// Truncated in place (rotation by truncate): restart from 0.
			i.logger.Info("file truncated, restarting tail", "path", tail.source.Path)
			tail.offset = 0
			continue
		}

		if curSize > tail.offset {
			if _, err := tail.file.Seek(tail.offset, io.SeekStart); err != nil {
				i.logger.Error("failed to seek tail file", "source", tail.source.Name, "error", err)
				time.Sleep(5 * time.Second)
				continue
			}

			want := curSize - tail.offset
			if want > maxTailRead {
				want = maxTailRead
			}
			if int64(cap(tail.buf)) < want {
				tail.buf = make([]byte, want)
			}
			data := tail.buf[:want]
			n, err := tail.file.Read(data)
			if err != nil && err != io.EOF {
				i.logger.Error("failed reading tail file", "source", tail.source.Name, "error", err)
				time.Sleep(5 * time.Second)
				continue
			}
			data = data[:n]

			// Only ingest complete lines; the remainder is re-read next poll.
			end := bytes.LastIndexByte(data, '\n')
			if end >= 0 {
				chunk := data[:end+1]
				pos := 0
				for pos < len(chunk) {
					nl := bytes.IndexByte(chunk[pos:], '\n')
					if nl < 0 {
						break
					}
					line := strings.TrimSpace(string(chunk[pos : pos+nl]))
					if ev := i.processLine(line, tail.source); ev != nil {
						if err := i.pipeline.Ingest(ctx, ev); err != nil {
							// Back-pressure or shutdown: do not advance the
							// offset, this line is retried on the next poll
							// instead of being silently lost.
							i.logger.Warn("failed to ingest event from file", "source", tail.source.Name, "error", err)
							break
						}
					}
					tail.offset += int64(nl + 1)
					pos += nl + 1
				}
			}
		}

		// Wait before checking again
		time.Sleep(1 * time.Second)
	}
}

// processLine parses a line based on the configured format.
func (i *Ingestor) processLine(line string, source Source) *event.Event {
	ev := event.NewEvent()
	ev.ReceivedAt = time.Now()
	ev.SourceType = fmt.Sprintf("file:%s", source.Format)

	event.Provenance(ev, []byte(line), fileProvenance(source.Format), "file-"+source.Format, "1", source.Name)

	switch source.Format {
	case "json":
		return i.parseJSONLine(line, ev)
	case "syslog":
		return i.parseSyslogLine(line, ev)
	case "cef":
		return i.parseSpecialLine(line, "cef", ev)
	case "leef":
		return i.parseSpecialLine(line, "leef", ev)
	case "gelf":
		return i.parseSpecialLine(line, "gelf", ev)
	case "regex":
		return i.parseRegexLine(line, source, ev)
	default:
		return i.parsePlainLine(line, ev)
	}
}

// parseSpecialLine parses a line with the named registry parser
// (cef/leef/gelf). Lines that do not match the format fall back to
// plain-text handling so malformed lines still get ingested.
func (i *Ingestor) parseSpecialLine(line, format string, ev *event.Event) *event.Event {
	p, ok := parsers.Default.Get(format)
	if !ok {
		return i.parsePlainLine(line, ev)
	}
	parsed, matched := p.Parse([]byte(line))
	if !matched {
		ev.Message = line
		return ev
	}
	parsers.Fill(ev, parsed)
	return ev
}

// parseJSONLine attempts to parse the line as JSON and map fields to the event.
func (i *Ingestor) parseJSONLine(line string, ev *event.Event) *event.Event {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		ev.Message = line
		return ev
	}

	// Map common JSON syslog/event fields
	if msg, ok := raw["message"].(string); ok {
		ev.Message = msg
	} else if msg, ok := raw["msg"].(string); ok {
		ev.Message = msg
	} else if msg, ok := raw["log"].(string); ok {
		ev.Message = msg
	} else {
		ev.Message = line
	}

	if host, ok := raw["host"].(string); ok {
		ev.Host = host
	} else if host, ok := raw["hostname"].(string); ok {
		ev.Host = host
	}

	if source, ok := raw["source"].(string); ok {
		ev.Source = source
	}
	if sourceType, ok := raw["sourcetype"].(string); ok {
		ev.SourceType = sourceType
	}
	if severity, ok := raw["severity"].(string); ok {
		ev.Severity = event.ParseSeverity(severity)
	} else if severity, ok := raw["level"].(string); ok {
		ev.Severity = event.ParseSeverity(severity)
	} else if sevNum, ok := raw["severity_level"].(float64); ok {
		ev.Severity = severityFromNumber(int32(sevNum))
	}

	if service, ok := raw["service"].(string); ok {
		ev.Service = service
	}
	if user, ok := raw["user"].(string); ok {
		ev.User = user
	}
	if sourceIP, ok := raw["source_ip"].(string); ok {
		ev.SourceIP = sourceIP
	}

	// Timestamp
	if ts, ok := raw["timestamp"].(string); ok {
		ev.Timestamp = event.ParseTimestamp(ts)
	} else if ts, ok := raw["@timestamp"].(string); ok {
		ev.Timestamp = event.ParseTimestamp(ts)
	} else if ts, ok := raw["time"].(string); ok {
		ev.Timestamp = event.ParseTimestamp(ts)
	}

	// Type/EventType
	if et, ok := raw["event_type"].(string); ok {
		ev.EventType = et
	} else if et, ok := raw["type"].(string); ok {
		ev.EventType = et
	}

	// Category
	if cat, ok := raw["category"].(string); ok {
		ev.Category = cat
	}

	// Action
	if action, ok := raw["action"].(string); ok {
		ev.Action = action
	}

	// Outcome
	if outcome, ok := raw["outcome"].(string); ok {
		ev.Outcome = outcome
	}

	// Copy remaining fields as attributes
	if ev.Attributes == nil {
		ev.Attributes = make(map[string]any)
	}
	for k, v := range raw {
		if _, known := knownFields[k]; !known {
			ev.Attributes[k] = v
		}
	}

	return ev
}

// parseSyslogLine parses the line using syslog format matching.
func (i *Ingestor) parseSyslogLine(line string, ev *event.Event) *event.Event {
	result := i.syslogParser(line)
	if result != nil {
		ev.SourceType = "syslog"
		ev.Severity = result.Severity
		ev.Host = result.Host
		ev.Source = result.Source
		ev.Message = result.Message
		ev.ProcessID = result.PID
	} else {
		ev.Message = line
	}

	return ev
}

// compiledRegex returns the compiled regex for pattern, compiling and caching
// it on first use.
func (i *Ingestor) compiledRegex(pattern string) (*regexp.Regexp, error) {
	i.reMu.Lock()
	defer i.reMu.Unlock()
	if re, ok := i.reCache[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	i.reCache[pattern] = re
	return re, nil
}

// parseRegexLine applies the source's regex pattern to extract fields. The
// pattern is compiled once and cached instead of recompiled per line.
func (i *Ingestor) parseRegexLine(line string, source Source, ev *event.Event) *event.Event {
	re, err := i.compiledRegex(source.Regex)
	if err != nil {
		i.logger.Error("invalid regex", "pattern", source.Regex, "error", err)
		ev.Message = line
		return ev
	}

	matches := re.FindStringSubmatch(line)
	if matches == nil {
		ev.Message = line
		return ev
	}

	ev.Message = line

	// Use named groups if available, otherwise use numbered groups
	if re.NumSubexp() > 0 {
		for i, name := range re.SubexpNames() {
			if i == 0 {
				continue
			}
			if i < len(matches) && matches[i] != "" {
				ev.Attributes[name] = matches[i]
			}
		}
	}

	return ev
}

// parsePlainLine uses the raw line as the message, after trying the
// unambiguous special formats (CEF/LEEF/GELF), which commonly arrive in
// plain-text files. Behavior for anything that is not one of those is
// unchanged.
func (i *Ingestor) parsePlainLine(line string, ev *event.Event) *event.Event {
	if parsed, name, ok := parsers.Default.DetectSpecial([]byte(line)); ok {
		parsers.Fill(ev, parsed)
		ev.Attributes["parsed_as"] = name
		return ev
	}
	ev.Message = line
	return ev
}

// fileProvenance maps a file source format to its raw-format label.
func fileProvenance(format string) string {
	switch format {
	case "json":
		return "ndjson"
	case "syslog":
		return "syslog"
	case "cef":
		return "cef"
	case "leef":
		return "leef"
	case "gelf":
		return "json"
	default:
		return "text"
	}
}

// syslogParserResult holds the parsed result of a syslog message.
type syslogParserResult struct {
	Facility int
	Severity string
	Host     string
	Source   string
	PID      string
	Message  string
}

// syslogParser attempts to parse a syslog message.
var (
	rfc5424Re = regexp.MustCompile(`^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(?:<(\d+)>)?\s*(.*)`)
	rfc3164Re = regexp.MustCompile(`^<(\d+)>(\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)`)
)

func (i *Ingestor) syslogParser(line string) *syslogParserResult {
	// RFC5424: <priority>version timestamp hostname app-name procid msgid sd message
	if m := rfc5424Re.FindStringSubmatch(line); m != nil {
		r := parseSyslogMatch(m, 2)
		if r != nil {
			return r
		}
	}

	// RFC3164: <priority>timestamp hostname app[pid]: message
	if m := rfc3164Re.FindStringSubmatch(line); m != nil {
		return parseSyslogMatch(m, 1)
	}

	return nil
}

// parseSyslogMatch extracts fields from a syslog regex match.
func parseSyslogMatch(m []string, version int) *syslogParserResult {
	priority, err := strconv.Atoi(m[1])
	if err != nil {
		return nil
	}

	facility := priority / 8
	severityCode := priority % 8

	result := &syslogParserResult{
		Facility: facility,
		Severity: severityFromNumber(int32(severityCode)),
	}

	if version == 2 {
		// RFC5424
		if len(m) > 4 && m[4] != "-" {
			result.Host = m[4]
		}
		if len(m) > 5 && m[5] != "-" {
			result.Source = m[5]
		}
		if len(m) > 6 && m[6] != "-" {
			result.PID = m[6]
		}
		if len(m) > 8 {
			result.Message = m[8]
		}
	} else {
		// RFC3164
		if len(m) > 3 && m[3] != "-" {
			result.Host = m[3]
		}
		if len(m) > 4 && m[4] != "-" {
			result.Source = m[4]
		}
		if len(m) > 5 && m[5] != "" {
			result.PID = m[5]
		}
		if len(m) > 6 {
			result.Message = m[6]
		}
	}

	return result
}

// severityFromNumber converts a numeric severity to string.
func severityFromNumber(n int32) string {
	switch {
	case n >= 7:
		return "emergency"
	case n >= 6:
		return "alert"
	case n >= 5:
		return "critical"
	case n >= 4:
		return "err"
	case n >= 3:
		return "warning"
	case n >= 2:
		return "notice"
	case n >= 1:
		return "informational"
	case n >= 0:
		return "debug"
	default:
		return "unset"
	}
}

// getInode returns the inode number of a file info.
func getInode(info os.FileInfo) uint64 {
	if fi, ok := info.Sys().(*syscall.Stat_t); ok {
		return fi.Ino
	}
	return 0
}

var knownFields = map[string]bool{
	"message":        true,
	"msg":            true,
	"log":            true,
	"host":           true,
	"hostname":       true,
	"source":         true,
	"sourcetype":     true,
	"severity":       true,
	"level":          true,
	"severity_level": true,
	"service":        true,
	"user":           true,
	"source_ip":      true,
	"timestamp":      true,
	"@timestamp":     true,
	"time":           true,
	"event_type":     true,
	"type":           true,
	"category":       true,
	"action":         true,
	"outcome":        true,
	"id":             true,
	"pid":            true,
	"process":        true,
	"user_id":        true,
	"dest_ip":        true,
	"dest_port":      true,
}
