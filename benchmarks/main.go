package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"quetzalog/internal/alerts"
	"quetzalog/internal/database"
	"quetzalog/internal/detections"
	"quetzalog/internal/events"
	"quetzalog/internal/query"
	"quetzalog/internal/spl"
	"quetzalog/pkg/event"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var eventTypes = []string{
	"authentication", "logon", "logoff", "file_access", "process_start",
	"network_connection", "firewall_deny", "firewall_allow", "dns_query",
	"privilege_escalation", "account_lockout", "password_change",
	"service_start", "service_stop", "config_change",
}

var sources = []string{
	"ssh", "sudo", "sshd", "systemd", "kernel", "firewall", "dns",
	"nginx", "apache", "postfix", "dovecot", "docker",
}

var severities = []string{"debug", "info", "notice", "warning", "err", "critical", "alert", "emergency"}

var hosts = []string{
	"web01", "web02", "db01", "db02", "app01", "app02", "auth01",
	"mail01", "proxy01", "dns01", "file01", "monitor01",
}

var users = []string{
	"root", "admin", "jsmith", "dbadmin", "deploy", "www-data",
	"nginx", "postgres", "ubuntu", "ec2-user", "ansible",
}

var messages = []string{
	"Failed password for %s from %s port %d ssh2",
	"Accepted publickey for %s from %s port %d ssh2",
	"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=%s",
	"session opened for user %s by (uid=0)",
	"session closed for user %s",
	"sudo: %s : TTY=pts/0 ; PWD=/root ; COMMAND=/bin/systemctl restart nginx",
	"kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=%s DST=%s LEN=40 TOS=0x00 PROTO=TCP SPT=%d DPT=22",
	"nginx: connection from %s:%d accepted",
	"POST /api/v1/alerts 201 Created",
	"GET /health 200 OK",
	"database connection pool exhausted, waiting for available connection",
	"failed to resolve hostname %s: NXDOMAIN",
	"privilege escalation detected: %s executed as root via sudo",
	"account %s locked out after 5 failed attempts",
	"certificate expiring in 7 days for *.example.com",
	"new process %s started by user %s with PID %d",
	"file modified: %s by user %s",
	"dns query for %s from %s type=A",
}

var actions = []string{"create", "read", "update", "delete", "login", "logout", "modify", "execute"}
var outcomes = []string{"success", "failure", "timeout", "denied"}

// EventGenerator generates synthetic security events at configurable rates.
type EventGenerator struct {
	sources    []string
	severities []string
	eventTypes []string
	hosts      []string
	users      []string
	ipRanges   []string
	messages   []string
	actions    []string
	outcomes   []string
	rng        *rand.Rand
	mu         sync.Mutex
	counter    int64
}

func NewEventGenerator() *EventGenerator {
	return &EventGenerator{
		sources:    sources,
		severities: severities,
		eventTypes: eventTypes,
		hosts:      hosts,
		users:      users,
		ipRanges:   []string{"10.0.0", "10.0.1", "192.168.1", "172.16.0", "10.10.0"},
		messages:   messages,
		actions:    actions,
		outcomes:   outcomes,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (g *EventGenerator) Generate() *event.Event {
	g.mu.Lock()
	id := atomic.AddInt64(&g.counter, 1)
	g.mu.Unlock()

	generator := g.rng
	eventType := g.eventTypes[generator.Intn(len(g.eventTypes))]
	source := g.sources[generator.Intn(len(g.sources))]
	severity := g.severities[generator.Intn(len(g.severities))]
	host := g.hosts[generator.Intn(len(g.hosts))]
	user := g.users[generator.Intn(len(g.users))]
	ipPrefix := g.ipRanges[generator.Intn(len(g.ipRanges))]
	ip := fmt.Sprintf("%s.%d", ipPrefix, generator.Intn(254)+1)
	port := generator.Intn(65535) + 1
	action := g.actions[generator.Intn(len(g.actions))]
	outcome := g.outcomes[generator.Intn(len(g.outcomes))]

	msg := g.generateMessage()
	msg = fmt.Sprintf(msg, user, ip, port, ip, user)

	return &event.Event{
		ID:              fmt.Sprintf("evt-%d-%08x", id, id),
		Timestamp:       time.Now(),
		ReceivedAt:      time.Now(),
		Source:          source,
		SourceType:      "syslog",
		Host:            host,
		IP:              ip,
		Service:         source,
		Severity:        severity,
		Message:         msg,
		EventType:       eventType,
		Category:        "security",
		Action:          action,
		Outcome:         outcome,
		User:            user,
		Process:         source,
		ProcessID:       fmt.Sprintf("%d", generator.Intn(65535)),
		DestinationIP:   ip,
		DestinationPort: port,
		SourceIP:        ip,
		SourcePort:      generator.Intn(65535) + 1024,
		Attributes: map[string]any{
			"event_id": fmt.Sprintf("evt-%d", id),
			"trace_id": fmt.Sprintf("trace-%016x", id),
		},
	}
}

func (g *EventGenerator) GenerateBatch(n int) []*event.Event {
	batch := make([]*event.Event, 0, n)
	for i := 0; i < n; i++ {
		batch = append(batch, g.Generate())
	}
	return batch
}

func (g *EventGenerator) generateMessage() string {
	msgs := []string{
		"User %s logged in from %s",
		"Failed login attempt by %s from %s",
		"Process %s started on host %s",
		"File %s accessed by %s",
		"Network connection from %s to %s",
		"Configuration changed by %s",
		"Service started on %s",
		"Authentication failure for %s from %s",
	}
	return msgs[g.rng.Intn(len(msgs))]
}

// BenchResult holds the result of a single benchmark.
type BenchResult struct {
	Name     string
	Items    int64
	Duration time.Duration
	Rate     float64 // items/sec
	Error    error
}

func (r BenchResult) String() string {
	err := ""
	if r.Error != nil {
		err = fmt.Sprintf(" error=%v", r.Error)
	}
	return fmt.Sprintf("  %-40s %8d events  %10s  (%.0f events/sec)%s",
		r.Name, r.Items, r.Duration.Round(time.Millisecond), r.Rate, err)
}

// BenchReport holds the full set of benchmark results for JSON output.
type BenchReport struct {
	Timestamp string        `json:"timestamp"`
	Host      string        `json:"host"`
	GoVersion string        `json:"go_version"`
	GoOS      string        `json:"go_os"`
	GoArch    string        `json:"go_arch"`
	Results   []BenchResult `json:"results"`
}

func main() {
	dbPath := flag.String("db", ":memory:", "Path to SQLite database")
	iterations := flag.Int("iterations", 3, "Number of times to run each benchmark (avg)")
	ingestN := flag.Int("ingest-n", 10000, "Number of events for ingestion benchmark")
	searchN := flag.Int("search-n", 1000, "Number of events to pre-seed for search benchmark")
	searchRepeat := flag.Int("search-repeat", 100, "Number of search iterations")
	concurrency := flag.Int("concurrency", 10, "Number of goroutines for concurrent benchmark")
	report := flag.Bool("report", false, "Output benchmark results as JSON")
	_ = flag.Bool("detail", false, "Show timing details for each iteration")
	slog.SetLogLoggerLevel(slog.LevelWarn)

	flag.Parse()

	host, _ := os.Hostname()

	fmt.Println("=== Quetzalog Benchmark Suite ===")
	fmt.Println()
	fmt.Printf("  DB:           %s\n", *dbPath)
	fmt.Printf("  Ingest N:     %d\n", *ingestN)
	fmt.Printf("  Search N:     %d\n", *searchN)
	fmt.Printf("  Search Rep:   %d\n", *searchRepeat)
	fmt.Printf("  Concurrency:  %d\n", *concurrency)
	fmt.Printf("  Iterations:   %d\n", *iterations)
	fmt.Printf("  Go:           %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	gen := NewEventGenerator()
	db, err := setupDB(*dbPath, gen, *searchN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup database: %v\n", err)
		os.Exit(1)
	}
	defer database.Shutdown(db)

	results := []BenchResult{}

	// 1. Single event ingestion (1 event at a time)
	r := benchMultiRun(*iterations, func() BenchResult {
		store := events.NewStore(db)
		ev := gen.Generate()
		start := time.Now()
		err := store.Create(context.Background(), ev)
		elapsed := time.Since(start)
		rate := float64(1) / elapsed.Seconds()
		return BenchResult{Name: "Single Event Ingestion", Items: 1, Duration: elapsed, Rate: rate, Error: err}
	})
	results = append(results, r)
	fmt.Println(r)

	// 2. Batch ingestion (1000 events at once)
	r = benchMultiRun(*iterations, func() BenchResult {
		store := events.NewStore(db)
		batch := gen.GenerateBatch(*ingestN)
		start := time.Now()
		err := store.CreateBatch(context.Background(), batch)
		elapsed := time.Since(start)
		rate := float64(len(batch)) / elapsed.Seconds()
		return BenchResult{Name: "Batch Ingestion", Items: int64(len(batch)), Duration: elapsed, Rate: rate, Error: err}
	})
	results = append(results, r)
	fmt.Println(r)

	// 3. Concurrent ingestion (10 goroutines, 10000 events each)
	r = benchConcurrentIngestion(db, gen, *concurrency, *ingestN)
	results = append(results, r)
	fmt.Println(r)

	// 4. Search by text (FTS5)
	r = benchSearchText(db, *searchN, *searchRepeat)
	results = append(results, r)
	fmt.Println(r)

	// 5. Search by field filter
	r = benchSearchFilter(db, *searchN, *searchRepeat)
	results = append(results, r)
	fmt.Println(r)

	// 6. Stats aggregation
	r = benchStatsAggregation(db, *searchN, *searchRepeat)
	results = append(results, r)
	fmt.Println(r)

	// 7. SPL query execution
	r = benchSPLQuery(db, *searchN, *searchRepeat)
	results = append(results, r)
	fmt.Println(r)

	// 8. Detection rule execution
	r = benchDetectionExecution(db, *searchN, *searchRepeat)
	results = append(results, r)
	fmt.Println(r)

	// 9. Alert creation benchmark
	r = benchAlertCreation(db, *iterations, 500)
	results = append(results, r)
	fmt.Println(r)

	// 10. Alert status update benchmark
	r = benchAlertStatusUpdate(db, *iterations, 500)
	results = append(results, r)
	fmt.Println(r)

	fmt.Println()
	fmt.Println("=== Summary ===")
	for _, r := range results {
		fmt.Println(r)
	}

	if *report {
		report := &BenchReport{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Host:      host,
			GoVersion: runtime.Version(),
			GoOS:      runtime.GOOS,
			GoArch:    runtime.GOARCH,
			Results:   results,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		encoder.Encode(report)
	}
}

func benchMultiRun(its int, fn func() BenchResult) BenchResult {
	var total time.Duration
	var totalRate float64
	var lastErr error
	items := int64(0)

	for i := 0; i < its; i++ {
		r := fn()
		if r.Error != nil {
			lastErr = r.Error
		}
		total += r.Duration
		totalRate += r.Rate
		items = r.Items
	}

	avg := total / time.Duration(its)
	avgRate := totalRate / float64(its)

	_ = avg
	_ = avgRate
	_ = items

	return BenchResult{
		Name:     fn().Name,
		Items:    items,
		Duration: total / time.Duration(its),
		Rate:     avgRate,
		Error:    lastErr,
	}
}

func benchConcurrentIngestion(db *sql.DB, gen *EventGenerator, goroutines int, eventsPerGoroutine int) BenchResult {
	store := events.NewStore(db)
	ctx := context.Background()

	start := time.Now()
	var wg sync.WaitGroup
	var errCount atomic.Int64
	totalEvents := 0

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			batch := gen.GenerateBatch(eventsPerGoroutine)
			if err := store.CreateBatch(ctx, batch); err != nil {
				errCount.Add(1)
			}
			totalEvents += eventsPerGoroutine
		}()
	}
	wg.Wait()

	elapsed := time.Since(start)
	rate := float64(eventsPerGoroutine*goroutines) / elapsed.Seconds()

	var lastErr error
	if errCount.Load() > 0 {
		lastErr = fmt.Errorf("%d goroutines failed", errCount.Load())
	}

	return BenchResult{
		Name:     fmt.Sprintf("Concurrent Ingestion (%d goroutines)", goroutines),
		Items:    int64(eventsPerGoroutine * goroutines),
		Duration: elapsed,
		Rate:     rate,
		Error:    lastErr,
	}
}

func benchSearchText(db *sql.DB, seedN int, repeat int) BenchResult {
	store := events.NewStore(db)
	ctx := context.Background()

	text := "authentication"
	totalEvents := 0
	var totalDuration time.Duration
	var lastErr error

	for i := 0; i < repeat; i++ {
		start := time.Now()
		q := events.Query{Text: text, Limit: 100}
		evts, err := store.Search(ctx, q)
		elapsed := time.Since(start)
		totalDuration += elapsed
		if err != nil {
			lastErr = err
		}
		totalEvents = len(evts)
	}

	avg := totalDuration / time.Duration(repeat)
	rate := float64(totalEvents) / avg.Seconds()

	return BenchResult{
		Name:     "Search by Text (FTS5)",
		Items:    int64(totalEvents),
		Duration: avg,
		Rate:     rate,
		Error:    lastErr,
	}
}

func benchSearchFilter(db *sql.DB, seedN int, repeat int) BenchResult {
	store := events.NewStore(db)
	ctx := context.Background()

	totalEvents := 0
	var totalDuration time.Duration
	var lastErr error

	for i := 0; i < repeat; i++ {
		start := time.Now()
		q := events.Query{Host: "web01", Severity: "err", Limit: 100}
		evts, err := store.Search(ctx, q)
		elapsed := time.Since(start)
		totalDuration += elapsed
		if err != nil {
			lastErr = err
		}
		totalEvents = len(evts)
	}

	avg := totalDuration / time.Duration(repeat)
	rate := float64(totalEvents) / avg.Seconds()

	return BenchResult{
		Name:     "Search by Field Filter",
		Items:    int64(totalEvents),
		Duration: avg,
		Rate:     rate,
		Error:    lastErr,
	}
}

func benchStatsAggregation(db *sql.DB, seedN int, repeat int) BenchResult {
	svc := query.NewService(db)
	ctx := context.Background()

	totalCount := 0
	var totalDuration time.Duration
	var lastErr error

	for i := 0; i < repeat; i++ {
		start := time.Now()
		resp, err := svc.Execute(ctx, query.SearchRequest{Query: "| stats count by severity"})
		elapsed := time.Since(start)
		totalDuration += elapsed
		if err != nil {
			lastErr = err
		} else if resp != nil {
			totalCount = resp.Count
		}
	}

	avg := totalDuration / time.Duration(repeat)
	rate := float64(totalCount) / avg.Seconds()

	return BenchResult{
		Name:     "Stats Aggregation",
		Items:    int64(totalCount),
		Duration: avg,
		Rate:     rate,
		Error:    lastErr,
	}
}

func benchSPLQuery(db *sql.DB, seedN int, repeat int) BenchResult {
	ctx := context.Background()

	var totalEvents int
	var totalDuration time.Duration
	var lastErr error

	splQuery := `search source=sshd severity=err | head 100`

	for i := 0; i < repeat; i++ {
		start := time.Now()
		results, _, err := spl.Execute(db, ctx, splQuery)
		elapsed := time.Since(start)
		totalDuration += elapsed
		if err != nil {
			lastErr = err
		} else {
			totalEvents = len(results)
		}
	}

	avg := totalDuration / time.Duration(repeat)
	rate := float64(totalEvents) / avg.Seconds()

	return BenchResult{
		Name:     "SPL Query Execution",
		Items:    int64(totalEvents),
		Duration: avg,
		Rate:     rate,
		Error:    lastErr,
	}
}

func benchDetectionExecution(db *sql.DB, seedN int, repeat int) BenchResult {
	evStore := events.NewStore(db)
	store := detections.NewStore(db)
	ctx := context.Background()

	rule := &detections.DetectionRule{
		ID:          "bench-rule-001",
		Name:        "Benchmark Detection Rule",
		Description: "Rule for benchmark testing",
		Query:       "source=sshd severity=err",
		Severity:    "high",
		Enabled:     true,
		Threshold: &detections.Threshold{
			Count:  1,
			Window: "1h",
		},
	}

	var totalDuration time.Duration
	var lastErr error
	totalMatched := 0

	for i := 0; i < repeat; i++ {
		start := time.Now()
		result, err := store.ExecuteNow(ctx, rule, evStore)
		elapsed := time.Since(start)
		totalDuration += elapsed
		if err != nil {
			lastErr = err
		} else {
			totalMatched = result.Matched
		}
	}

	avg := totalDuration / time.Duration(repeat)
	rate := float64(totalMatched) / avg.Seconds()

	return BenchResult{
		Name:     "Detection Rule Execution",
		Items:    int64(totalMatched),
		Duration: avg,
		Rate:     rate,
		Error:    lastErr,
	}
}

func benchAlertCreation(db *sql.DB, iterations int, alertN int) BenchResult {
	store := alerts.NewStore(db)
	ctx := context.Background()

	totalDuration := time.Duration(0)
	var lastErr error

	for i := 0; i < iterations; i++ {
		start := time.Now()
		alert := &alerts.Alert{
			Title:       fmt.Sprintf("Bench alert %d", i),
			Description: "Benchmark alert",
			Severity:    "high",
			DetectionID: "rule-001",
		}
		err := store.Create(ctx, alert)
		elapsed := time.Since(start)
		totalDuration += elapsed
		if err != nil {
			lastErr = err
		}
	}

	avg := totalDuration / time.Duration(iterations)
	rate := float64(alertN) / avg.Seconds()

	return BenchResult{
		Name:     "Alert Creation",
		Items:    int64(alertN),
		Duration: avg,
		Rate:     rate,
		Error:    lastErr,
	}
}

func benchAlertStatusUpdate(db *sql.DB, iterations int, alertN int) BenchResult {
	store := alerts.NewStore(db)
	ctx := context.Background()

	// Create alerts first
	alertIDs := make([]string, 0, iterations)
	for i := 0; i < iterations; i++ {
		alert := &alerts.Alert{
			Title:       fmt.Sprintf("Update bench alert %d", i),
			Description: "For update benchmark",
			Severity:    "medium",
			DetectionID: "rule-002",
		}
		if err := store.Create(ctx, alert); err != nil {
			return BenchResult{Name: "Alert Status Update", Error: fmt.Errorf("setup: %w", err)}
		}
		alertIDs = append(alertIDs, alert.ID)
	}

	totalDuration := time.Duration(0)
	var lastErr error

	for i := 0; i < iterations; i++ {
		start := time.Now()
		err := store.UpdateStatus(ctx, alertIDs[i%len(alertIDs)], "resolved")
		elapsed := time.Since(start)
		totalDuration += elapsed
		if err != nil {
			lastErr = err
		}
	}

	avg := totalDuration / time.Duration(iterations)
	rate := float64(alertN) / avg.Seconds()

	return BenchResult{
		Name:     "Alert Status Update",
		Items:    int64(alertN),
		Duration: avg,
		Rate:     rate,
		Error:    lastErr,
	}
}

// setupDB creates and migrates the database, then seeds it with events.
func setupDB(dbPath string, gen *EventGenerator, seedN int) (*sql.DB, error) {
	db, err := database.Open(dbPath, 4, 2, "30s")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := database.Migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	if seedN > 0 {
		store := events.NewStore(db)
		batch := gen.GenerateBatch(seedN)
		if err := store.CreateBatch(context.Background(), batch); err != nil {
			db.Close()
			return nil, fmt.Errorf("seed events: %w", err)
		}
	}

	return db, nil
}
