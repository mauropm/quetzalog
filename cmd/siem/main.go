package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"quetzalog/internal/alerts"
	"quetzalog/internal/api"
	"quetzalog/internal/auth"
	"quetzalog/internal/config"
	"quetzalog/internal/correlation"
	"quetzalog/internal/database"
	"quetzalog/internal/detections"
	"quetzalog/internal/enrichment"
	"quetzalog/internal/events"
	"quetzalog/internal/incidents"
	"quetzalog/internal/ingestion"
	"quetzalog/internal/ingestion/file"
	"quetzalog/internal/ingestion/hec"
	ingestjson "quetzalog/internal/ingestion/json"
	"quetzalog/internal/ingestion/otlp"
	"quetzalog/internal/ingestion/syslog"
	"quetzalog/internal/query"
	"quetzalog/internal/risk"
	"quetzalog/internal/telemetry"
	"quetzalog/pkg/event"
)

func main() {
	os.Exit(run())
}

func run() int {
	for _, arg := range os.Args[1:] {
		if arg == "--help" || arg == "-h" || arg == "help" {
			fs := flag.NewFlagSet("quetzalog", flag.ExitOnError)
			fs.String("config", "", "path to config file (default ./config.yaml)")
			fs.Bool("debug", false, "enable debug logging")
			writeUsage(fs)
			return 0
		}
	}

	fs := flag.NewFlagSet("quetzalog", flag.ExitOnError)
	// Get command from os.Args, not from FlagSet which may have consumed it
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	configFile := fs.String("config", "", "path to config file (default ./config.yaml)")
	debug := fs.Bool("debug", false, "enable debug logging")

	switch cmd {
	case "serve", "run", "":
		// Parse the flags registered on `fs` for this path; without this the
		// --config/--debug flags were silently ignored (fail-open to defaults).
		if cmd == "" {
			fs.Parse(os.Args[1:])
		} else if len(os.Args) > 2 {
			fs.Parse(os.Args[2:])
		}
		return cmdServe(*configFile, *debug)
	case "demo":
		return cmdDemo()
	case "ingest":
		return cmdIngest(fs.Args())
	case "search":
		return cmdSearch(fs.Args())
	case "alerts":
		return cmdAlerts(fs.Args())
	case "incidents":
		return cmdIncidents(fs.Args())
	case "sources":
		return cmdSources(fs.Args())
	case "detections":
		return cmdDetections(fs.Args())
	case "db":
		return cmdDB(fs.Args())
	case "config":
		return cmdConfig(fs.Args())
	default:
		writeUsage(fs)
		return 1
	}
}

func writeUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", fs.Arg(0))
	fmt.Fprintf(os.Stderr, "Usage: quetzalog <command> [arguments]\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  serve       Start the SIEM server\n")
	fmt.Fprintf(os.Stderr, "  run         Start the SIEM server (alias for serve)\n")
	fmt.Fprintf(os.Stderr, "  demo        Run with synthetic data and exit\n")
	fmt.Fprintf(os.Stderr, "  ingest      Ingest events from file or stdin\n")
	fmt.Fprintf(os.Stderr, "  search      Search events\n")
	fmt.Fprintf(os.Stderr, "  alerts      List alerts\n")
	fmt.Fprintf(os.Stderr, "  incidents   List incidents\n")
	fmt.Fprintf(os.Stderr, "  sources     Manage sources\n")
	fmt.Fprintf(os.Stderr, "  detections  Manage detections\n")
	fmt.Fprintf(os.Stderr, "  db          Database info\n")
	fmt.Fprintf(os.Stderr, "  config      Config management\n")
	fmt.Fprintf(os.Stderr, "\nGlobal:\n")
	fs.PrintDefaults()
}

func cmdServe(cfgFile string, debug bool) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: func() slog.Level {
			if debug {
				return slog.LevelDebug
			}
			return slog.LevelInfo
		}(),
	}))
	slog.SetDefault(logger)

	cfg := config.DefaultConfig()
	if cfgFile != "" {
		loaded, err := config.LoadConfig(cfgFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return 1
		}
		cfg = loaded
	}
	if tok, ok := os.LookupEnv("QUETZALOG_API_TOKEN"); ok && tok != "" {
		cfg.Auth.APIToken = tok
	}

	if debug {
		fmt.Println("Loading config from:", cfgFile)
	}

	dbPath := cfg.Database.Path
	if dbPath == "" {
		dbPath = "./data/siem.db"
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating data directory: %v\n", err)
		return 1
	}

	db, err := database.Open(dbPath, cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.MaxIdleTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		return 1
	}
	defer database.Shutdown(db)

	if debug {
		fmt.Println("Database opened:", dbPath)
	}

	if err := database.Migrate(db); err != nil {
		fmt.Fprintf(os.Stderr, "Error running migrations: %v\n", err)
		return 1
	}

	// Restrict database file permissions once the files exist (contains
	// credentials, tokens, events).
	hardenDataFiles(dbPath)

	if debug {
		fmt.Println("Migrations applied")
	}

	eventStore := events.NewStore(db)
	alertStore := alerts.NewStore(db)
	incidentStore := incidents.NewStore(db)
	detectionStore := detections.NewStore(db)
	searchSvc := query.NewService(db)
	authStore := auth.NewStore(db)
	_ = correlation.NewGraph(db)
	geoEnricher, _ := enrichment.BuildGeoIPEnricher(enrichment.GeoIPConfig{Enabled: false})
	_ = enrichment.NewCompositeEnricher([]enrichment.Enricher{
		enrichment.NewLocalIPEnricher(),
		geoEnricher,
	})
	_ = risk.NewScorer(risk.DefaultConfig, db)
	telemetryMetrics := telemetry.New()

	pipeline := ingestion.NewPipeline(eventStore, cfg.Ingestion.Workers, cfg.Ingestion.BatchSize, logger)
	if err := pipeline.Start(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting pipeline: %v\n", err)
		return 1
	}
	defer pipeline.Stop(context.Background())

	var ingestors []string

	telemetryMetrics.StartBackgroundUpdates(context.Background(), dbPath, 30*time.Second)

	jsonHandler := ingestjson.NewIngestHandler(pipeline, logger)
	jsonServer := &http.Server{
		Addr: fmt.Sprintf(":%d", 8081),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = jsonHandler.Handle(w, r)
		}),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	var syslogReceiver *syslog.Receiver
	if cfg.Syslog.UDPEnabled || cfg.Syslog.TCPEnabled {
		syslogReceiver = syslog.NewReceiver(pipeline, syslog.Config{
			UDPEnabled: cfg.Syslog.UDPEnabled,
			UDPPort:    cfg.Syslog.UDPPort,
			TCPEnabled: cfg.Syslog.TCPEnabled,
			TCPPort:    cfg.Syslog.TCPPort,
		}, logger)
		if err := syslogReceiver.Start(context.Background()); err != nil {
			logger.Error("syslog receiver failed", "error", err)
		} else {
			ingestors = append(ingestors, fmt.Sprintf("syslog (TCP:%d, UDP:%d)", cfg.Syslog.TCPPort, cfg.Syslog.UDPPort))
		}
	}

	if cfg.Splunk.HECEnabled {
		hecTokens := make([]hec.HECToken, len(cfg.Splunk.HECTokens))
		for i, t := range cfg.Splunk.HECTokens {
			hecTokens[i] = hec.HECToken{Token: t.Token, Meta: t.ID}
		}
		hecHandler := hec.NewHandler(pipeline, hecTokens, logger)
		hecServer := &http.Server{
			Addr: fmt.Sprintf(":%d", cfg.Splunk.HECPort),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = hecHandler.Handle(w, r)
			}),
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
		}
		ingestors = append(ingestors, fmt.Sprintf("HEC (port %d)", cfg.Splunk.HECPort))
		go func() {
			logger.Info("HEC server starting", "addr", hecServer.Addr)
			if err := hecServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("HEC server error", "error", err)
			}
		}()
		defer hecServer.Shutdown(context.Background())
	}

	if cfg.OTel.Enabled {
		otlpHandler := otlp.NewHandler(pipeline, logger)
		otlpServer := &http.Server{
			Addr: fmt.Sprintf(":%d", cfg.OTel.HttpPort),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = otlpHandler.Handle(w, r)
			}),
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
		}
		ingestors = append(ingestors, fmt.Sprintf("OTLP HTTP (port %d)", cfg.OTel.HttpPort))
		go func() {
			logger.Info("OTLP server starting", "addr", otlpServer.Addr)
			if err := otlpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("OTLP server error", "error", err)
			}
		}()
		defer otlpServer.Shutdown(context.Background())

		otelGRPC := otlp.NewGRPCReceiver(pipeline, cfg.OTel.GrpcPort, logger)
		if err := otelGRPC.Start(context.Background()); err != nil {
			logger.Error("OTLP gRPC server failed", "error", err)
		} else {
			ingestors = append(ingestors, fmt.Sprintf("OTLP gRPC (port %d)", cfg.OTel.GrpcPort))
		}
		defer otelGRPC.Stop(context.Background())
	}

	if len(cfg.FileIngestion.Sources) > 0 {
		fileSources := make([]file.Source, len(cfg.FileIngestion.Sources))
		for i, s := range cfg.FileIngestion.Sources {
			fileSources[i] = file.Source{Name: s.Name, Path: s.Path, Format: s.Format}
		}
		fileIngestor := file.NewIngestor(pipeline, fileSources, logger)
		if err := fileIngestor.Start(context.Background()); err != nil {
			logger.Error("file ingestor failed", "error", err)
		} else {
			for _, src := range cfg.FileIngestion.Sources {
				ingestors = append(ingestors, fmt.Sprintf("file: %s (%s)", src.Path, src.Format))
			}
		}
	}

	if len(ingestors) > 0 {
		logger.Info("ingestors started", "sources", ingestors)
	}

	mux := http.NewServeMux()
	apiHandler, err := api.SetupRouter(cfg, eventStore, searchSvc, alertStore, incidentStore, detectionStore, authStore, logger)
	if err != nil {
		logger.Error("API setup failed", "error", err)
		if debug {
			fmt.Printf("API setup failed: %v\n", err)
		}
		return 1
	}
	mux.Handle("/api/v1/", apiHandler)
	mux.Handle("/api/v1/json", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = jsonHandler.Handle(w, r)
	}))
	mux.Handle("/api/", apiHandler)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	if debug {
		fmt.Printf("Starting SIEM server on %s\n", server.Addr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errChan := make(chan error, 1)

	go func() {
		logger.Info("SIEM server starting", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	jsonErrChan := make(chan error, 1)
	go func() {
		if debug {
			fmt.Printf("JSON ingestor starting on :%d\n", 8081)
		}
		if err := jsonServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			jsonErrChan <- err
		}
	}()
	defer jsonServer.Shutdown(context.Background())

	metricsAddr := fmt.Sprintf(":%d", cfg.Server.Port+1)
	metricsServer := telemetryMetrics.RegisterHTTP(metricsAddr)
	go func() {
		logger.Info("metrics server starting", "addr", metricsServer.Addr)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server error", "error", err)
		}
	}()
	defer metricsServer.Shutdown(context.Background())

	<-ctx.Done()
	logger.Info("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	jsonServer.Shutdown(shutdownCtx)
	pipeline.Stop(shutdownCtx)
	telemetryMetrics.Shutdown(shutdownCtx)
	database.Shutdown(db)

	select {
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			return 1
		}
	case err := <-jsonErrChan:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "JSON ingestor error: %v\n", err)
			return 1
		}
	case <-shutdownCtx.Done():
		fmt.Fprintf(os.Stderr, "Shutdown timeout\n")
		return 1
	}

	fmt.Println("SIEM server shut down gracefully")
	return 0
}

// hardenDataFiles best-effort restricts the SQLite files to owner access.
func hardenDataFiles(dbPath string) {
	if dbPath == "" || dbPath == ":memory:" {
		return
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := dbPath + suffix
		if _, err := os.Stat(p); err == nil {
			_ = os.Chmod(p, 0o600)
		}
	}
}

func cmdDemo() int {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	fmt.Println("=== SIEMto Demo ===")
	fmt.Println()
	fmt.Println(`███╗   ███╗███████╗███╗   ███╗█████╗  ██████╗██╗  ██╗███████╗
████╗ ████║██╔════╝████╗ ████║██╔══██╗██╔══██╗██║  ██║██╔════╝
██╔████╔██║█████╗  ██╔████╔██║███████║██║  ██║███████║█████╗  
██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██╔══██║██║  ██║██╔══██║██╔══╝  
██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║██║  ██║╚██████╔╝██║  ██║███████╗
╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝`)
	fmt.Println()

	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		return 1
	}
	defer database.Shutdown(db)

	if err := database.Migrate(db); err != nil {
		fmt.Fprintf(os.Stderr, "Error running migrations: %v\n", err)
		return 1
	}

	eventStore := events.NewStore(db)
	alertStore := alerts.NewStore(db)
	detectionStore := detections.NewStore(db)
	authStore := auth.NewStore(db)

	sources := []string{"sshd", "httpd", "firewall", "auth", "kernel", "nginx", "postgres"}
	severities := []string{"debug", "info", "notice", "warning", "err", "critical", "emergency"}
	eventTypes := []string{"authentication", "network", "file_access", "process", "policy", "intrusion_attempt", "brute_force", "data_exfil"}
	hosts := []string{"web01", "db01", "fw01", "auth01", "app01", "mail01", "proxy01"}
	users := []string{"admin", "root", "deploy", "www-data", "postgres", "backup", "unknown", "attacker"}

	fmt.Println("Generating ~200 synthetic security events...")

	batch := make([]*event.Event, 0, 20)
	now := time.Now()

	for i := 0; i < 200; i++ {
		ev := event.NewEvent()
		ev.Timestamp = now.Add(-time.Duration(200-i) * time.Minute)
		ev.Source = sources[i%len(sources)]
		ev.Severity = severities[i%len(severities)]
		ev.EventType = eventTypes[i%len(eventTypes)]
		ev.Host = hosts[i%len(hosts)]
		ev.User = users[i%len(users)]
		ev.Message = fmt.Sprintf("Synthetic event #%d: %s from %s [%s]", i+1, ev.EventType, ev.Host, ev.Severity)

		if ev.Severity == "critical" || ev.Severity == "emergency" {
			ev.EventType = "intrusion_attempt"
			ev.Action = "blocked"
			ev.Outcome = "blocked"
		} else if ev.Severity == "err" {
			ev.EventType = "authentication"
			ev.Action = "login_failed"
			ev.Outcome = "failure"
		} else if ev.Severity == "warning" {
			ev.EventType = "policy"
			ev.Action = "policy_violation"
		}

		if ev.Attributes == nil {
			ev.Attributes = make(map[string]any)
		}
		ev.Attributes["event_index"] = i + 1
		ev.Attributes["demo"] = true

		batch = append(batch, ev)

		if len(batch) >= 20 {
			if err := eventStore.CreateBatch(context.Background(), batch); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating batch: %v\n", err)
				return 1
			}
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		if err := eventStore.CreateBatch(context.Background(), batch); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating batch: %v\n", err)
			return 1
		}
	}

	fmt.Println("Generated 200 events")

	count, err := eventStore.Count(context.Background(), events.Query{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error counting events: %v\n", err)
		return 1
	}
	fmt.Printf("Total events in database: %d\n", count)

	fmt.Println("\nEvents by severity:")
	for _, sev := range severities {
		n, err := eventStore.Count(context.Background(), events.Query{Severity: sev})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error counting %s: %v\n", sev, err)
			continue
		}
		fmt.Printf("  %-12s %d\n", sev, n)
	}

	fmt.Println("\nAdding detection rules...")

	rules := []detections.DetectionRule{
		{
			Name:        "Brute Force Detection",
			Description: "Detects repeated failed authentication attempts",
			Query:       "event_type=authentication action=login_failed",
			Severity:    "critical",
			Enabled:     true,
			Threshold: &detections.Threshold{
				Count:  5,
				Window: "1h",
			},
		},
		{
			Name:        "Intrusion Attempt",
			Description: "Detects potential intrusion attempts",
			Query:       "event_type=intrusion_attempt",
			Severity:    "emergency",
			Enabled:     true,
		},
		{
			Name:        "Policy Violation",
			Description: "Detects policy violations",
			Query:       "event_type=policy",
			Severity:    "warning",
			Enabled:     true,
		},
		{
			Name:        "Critical Service Activity",
			Description: "Monitors critical services for anomalous activity",
			Query:       "severity=err OR severity=critical OR severity=emergency",
			Severity:    "err",
			Enabled:     true,
		},
	}

	for _, rule := range rules {
		if err := detectionStore.Create(context.Background(), &rule); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating detection rule: %v\n", err)
			return 1
		}
		fmt.Printf("  Added: %s\n", rule.Name)
	}

	fmt.Println("\nCreating demo users...")
	if err := authStore.CreateUser(context.Background(), "analyst", "analyst123", auth.RoleAnalyst); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating analyst user: %v\n", err)
	} else {
		fmt.Println("  Created analyst user")
	}
	if err := authStore.CreateUser(context.Background(), "viewer", "viewer123", auth.RoleViewer); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating viewer user: %v\n", err)
	} else {
		fmt.Println("  Created viewer user")
	}

	fmt.Println("\nRunning detection rules...")

	allRules, err := detectionStore.List(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing detection rules: %v\n", err)
		return 1
	}

	totalAlerts := 0
	for _, rule := range allRules {
		result, err := detectionStore.ExecuteNow(context.Background(), rule, eventStore)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error executing detection %s: %v\n", rule.Name, err)
			continue
		}

		if result.Matched > 0 {
			alert := &alerts.Alert{
				DetectionID: rule.ID,
				Severity:    rule.Severity,
				Title:       fmt.Sprintf("Alert: %s", rule.Name),
				Description: fmt.Sprintf("Detection rule matched %d events", result.Matched),
				Status:      "new",
			}
			if err := alertStore.Create(context.Background(), alert); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating alert: %v\n", err)
			} else {
				totalAlerts++
			}
		}

		fmt.Printf("  %-30s: %d matched, %d total events\n", rule.Name, result.Matched, result.Total)
	}

	fmt.Printf("\nTotal alerts generated: %d\n", totalAlerts)

	fmt.Println("\nAlerts:")
	alertList, err := alertStore.List(context.Background(), alerts.Filter{Limit: 20})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing alerts: %v\n", err)
		return 1
	}

	for _, a := range alertList {
		fmt.Printf("  [%s] %s - %s\n", a.Severity, a.Title, a.Status)
	}

	fmt.Println("\nEntity correlation graph:")
	graph := correlation.NewGraph(db)

	for _, host := range hosts {
		neighbors, err := graph.GetNeighbors(context.Background(), correlation.EntityTypeHost, host, 2)
		if err != nil {
			continue
		}
		if len(neighbors) > 0 {
			fmt.Printf("  Host '%s' -> %d related entities\n", host, len(neighbors))
		}
	}

	fmt.Println("\n=== Demo Complete ===")
	fmt.Printf("  Events ingested:    %d\n", count)
	fmt.Printf("  Detection rules:    %d\n", len(allRules))
	fmt.Printf("  Alerts generated:   %d\n", totalAlerts)
	fmt.Printf("  Time:               %s\n", time.Since(now).Round(time.Millisecond))
	fmt.Println("\nData was stored in an in-memory SQLite database (no persistence).")

	return 0
}

func cmdIngest(args []string) int {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	var (
		configFile string
		quiet      bool
	)
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	fs.BoolVar(&quiet, "quiet", false, "suppress progress output")
	fs.Parse(args)

	cfg := config.DefaultConfig()
	if configFile != "" {
		loaded, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return 1
		}
		cfg = loaded
	}

	dbPath := cfg.Database.Path
	if dbPath == "" {
		dbPath = "./data/siem.db"
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating data directory: %v\n", err)
		return 1
	}

	db, err := database.Open(dbPath, cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.MaxIdleTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		return 1
	}
	defer database.Shutdown(db)

	if err := database.Migrate(db); err != nil {
		fmt.Fprintf(os.Stderr, "Error running migrations: %v\n", err)
		return 1
	}

	eventStore := events.NewStore(db)
	pipeline := ingestion.NewPipeline(eventStore, cfg.Ingestion.Workers, cfg.Ingestion.BatchSize, logger)
	if err := pipeline.Start(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting pipeline: %v\n", err)
		return 1
	}
	defer pipeline.Stop(context.Background())

	count := 0

	if len(fs.Args()) > 0 {
		filename := fs.Args()[0]
		data, err := os.ReadFile(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			return 1
		}

		batch := []json.RawMessage{}
		if err := json.Unmarshal(data, &batch); err == nil {
			for _, raw := range batch {
				ev, err := event.EventFromJSON(raw)
				if err != nil {
					logger.Warn("skipping invalid event", "error", err)
					continue
				}
				if err := pipeline.Ingest(context.Background(), ev); err != nil {
					logger.Warn("failed to ingest event", "error", err)
				}
				count++
			}
		} else {
			ev, err := event.EventFromJSON(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
				return 1
			}
			if err := pipeline.Ingest(context.Background(), ev); err != nil {
				fmt.Fprintf(os.Stderr, "Error ingesting event: %v\n", err)
				return 1
			}
			count = 1
		}
	} else {
		if !quiet {
			fmt.Println("Reading from stdin... (Ctrl+D to finish)")
		}
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			ev, err := event.EventFromJSON([]byte(line))
			if err != nil {
				logger.Warn("skipping invalid JSON line", "error", err)
				continue
			}
			if err := pipeline.Ingest(context.Background(), ev); err != nil {
				logger.Warn("failed to ingest event", "error", err)
			}
			count++
		}
	}

	fmt.Printf("Ingested %d events\n", count)
	return 0
}

func cmdSearch(args []string) int {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	var (
		configFile string
		limit      int
		offset     int
		format     string
	)
	fs := flag.NewFlagSet("search", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	fs.IntVar(&limit, "limit", 20, "max results")
	fs.IntVar(&offset, "offset", 0, "result offset")
	fs.StringVar(&format, "format", "text", "output format: text, json")
	fs.Parse(args)

	if len(fs.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: quetzalog search <query> [flags]\n")
		return 1
	}

	cfg := config.DefaultConfig()
	if configFile != "" {
		loaded, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return 1
		}
		cfg = loaded
	}

	dbPath := cfg.Database.Path
	if dbPath == "" {
		dbPath = "./data/siem.db"
	}

	db, err := database.Open(dbPath, cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.MaxIdleTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		return 1
	}
	defer database.Shutdown(db)

	if err := database.Migrate(db); err != nil {
		fmt.Fprintf(os.Stderr, "Error running migrations: %v\n", err)
		return 1
	}

	searchSvc := query.NewService(db)

	req := query.SearchRequest{
		Query:  fs.Args()[0],
		Limit:  limit,
		Offset: offset,
	}

	result, err := searchSvc.Execute(context.Background(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing search: %v\n", err)
		return 1
	}

	if format == "json" {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	if len(result.Columns) > 0 {
		for _, col := range result.Columns {
			fmt.Printf("%-20s", col)
		}
		fmt.Println()
		for _, row := range result.Results {
			for _, col := range result.Columns {
				fmt.Printf("%-20s", fmt.Sprintf("%v", row[col]))
			}
			fmt.Println()
		}
	}

	fmt.Printf("\nTotal: %d results\n", result.Count)
	return 0
}

func cmdAlerts(args []string) int {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	var (
		configFile string
		status     string
		severity   string
		limit      int
		format     string
	)
	fs := flag.NewFlagSet("alerts", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	fs.StringVar(&status, "status", "", "filter by status")
	fs.StringVar(&severity, "severity", "", "filter by severity")
	fs.IntVar(&limit, "limit", 20, "max results")
	fs.StringVar(&format, "format", "text", "output format: text, json")
	fs.Parse(args)

	cfg := config.DefaultConfig()
	if configFile != "" {
		loaded, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return 1
		}
		cfg = loaded
	}

	dbPath := cfg.Database.Path
	if dbPath == "" {
		dbPath = "./data/siem.db"
	}

	db, err := database.Open(dbPath, cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.MaxIdleTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		return 1
	}
	defer database.Shutdown(db)

	if err := database.Migrate(db); err != nil {
		fmt.Fprintf(os.Stderr, "Error running migrations: %v\n", err)
		return 1
	}

	alertStore := alerts.NewStore(db)

	filter := alerts.Filter{Limit: limit}
	if status != "" {
		filter.Status = status
	}
	if severity != "" {
		filter.Severity = severity
	}

	alerts, err := alertStore.List(context.Background(), filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing alerts: %v\n", err)
		return 1
	}

	if format == "json" {
		data, _ := json.MarshalIndent(alerts, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	if len(alerts) == 0 {
		fmt.Println("No alerts found")
		return 0
	}

	fmt.Printf("%-8s %-12s %-30s %s\n", "SEVERITY", "STATUS", "TITLE", "TIMESTAMP")
	fmt.Println(strings.Repeat("-", 80))
	for _, a := range alerts {
		title := a.Title
		if len(title) > 30 {
			title = title[:27] + "..."
		}
		fmt.Printf("%-8s %-12s %-30s %s\n", a.Severity, a.Status, title, a.Timestamp.Format(time.RFC3339))
	}

	fmt.Printf("\nTotal: %d alerts\n", len(alerts))
	return 0
}

func cmdIncidents(args []string) int {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	var (
		configFile string
		status     string
		severity   string
		limit      int
		format     string
	)
	fs := flag.NewFlagSet("incidents", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	fs.StringVar(&status, "status", "", "filter by status")
	fs.StringVar(&severity, "severity", "", "filter by severity")
	fs.IntVar(&limit, "limit", 20, "max results")
	fs.StringVar(&format, "format", "text", "output format: text, json")
	fs.Parse(args)

	cfg := config.DefaultConfig()
	if configFile != "" {
		loaded, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return 1
		}
		cfg = loaded
	}

	dbPath := cfg.Database.Path
	if dbPath == "" {
		dbPath = "./data/siem.db"
	}

	db, err := database.Open(dbPath, cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.MaxIdleTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		return 1
	}
	defer database.Shutdown(db)

	if err := database.Migrate(db); err != nil {
		fmt.Fprintf(os.Stderr, "Error running migrations: %v\n", err)
		return 1
	}

	incidentStore := incidents.NewStore(db)

	filter := incidents.Filter{Limit: limit}
	if status != "" {
		filter.Status = status
	}
	if severity != "" {
		filter.Severity = severity
	}

	incs, err := incidentStore.List(context.Background(), filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing incidents: %v\n", err)
		return 1
	}

	if format == "json" {
		data, _ := json.MarshalIndent(incs, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	if len(incs) == 0 {
		fmt.Println("No incidents found")
		return 0
	}

	fmt.Printf("%-8s %-14s %-30s %s\n", "SEVERITY", "STATUS", "TITLE", "CREATED AT")
	fmt.Println(strings.Repeat("-", 80))
	for _, inc := range incs {
		title := inc.Title
		if len(title) > 30 {
			title = title[:27] + "..."
		}
		fmt.Printf("%-8s %-14s %-30s %s\n", inc.Severity, inc.Status, title, inc.CreatedAt.Format(time.RFC3339))
	}

	fmt.Printf("\nTotal: %d incidents\n", len(incs))
	return 0
}

func cmdSources(args []string) int {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	var configFile string
	fs := flag.NewFlagSet("sources", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	fs.Parse(args)

	cfg := config.DefaultConfig()
	if configFile != "" {
		loaded, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return 1
		}
		cfg = loaded
	}

	fmt.Println("=== Sources ===")
	fmt.Println()
	fmt.Printf("  JSON HTTP ingest:    :%d\n", 8081)
	fmt.Printf("  Syslog TCP:          :%d\n", cfg.Syslog.TCPPort)
	fmt.Printf("  Syslog UDP:          :%d\n", cfg.Syslog.UDPPort)
	if cfg.Splunk.HECEnabled {
		fmt.Printf("  Splunk HEC:          :%d\n", cfg.Splunk.HECPort)
	}
	if cfg.OTel.Enabled {
		fmt.Printf("  OTLP HTTP:           :%d\n", cfg.OTel.HttpPort)
		fmt.Printf("  OTLP gRPC:           :%d\n", cfg.OTel.GrpcPort)
	}
	if len(cfg.FileIngestion.Sources) > 0 {
		fmt.Println("  File sources:")
		for _, src := range cfg.FileIngestion.Sources {
			fmt.Printf("    - %s: %s (%s)\n", src.Name, src.Path, src.Format)
		}
	}

	return 0
}

func cmdDetections(args []string) int {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	var (
		configFile string
		format     string
		enable     bool
		disable    bool
	)
	fs := flag.NewFlagSet("detections", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	fs.StringVar(&format, "format", "text", "output format: text, json")
	fs.BoolVar(&enable, "enable", false, "enable a detection rule")
	fs.BoolVar(&disable, "disable", false, "disable a detection rule")
	fs.Parse(args)

	cfg := config.DefaultConfig()
	if configFile != "" {
		loaded, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return 1
		}
		cfg = loaded
	}

	dbPath := cfg.Database.Path
	if dbPath == "" {
		dbPath = "./data/siem.db"
	}

	db, err := database.Open(dbPath, cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.MaxIdleTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		return 1
	}
	defer database.Shutdown(db)

	if err := database.Migrate(db); err != nil {
		fmt.Fprintf(os.Stderr, "Error running migrations: %v\n", err)
		return 1
	}

	detectionStore := detections.NewStore(db)

	allRules, err := detectionStore.List(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing detection rules: %v\n", err)
		return 1
	}

	if enable || disable {
		if len(fs.Args()) == 0 {
			fmt.Fprintf(os.Stderr, "Usage: quetzalog detections --enable/--disable <rule-id>\n")
			return 1
		}
		id := fs.Args()[0]
		if enable {
			if err := detectionStore.Enable(context.Background(), id); err != nil {
				fmt.Fprintf(os.Stderr, "Error enabling detection: %v\n", err)
				return 1
			}
			fmt.Println("Detection enabled:", id)
		}
		if disable {
			if err := detectionStore.Disable(context.Background(), id); err != nil {
				fmt.Fprintf(os.Stderr, "Error disabling detection: %v\n", err)
				return 1
			}
			fmt.Println("Detection disabled:", id)
		}
		return 0
	}

	if format == "json" {
		data, _ := json.MarshalIndent(allRules, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	if len(allRules) == 0 {
		fmt.Println("No detection rules found")
		return 0
	}

	fmt.Printf("%-30s %-8s %-10s %s\n", "NAME", "SEVERITY", "ENABLED", "QUERY")
	fmt.Println(strings.Repeat("-", 80))
	for _, rule := range allRules {
		enabled := "no"
		if rule.Enabled {
			enabled = "yes"
		}
		query := rule.Query
		if len(query) > 30 {
			query = query[:27] + "..."
		}
		fmt.Printf("%-30s %-8s %-10s %s\n", rule.Name, rule.Severity, enabled, query)
	}

	fmt.Printf("\nTotal: %d detections\n", len(allRules))
	return 0
}

func cmdDB(args []string) int {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	var configFile string
	fs := flag.NewFlagSet("db", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	fs.Parse(args)

	cfg := config.DefaultConfig()
	if configFile != "" {
		loaded, err := config.LoadConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return 1
		}
		cfg = loaded
	}

	dbPath := cfg.Database.Path
	if dbPath == "" {
		dbPath = "./data/siem.db"
	}

	db, err := database.Open(dbPath, cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.MaxIdleTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		return 1
	}
	defer database.Shutdown(db)

	if err := database.Migrate(db); err != nil {
		fmt.Fprintf(os.Stderr, "Error running migrations: %v\n", err)
		return 1
	}

	tables := []string{"events", "alerts", "incidents", "detection_rules", "ingestion_sources", "entities", "users"}
	fmt.Println("=== Database Info ===")
	fmt.Printf("Path: %s\n\n", dbPath)

	for _, t := range tables {
		var count int
		err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+t).Scan(&count)
		if err != nil {
			continue
		}
		fmt.Printf("  %-20s %d rows\n", t, count)
	}

	return 0
}

func cmdConfig(args []string) int {
	var (
		configFile string
		show       bool
		writeFile  string
	)
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	fs.BoolVar(&show, "show", false, "show current config")
	fs.StringVar(&writeFile, "write", "", "write default config to file")
	fs.Parse(args)

	cfg := config.DefaultConfig()

	if show {
		if configFile != "" {
			loaded, err := config.LoadConfig(configFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				return 1
			}
			cfg = loaded
		}
		if err := cfg.Save("config.yaml"); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing config: %v\n", err)
			return 1
		}
		fmt.Println("Config written to config.yaml")
		return 0
	}

	if writeFile != "" {
		if err := cfg.Save(writeFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing config: %v\n", err)
			return 1
		}
		fmt.Printf("Default config written to %s\n", writeFile)
		return 0
	}

	fmt.Println("quetzalog config")
	fmt.Println("Usage: quetzalog config --show [--config path] [--write path]")
	return 0
}
