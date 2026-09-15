package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"quetzalog/internal/ai"
	"quetzalog/internal/alerts"
	"quetzalog/internal/api"
	"quetzalog/internal/assets"
	"quetzalog/internal/attackgraph"
	"quetzalog/internal/auth"
	"quetzalog/internal/config"
	"quetzalog/internal/correlation"
	"quetzalog/internal/coverage"
	"quetzalog/internal/database"
	"quetzalog/internal/detections"
	"quetzalog/internal/enrichment"
	"quetzalog/internal/entities"
	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/internal/graph"
	"quetzalog/internal/incidents"
	"quetzalog/internal/ingestion"
	"quetzalog/internal/ingestion/file"
	"quetzalog/internal/ingestion/hec"
	ingestjson "quetzalog/internal/ingestion/json"
	"quetzalog/internal/ingestion/otlp"
	"quetzalog/internal/ingestion/syslog"
	"quetzalog/internal/investigations"
	"quetzalog/internal/mitre"
	"quetzalog/internal/query"
	"quetzalog/internal/response"
	"quetzalog/internal/risk"
	"quetzalog/internal/telemetry"
	"quetzalog/internal/threatintel"
	"quetzalog/internal/web"
	"quetzalog/pkg/event"

	"golang.org/x/term"
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

	// FlagSet.Args() on the un-parsed root set returns the full argv
	// (["prog", "subcmd", ...]); subcommand flag sets stop parsing at their
	// first positional arg, so they must receive argv after the subcommand.
	subArgs := func() []string {
		if len(os.Args) > 2 {
			return os.Args[2:]
		}
		return nil
	}

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
		return cmdDemo(subArgs())
	case "ingest":
		return cmdIngest(subArgs())
	case "search":
		return cmdSearch(subArgs())
	case "alerts":
		return cmdAlerts(subArgs())
	case "incidents":
		return cmdIncidents(subArgs())
	case "sources":
		return cmdSources(subArgs())
	case "detections":
		return cmdDetections(subArgs())
	case "db":
		return cmdDB(subArgs())
	case "user":
		return cmdUser(subArgs())
	case "config":
		return cmdConfig(subArgs())
	default:
		writeUsage(fs)
		return 1
	}
}

// parseMixed parses flags in any order relative to positional arguments
// (e.g. `search <query> --limit 5` or `--enable <id> --config c`). The
// flag package stops at the first positional, so collect positionals and
// resume flag parsing after each one.
func parseMixed(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for len(args) > 0 {
		fs.Parse(args)
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	return positional
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
	fmt.Fprintf(os.Stderr, "  user        Manage user accounts (user set-admin)\n")
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
	findingStore := findings.NewStore(db)
	investigationStore := investigations.NewStore(db)
	entityRiskStore := risk.NewEntityRiskStore(db)
	searchSvc := query.NewService(db)
	authStore := auth.NewStore(db)
	responseRegistry := response.NewRegistry(db, response.Deps{
		Findings:       findingStore,
		Investigations: investigationStore,
		Risk:           entityRiskStore,
	})
	aiStore := ai.NewStore(db)
	contextBuilder := ai.NewContextBuilder(findingStore, eventStore)
	assetsStore := assets.NewStore(db)
	if cfg.Assets.Enabled {
		// Observed-draft asset creation: the first event naming a host
		// auto-creates a draft asset (synchronous, bounded, non-fatal —
		// the events store swallows observer errors).
		eventStore.AddObserver(func(ev *event.Event) {
			if ev == nil || ev.Host == "" {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _, _ = assetsStore.Observe(ctx, "host", "host:"+ev.Host, ev.Host, "", ev.Timestamp)
		})
	}
	entitiesStore := entities.NewStore(db)
	graphLayer := graph.NewGraph(db)
	if cfg.Entities.Enabled {
		// V2 entity extraction/resolution on the write path: typed entity
		// upserts, host-ip alias candidates, observed relationship
		// provenance (synchronous, bounded, non-fatal).
		resolver := entities.NewResolver(eventStore.Graph(), entitiesStore)
		eventStore.AddObserver(func(ev *event.Event) {
			if ev == nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			resolver.FromEvent(ctx, ev)
		})
	}
	if cfg.Risk.EventScoring.Enabled {
		// Per-event risk contributions: severity base + asset criticality
		// + identity privilege, recorded explainably (synchronous, bounded,
		// non-fatal).
		eventScorer := risk.NewEventScorer(entityRiskStore, assetsStore, entitiesStore)
		eventStore.AddObserver(func(ev *event.Event) {
			if ev == nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _ = eventScorer.ScoreEvent(ctx, ev)
		})
	}
	coverageStore := coverage.NewStore(db)
	coverageRunner := coverage.NewRunner(db, assetsStore, coverageStore, logger, cfg.TelemetryCoverage.Freshness)
	if cfg.TelemetryCoverage.Enabled {
		go coverageRunner.Start(context.Background(), cfg.TelemetryCoverage.Interval)
	}
	// Threat intelligence: indicator store + provider registry. External
	// feeds are untrusted input; the internal provider is the built-in
	// store (analyst-created indicators).
	tiStore := threatintel.NewStore(db)
	tiRegistry := threatintel.NewRegistry(tiStore)
	for _, p := range cfg.ThreatIntelligence.Providers {
		if !p.Enabled {
			continue
		}
		switch p.Type {
		case "internal":
			tiRegistry.Register(threatintel.NewInternalProvider(tiStore))
		case "abusech":
			tiRegistry.Register(threatintel.NewAbuseChProvider(threatintel.AbuseChConfig{
				UserAgent: "quetzalog-threatintel/1.0",
			}))
		}
	}
	// MITRE event→technique mapping: async worker writing mitre.attack
	// attributes (embedded rules, runtime-extensible via API).
	mitreMapper, err := mitre.NewMapper()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading mitre mapping rules: %v\n", err)
		return 1
	}
	if cfg.Mitre.Enabled && cfg.Mitre.EventMapping {
		eventMapper := mitre.NewEventMapper(mitreMapper, db, logger)
		eventMapper.Start(2)
		defer eventMapper.Stop()
		eventStore.AddObserver(eventMapper.Enqueue)
	}
	// Correlation engine: online evaluation of sequence + correlation
	// rules on the event stream (bounded queue, off the write path).
	// Scheduled detection runs remain the safety net (state pruning).
	correlationEngine := detections.NewCorrelationEngine(db, detectionStore, eventStore, findingStore, entityRiskStore, func(msg string, kv ...any) {
		logger.Info(msg, kv...)
	})
	correlationEngine.Start(2)
	defer correlationEngine.Stop()
	eventStore.AddObserver(correlationEngine.Enqueue)
	go func() {
		sweep := time.NewTicker(15 * time.Minute)
		defer sweep.Stop()
		for range sweep.C {
			if n, err := correlationEngine.Sweep(context.Background()); err != nil {
				logger.Warn("correlation state sweep", "error", err)
			} else if n > 0 {
				logger.Info("correlation state sweep", "pruned", n)
			}
		}
	}()
	// Behavioral analysis: rolling baselines (hourly) + anomaly scoring on
	// the event stream. Default off; when enabled, baselines are computed
	// hourly and statistical/behavioral rules score against trusted baselines.
	if cfg.BehavioralAnalysis.Enabled {
		baselineInterval := cfg.BehavioralAnalysis.UpdateInterval
		if baselineInterval <= 0 {
			baselineInterval = time.Hour
		}
		updater := detections.NewBaselineUpdater(db, func(msg string, kv ...any) {
			logger.Info(msg, kv...)
		})
		go func() {
			t := time.NewTicker(baselineInterval)
			defer t.Stop()
			// Initial computation on start.
			if err := updater.UpdateAll(context.Background(), time.Now().UTC()); err != nil {
				logger.Warn("baseline update", "error", err)
			}
			for range t.C {
				if err := updater.UpdateAll(context.Background(), time.Now().UTC()); err != nil {
					logger.Warn("baseline update", "error", err)
				}
			}
		}()
		behavioralEngine := detections.NewBehavioralEngine(db, detectionStore, findingStore, entityRiskStore, func(msg string, kv ...any) {
			logger.Info(msg, kv...)
		})
		behavioralEngine.Start(2)
		defer behavioralEngine.Stop()
		eventStore.AddObserver(behavioralEngine.Enqueue)
	}
	// Threat scenarios: async evaluator opening/advancing attack-chain
	// runs from mapped events + telemetry coverage. Default off.
	scenarioEvaluator := detections.NewScenarioEvaluator(db, eventStore, findingStore, assetsStore, coverageStore, func(msg string, kv ...any) {
		logger.Info(msg, kv...)
	})
	if cfg.Scenarios.Enabled {
		scenInterval := cfg.Scenarios.EvaluateInterval
		if scenInterval <= 0 {
			scenInterval = time.Hour
		}
		go func() {
			if n, err := scenarioEvaluator.Evaluate(context.Background(), time.Now().UTC()); err != nil {
				logger.Warn("scenario evaluate", "error", err)
			} else if n > 0 {
				logger.Info("scenario evaluate", "steps_changed", n)
			}
			t := time.NewTicker(scenInterval)
			defer t.Stop()
			for range t.C {
				if n, err := scenarioEvaluator.Evaluate(context.Background(), time.Now().UTC()); err != nil {
					logger.Warn("scenario evaluate", "error", err)
				} else if n > 0 {
					logger.Info("scenario evaluate", "steps_changed", n)
				}
			}
		}()
	}
	// Attack graph: shared builder for hourly recompute (attack-graph.md §2)
	// and the AI context's bounded graph view.
	agBuilder := attackgraph.NewBuilder(db, assetsStore, coverageStore, logger)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			if n, err := agBuilder.Recompute(context.Background()); err != nil {
				logger.Warn("attack graph recompute", "error", err)
			} else if n > 0 {
				logger.Info("attack graph recompute", "paths", n)
			}
		}
	}()
	if cfg.ThreatIntelligence.Enabled {
		// Indicator enrichment: bounded async queue matching event values
		// against the indicator store (never blocks ingestion).
		tiEnricher := threatintel.NewEnricher(tiStore, entityRiskStore, db, logger)
		tiEnricher.Start(2)
		defer tiEnricher.Stop()
		eventStore.AddObserver(tiEnricher.Enqueue)
		go func() {
			interval := cfg.ThreatIntelligence.SyncInterval
			if interval <= 0 {
				interval = 6 * time.Hour
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range ticker.C {
				if n, errs := tiRegistry.SyncAll(context.Background()); len(errs) > 0 {
					logger.Warn("ti sync", "imported", n, "errors", errs)
				}
			}
		}()
	}
	// Enrich the AI context with asset criticality, telemetry gaps, threat
	// intel, active scenarios and the attack-graph neighborhood for the
	// finding's hosts (bounded read-only lookups; nil when absent).
	contextBuilder.
		WithLogger(logger).
		WithAssets(func(ctx context.Context, host string) *ai.HostAsset {
			a, err := assetsStore.GetByEntityRef(ctx, "host:"+host)
			if err != nil || a == nil {
				return nil
			}
			h := &ai.HostAsset{
				Name:               a.Name,
				EntityType:         a.EntityType,
				OS:                 a.OS,
				Criticality:        a.Criticality,
				Owner:              a.Owner,
				Environment:        a.Environment,
				InternetExposed:    a.InternetExposed,
				DataClassification: a.DataClassification,
			}
			if cov, cerr := coverageRunner.CoverageFor(ctx, a.ID); cerr == nil && cov != nil &&
				(len(cov.Available) > 0 || len(cov.Missing) > 0) {
				h.TelemetryCoverage = &ai.CoveragePct{Pct: cov.CoveragePct, Missing: cov.Missing}
			}
			if vulns, verr := assetsStore.Vulnerabilities(ctx, a.ID); verr == nil {
				for _, v := range vulns {
					h.Vulnerabilities = append(h.Vulnerabilities, ai.VulnBrief{
						CVE:              v.CVE,
						CVSS:             v.CVSS,
						ExploitAvailable: v.ExploitAvailable,
					})
				}
			}
			return h
		}).
		WithThreatIntel(func(ctx context.Context, values []string) []ai.TIHit {
			out := []ai.TIHit{}
			for _, v := range values {
				indicators, err := tiStore.Lookup(ctx, v)
				if err != nil || len(indicators) == 0 {
					continue
				}
				for _, ind := range indicators {
					hit := ai.TIHit{
						Value:       ind.Value,
						Type:        ind.Type,
						Severity:    ind.Severity,
						Description: ind.Description,
						Source:      ind.Source,
						Confidence:  ai.TIConfidence{IndicatorConfidence: ind.Confidence, Corroboration: ind.HitCount},
						FirstSeen:   ind.FirstSeen,
						LastSeen:    ind.LastSeen,
					}
					if srcs, serr := tiStore.SourcesOf(ctx, ind.ID); serr == nil && len(srcs) > 0 {
						var sum float64
						n := 0
						for _, s := range srcs {
							sum += s.Reliability
							n++
							if s.SourceURL != "" {
								hit.References = append(hit.References, s.SourceURL)
							}
						}
						if n > 0 {
							hit.Confidence.SourceReliability = sum / float64(n)
							hit.Confidence.Corroboration = n
						}
					}
					if actors, aerr := tiStore.ActorsOf(ctx, ind.ID, 5); aerr == nil {
						hit.Actors = actors
					}
					if malw, merr := tiStore.MalwareOf(ctx, ind.ID, 5); merr == nil {
						hit.Malware = malw
					}
					out = append(out, hit)
				}
			}
			return out
		}).
		WithScenarios(func(ctx context.Context, host string) *ai.ScenarioBrief {
			runs, err := scenarioEvaluator.ActiveRunsByHost(ctx, host)
			if err != nil || len(runs) == 0 {
				return nil
			}
			run := runs[0]
			sb := &ai.ScenarioBrief{Status: run.Status, OpenedAt: run.OpenedAt}
			var def struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(run.Definition, &def) == nil {
				sb.Name = def.Name
			}
			steps, serr := scenarioEvaluator.Steps(ctx, run.ID)
			if serr == nil {
				for _, s := range steps {
					switch s.Status {
					case "observed":
						sb.Observed = append(sb.Observed, s.Technique)
					case "expected":
						sb.ExpectedNext = append(sb.ExpectedNext, s.Technique)
					case "unknown":
						sb.Unknown = append(sb.Unknown, s.Technique+" — telemetry insufficient")
					}
				}
			}
			return sb
		}).
		WithAttackGraph(func(ctx context.Context, hosts []string) *ai.AttackGraphBrief {
			brief, err := agBuilder.GraphBrief(ctx, hosts, 25)
			if err != nil || brief == nil {
				return nil
			}
			return &ai.AttackGraphBrief{
				CompromisedNodes: brief.CompromisedNodes,
				AtRiskNodes:      brief.AtRiskNodes,
				Edges: func() []ai.GraphEdge {
					out := []ai.GraphEdge{}
					for _, e := range brief.Edges {
						out = append(out, ai.GraphEdge{From: e.From, To: e.To, Relation: e.Relation, State: e.State})
					}
					return out
				}(),
			}
		}).
		WithPriorAnalyses(func(ctx context.Context, findingIDs []string) []ai.PriorAnalysis {
			prior, err := aiStore.PriorAnalyses(ctx, findingIDs, 5)
			if err != nil {
				return nil
			}
			return prior
		})
	aiService := ai.NewService(&cfg, cfgFile, aiStore, findingStore, contextBuilder, logger)
	// New findings materialized by the detection engine are offered to the
	// AI Analyst (no-op unless enabled; the service runs it asynchronously).
	detectionStore.SetOnNewFinding(aiService.OnFindingCreated)
	geoEnricher, _ := enrichment.BuildGeoIPEnricher(enrichment.GeoIPConfig{Enabled: false})
	_ = enrichment.NewCompositeEnricher([]enrichment.Enricher{
		enrichment.NewLocalIPEnricher(),
		geoEnricher,
	})
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
	apiHandler, err := api.SetupRouter(cfg, eventStore, searchSvc, alertStore, incidentStore, detectionStore, findingStore, investigationStore, entityRiskStore, responseRegistry, authStore, aiStore, aiService, assetsStore, entitiesStore, graphLayer, coverageRunner, tiStore, tiRegistry, mitreMapper, correlationEngine, scenarioEvaluator, logger)
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
	mux.Handle("/", web.Setup())

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Bind up front so a busy port fails the start instead of leaving
	// a half-armed process serving only its auxiliary listeners.
	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		logger.Error("SIEM server bind failed", "addr", server.Addr, "error", err)
		return 1
	}

	if debug {
		fmt.Printf("Starting SIEM server on %s\n", server.Addr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Detections.Scheduled {
		go runDetectionScheduler(ctx, cfg.Detections.Interval, detectionStore, eventStore, findingStore, entityRiskStore, logger)
	}

	errChan := make(chan error, 1)

	go func() {
		logger.Info("SIEM server starting", "addr", server.Addr)
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
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

	// The JSON ingestor binds :8081 unconditionally, so keep metrics off that port.
	metricsPort := cfg.Server.Port + 1
	if metricsPort == 8081 {
		metricsPort = cfg.Server.Port + 2
	}
	metricsAddr := fmt.Sprintf(":%d", metricsPort)
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
// seedScenarioEvents builds the scripted attack chain: two geo-anomalous
// failed logins, a successful login from the same foreign IP, encoded
// PowerShell, SMB lateral movement and a large outbound transfer.
func seedScenarioEvents(now time.Time) []*event.Event {
	attackerIP := "185.220.101.47"
	workstationIP := "10.20.30.40"
	fileSrvIP := "10.20.30.60"

	mk := func(age time.Duration, fn func(e *event.Event)) *event.Event {
		e := event.NewEvent()
		e.Timestamp = now.Add(-age)
		fn(e)
		return e
	}

	return []*event.Event{
		mk(3*time.Hour, func(e *event.Event) {
			e.Source, e.Severity = "sshd", "warning"
			e.EventType, e.Action, e.Outcome = "authentication", "login_failed", "failure"
			e.User, e.Host = "jsmith", "workstation-42"
			e.SourceIP, e.DestinationIP = attackerIP, "10.0.0.5"
			e.Message = "Failed password for jsmith from 185.220.101.47 (geo: RU)"
			e.Attributes["geo_anomaly"] = "true"
			e.Attributes["geo_country"] = "RU"
		}),
		mk(2*time.Hour, func(e *event.Event) {
			e.Source, e.Severity = "sshd", "warning"
			e.EventType, e.Action, e.Outcome = "authentication", "login_failed", "failure"
			e.User, e.Host = "jsmith", "workstation-42"
			e.SourceIP, e.DestinationIP = attackerIP, "10.0.0.5"
			e.Message = "Failed password for jsmith from 185.220.101.47 (geo: RU)"
			e.Attributes["geo_anomaly"] = "true"
			e.Attributes["geo_country"] = "RU"
		}),
		mk(110*time.Minute, func(e *event.Event) {
			e.Source, e.Severity = "sshd", "notice"
			e.EventType, e.Action, e.Outcome = "authentication", "login_success", "success"
			e.User, e.Host = "jsmith", "workstation-42"
			e.SourceIP, e.DestinationIP = attackerIP, "10.0.0.5"
			e.Message = "Accepted publickey for jsmith from 185.220.101.47"
			e.Attributes["geo_anomaly"] = "true"
		}),
		mk(100*time.Minute, func(e *event.Event) {
			e.Source, e.Severity = "windows", "err"
			e.EventType, e.Action = "process", "process_creation"
			e.User, e.Host = "jsmith", "workstation-42"
			e.SourceIP, e.DestinationIP = workstationIP, workstationIP
			e.Process = "powershell.exe"
			e.Message = `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand QwBzACA...`
			e.Attributes["encoded_command"] = "true"
		}),
		mk(90*time.Minute, func(e *event.Event) {
			e.Source, e.Severity = "smb", "warning"
			e.EventType, e.Action = "network", "smb_session"
			e.User = "jsmith"
			e.Host = "file-srv-01"
			e.SourceIP, e.DestinationIP = workstationIP, fileSrvIP
			e.Message = "SMB session established to \\\\file-srv-01\\admin$"
		}),
		mk(75*time.Minute, func(e *event.Event) {
			e.Source, e.Severity = "auditd", "err"
			e.EventType, e.Action = "file_access", "directory_traversal"
			e.User, e.Host = "jsmith", "file-srv-01"
			e.SourceIP, e.DestinationIP = fileSrvIP, fileSrvIP
			e.FilePath = "\\\\file-srv-01\\finance\\q3"
			e.Message = "Directory traversal on sensitive share by jsmith"
		}),
		mk(60*time.Minute, func(e *event.Event) {
			e.Source, e.Severity = "firewall", "critical"
			e.EventType, e.Action, e.Outcome = "data_exfil", "outbound_transfer", "failure"
			e.User, e.Host = "jsmith", "file-srv-01"
			e.SourceIP, e.DestinationIP = fileSrvIP, attackerIP
			e.DestinationPort = 443
			e.Message = "Outbound HTTPS transfer 4.0 GB from file-srv-01 to 185.220.101.47"
			e.Attributes["exfil_suspect"] = "true"
			e.Attributes["bytes_transferred"] = "4294967296"
		}),
	}
}

// runDetectionScheduler evaluates enabled detection rules on a fixed interval
// and materializes findings. It is an in-process ticker: a single SIEM process
// is the unit of deployment, so no distributed scheduler is required.
func runDetectionScheduler(ctx context.Context, interval time.Duration, detectionStore *detections.Store, eventStore *events.Store, findingStore *findings.Store, riskStore *risk.EntityRiskStore, logger *slog.Logger) {
	if interval < time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	logger.Info("detection scheduler started", "interval", interval.String())

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rules, err := detectionStore.List(ctx)
			if err != nil {
				logger.Warn("detection scheduler: list rules", "error", err)
				continue
			}
			for _, rule := range rules {
				if !rule.Enabled || rule.Suppressed {
					continue
				}
				result, err := detectionStore.RunWithFindings(ctx, rule, eventStore, findingStore, riskStore)
				if err != nil {
					logger.Warn("detection scheduler: rule failed", "rule", rule.Name, "error", err)
					continue
				}
				if result.Created > 0 {
					logger.Info("detection scheduler: new findings", "rule", rule.Name, "created", result.Created, "matched", result.Matched)
				}
			}
		}
	}
}

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

func cmdDemo(args []string) int {
	var (
		configFile string
		reset      bool
	)
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	fs.BoolVar(&reset, "reset", false, "delete the database first so each run starts clean")
	parseMixed(fs, args)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	fmt.Println("=== Quetzalog Demo ===")
	fmt.Println()
	fmt.Println(` ███  █   █ █████ █████ █████  ███  █      ███   ███
█   █ █   █ █       █      █  █   █ █     █   █ █
█ █ █ █   █ ████    █     █   █████ █     █   █ █ ███
█  ██ █   █ █       █    █    █   █ █     █   █ █   █
 ████  ███  █████   █   █████ █   █ █████  ███   ████`)
	fmt.Println()

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
	if reset && dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file::memory:") {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if err := os.Remove(dbPath + suffix); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Error removing %s%s: %v\n", dbPath, suffix, err)
				return 1
			}
		}
		fmt.Printf("Reset database: %s\n", dbPath)
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
	hardenDataFiles(dbPath)

	eventStore := events.NewStore(db)
	alertStore := alerts.NewStore(db)
	detectionStore := detections.NewStore(db)
	findingStore := findings.NewStore(db)
	investigationStore := investigations.NewStore(db)
	entityRiskStore := risk.NewEntityRiskStore(db)
	authStore := auth.NewStore(db)

	sources := []string{"sshd", "httpd", "firewall", "auth", "kernel", "nginx", "postgres"}
	severities := []string{"debug", "info", "notice", "warning", "err", "critical", "emergency"}
	eventTypes := []string{"authentication", "network", "file_access", "process", "policy", "intrusion_attempt", "brute_force", "data_exfil"}
	hosts := []string{"web01", "db01", "fw01", "auth01", "app01", "mail01", "proxy01"}
	users := []string{"admin", "root", "deploy", "www-data", "postgres", "backup", "unknown", "attacker"}

	fmt.Println("Generating ~200 synthetic security events (random order)...")

	batch := make([]*event.Event, 0, 20)
	now := time.Now()

	// Shuffled iteration: the same 200-event dataset is ingested in a
	// different order on every run.
	for _, i := range rand.Perm(200) {
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

	// A scripted, deterministic attack chain so the SOC pages (queue,
	// investigations, risk, MITRE, intel) have a coherent story to show:
	// credential compromise -> encoded PowerShell -> lateral movement -> exfiltration.
	fmt.Println("Seeding attack scenario (jsmith / workstation-42 / 185.220.101.47)...")
	scenario := seedScenarioEvents(now)
	if err := eventStore.CreateBatch(context.Background(), scenario); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating scenario events: %v\n", err)
		return 1
	}
	fmt.Printf("  Seeded %d scenario events\n", len(scenario))

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
			Name:           "Suspicious Logins (Geo Anomaly)",
			Description:    "Failed logins flagged by geo-velocity heuristics",
			Query:          "event_type=authentication action=login_failed geo_anomaly=true",
			Severity:       "high",
			Enabled:        true,
			RiskScore:      35,
			GroupBy:        []string{"user"},
			MITRETactic:    "TA0006",
			MITRETechnique: "T1110",
			Tags:           []string{"credential-access", "scenario"},
			DataSources:    []string{"authentication"},
			Threshold: &detections.Threshold{
				Count:  2,
				Window: "4h",
			},
		},
		{
			Name:           "Encoded PowerShell Execution",
			Description:    "PowerShell launched with an encoded payload (T1059.001)",
			Query:          "event_type=process encoded_command=true",
			Severity:       "high",
			Enabled:        true,
			RiskScore:      40,
			GroupBy:        []string{"host"},
			MITRETactic:    "TA0002",
			MITRETechnique: "T1059.001",
			Tags:           []string{"execution", "defense-evasion", "scenario"},
		},
		{
			Name:           "Lateral Movement via SMB",
			Description:    "SMB session establishment to file services (T1021.002)",
			Query:          "event_type=network action=smb_session",
			Severity:       "medium",
			Enabled:        true,
			RiskScore:      25,
			GroupBy:        []string{"user"},
			MITRETactic:    "TA0008",
			MITRETechnique: "T1021.002",
			Tags:           []string{"lateral-movement", "scenario"},
		},
		{
			Name:           "Large Outbound Exfiltration",
			Description:    "Large outbound transfer from a file server (T1041)",
			Query:          "event_type=data_exfil exfil_suspect=true",
			Severity:       "critical",
			Enabled:        true,
			RiskScore:      50,
			GroupBy:        []string{"destination_ip"},
			MITRETactic:    "TA0010",
			MITRETechnique: "T1041",
			Tags:           []string{"exfiltration", "scenario"},
		},
		{
			Name:        "Intrusion Attempt",
			Description: "Detects potential intrusion attempts",
			Query:       "event_type=intrusion_attempt",
			Severity:    "emergency",
			Enabled:     true,
			RiskScore:   45,
		},
		{
			Name:        "Policy Violation",
			Description: "Detects policy violations",
			Query:       "event_type=policy",
			Severity:    "warning",
			Enabled:     true,
			RiskScore:   10,
		},
	}

	for _, rule := range rules {
		if err := detectionStore.Create(context.Background(), &rule); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating detection rule: %v\n", err)
			return 1
		}
		fmt.Printf("  Added: %s\n", rule.Name)
	}

	// Install the built-in catalog detection entries (spec §41/§54). Each
	// install stamps the catalog version so upgrades are detectable.
	catalogEntries, err := detections.ListCatalog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing detection catalog: %v\n", err)
		return 1
	}
	for i := range catalogEntries {
		entry := &catalogEntries[i]
		if entry.Category != "detection" {
			continue
		}
		installed, err := detectionStore.InstallCatalog(context.Background(), entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error installing catalog entry %s: %v\n", entry.Name, err)
			return 1
		}
		fmt.Printf("  Added: %s (catalog v%d)\n", installed.Name, entry.Version)
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
		result, err := detectionStore.RunWithFindings(context.Background(), rule, eventStore, findingStore, entityRiskStore)
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

		fmt.Printf("  %-30s: %d matched, %d total events, %d new findings\n", rule.Name, result.Matched, result.Total, result.Created)
	}

	fmt.Printf("\nTotal alerts generated: %d\n", totalAlerts)

	// Tie the scenario findings into one investigation so the workbench page
	// has a populated story on first run.
	allFindings, _, err := findingStore.List(context.Background(), findings.Filter{Limit: 50})
	if err == nil && len(allFindings) > 0 {
		scenarioIDs := make([]string, 0, len(allFindings))
		for _, f := range allFindings {
			for _, tag := range f.Tags {
				if tag == "scenario" {
					scenarioIDs = append(scenarioIDs, f.ID)
					break
				}
			}
		}
		if len(scenarioIDs) > 0 {
			in := &investigations.Investigation{
				Title:       "Compromised account: jsmith",
				Description: "Demo scenario: geo-anomalous logins, encoded PowerShell, SMB lateral movement and exfiltration.",
				Severity:    "critical",
				Status:      "in_progress",
				Assignee:    "analyst",
				FindingIDs:  scenarioIDs,
			}
			if err := investigationStore.Create(context.Background(), in); err == nil {
				if _, err := investigationStore.AddNote(context.Background(), &investigations.Note{
					InvestigationID: in.ID,
					Author:          "analyst",
					Body:            "Initial triage: all four detection families hit the same user and workstation chain. Escalating.",
				}); err == nil {
					fmt.Printf("Created demo investigation with %d linked findings\n", len(scenarioIDs))
				}
			}
		}
	}

	if posture, err := findingStore.Posture(context.Background()); err == nil {
		fmt.Printf("\nQueue posture: %d open (%d critical, %d high, %d medium, %d low)\n",
			posture["open"], posture["critical"], posture["high"], posture["medium"], posture["low"])
	}
	if topUsers, err := entityRiskStore.Top(context.Background(), "user", 3); err == nil && len(topUsers) > 0 {
		fmt.Println("Top risk users:")
		for _, u := range topUsers {
			fmt.Printf("  %-12s %6.0f  (%d open findings)\n", u.Value, u.RiskScore, u.Findings)
		}
	}

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

	if _, findingTotal, err := findingStore.List(context.Background(), findings.Filter{Limit: 1}); err == nil {
		fmt.Printf("  Findings:           %d\n", findingTotal)
	}
	if _, invTotal, err := investigationStore.List(context.Background(), investigations.Filter{}); err == nil {
		fmt.Printf("  Investigations:     %d\n", invTotal)
	}

	fmt.Println("\n=== Demo Complete ===")
	fmt.Printf("  Events ingested:    %d\n", count)
	fmt.Printf("  Detection rules:    %d\n", len(allRules))
	fmt.Printf("  Alerts generated:   %d\n", totalAlerts)
	fmt.Printf("  Time:               %s\n", time.Since(now).Round(time.Millisecond))
	fmt.Printf("\nData persisted to %s\n", dbPath)
	fmt.Println("Run 'quetzalog serve' (with the same --config, if any) to browse the SOC overview, analyst queue, investigations, risk, MITRE ATT&CK and entity graph in the web UI.")

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
	ingestTail := parseMixed(fs, args)
	filename := ""
	if len(ingestTail) > 0 {
		filename = ingestTail[0]
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

	if filename != "" {
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
	tail := parseMixed(fs, args)

	q := ""
	if len(tail) > 0 {
		q = tail[0]
	}
	if q == "" {
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
		Query:  q,
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

	// Subcommand: `detections import-sigma <file>` imports a Sigma rule YAML
	// as a detection rule. Unsupported constructs fail with a structured
	// error listing each clause (never a partial import).
	if len(args) > 0 && args[0] == "import-sigma" {
		return cmdDetectionsImportSigma(args[1:])
	}

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
	detTail := parseMixed(fs, args)
	ruleID := ""
	if len(detTail) > 0 {
		ruleID = detTail[0]
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

	detectionStore := detections.NewStore(db)

	allRules, err := detectionStore.List(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing detection rules: %v\n", err)
		return 1
	}

	if enable || disable {
		if ruleID == "" {
			fmt.Fprintf(os.Stderr, "Usage: quetzalog detections --enable/--disable <rule-id>\n")
			return 1
		}
		id := ruleID
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

// cmdDetectionsImportSigma imports a Sigma rule YAML file as a detection rule
// (spec §42). Usage: quetzalog detections import-sigma <file> [--config c].
func cmdDetectionsImportSigma(args []string) int {
	var configFile string
	fs := flag.NewFlagSet("detections import-sigma", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	rest := parseMixed(fs, args)
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: quetzalog detections import-sigma <sigma-rule.yaml> [--config c]")
		return 1
	}
	path := rest[0]

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading sigma file: %v\n", err)
		return 1
	}

	rule, err := detections.ImportSigma(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error importing sigma rule: %v\n", err)
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

	detectionStore := detections.NewStore(db)
	if err := detectionStore.Create(context.Background(), rule); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating detection rule: %v\n", err)
		return 1
	}

	fmt.Printf("Imported Sigma rule:\n")
	fmt.Printf("  Name:      %s\n", rule.Name)
	fmt.Printf("  Severity:  %s\n", rule.Severity)
	fmt.Printf("  Kind:      %s\n", rule.Kind)
	fmt.Printf("  Query:     %s\n", rule.Query)
	if rule.Threshold != nil {
		fmt.Printf("  Threshold: %d in %s\n", rule.Threshold.Count, rule.Threshold.Window)
	}
	if len(rule.Tags) > 0 {
		fmt.Printf("  Tags:      %s\n", strings.Join(rule.Tags, ", "))
	}
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

// readPasswordOnce prompts on the terminal and reads a line without
// echoing the characters, so the password never appears on screen or in
// shell history.
func readPasswordOnce(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		raw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr) // move past the (unseen) input
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return string(raw), nil
	}
	return "", fmt.Errorf("password input requires an interactive terminal (stdin is not a TTY)")
}

// cmdUser manages user accounts. set-admin creates the admin user if it
// does not exist (the demo seed only creates analyst and viewer) or resets
// its password if it does. The password is typed at two prompts — it is
// never taken from the command line, so it stays out of shell history.
func cmdUser(args []string) int {
	var configFile string
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "path to config file")
	positional := parseMixed(fs, args)
	if len(positional) != 1 || positional[0] != "set-admin" {
		fmt.Fprintln(os.Stderr, "Usage: quetzalog user set-admin [--config path]")
		fmt.Fprintln(os.Stderr, "       Creates the admin account if missing, or resets its password.")
		fmt.Fprintln(os.Stderr, "       The password is typed twice at the prompt, without echoing.")
		return 1
	}

	password, err := readPasswordOnce("New password for admin: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if password == "" {
		fmt.Fprintln(os.Stderr, "Error: password must not be empty")
		return 1
	}
	if len(password) < 4 {
		fmt.Fprintln(os.Stderr, "Error: password must be at least 4 characters")
		return 1
	}
	confirm, err := readPasswordOnce("Confirm password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if password != confirm {
		fmt.Fprintln(os.Stderr, "Error: passwords do not match — nothing was changed")
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
	hardenDataFiles(dbPath)

	authStore := auth.NewStore(db)
	ctx := context.Background()
	admin, err := authStore.GetUserByUsername(ctx, "admin")
	switch {
	case err == auth.ErrUserNotFound:
		if err := authStore.CreateUser(ctx, "admin", password, auth.RoleAdmin); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating admin user: %v\n", err)
			return 1
		}
		fmt.Println("Created admin user 'admin' with the new password. Sign in as admin.")
	case err != nil:
		fmt.Fprintf(os.Stderr, "Error looking up admin user: %v\n", err)
		return 1
	default:
		if err := authStore.UpdatePassword(ctx, admin.ID, password); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating admin password: %v\n", err)
			return 1
		}
		fmt.Println("Reset the password of admin user 'admin'. Sign in as admin.")
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
