package telemetry

import (
	"context"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	eventsIngested    atomic.Int64
	eventsRejected    atomic.Int64
	eventsProcessed   atomic.Int64
	ingestionErrors   atomic.Int64
	searchesTotal     atomic.Int64
	detectionsTriggered atomic.Int64
	alertsCreated     atomic.Int64
	ingestDuration    atomic.Int64

	server *http.Server
}

var (
	EventsIngested     = prometheus.NewCounter(prometheus.CounterOpts{Name: "siem_events_ingested_total"})
	EventsRejected     = prometheus.NewCounter(prometheus.CounterOpts{Name: "siem_events_rejected_total"})
	EventsProcessed    = prometheus.NewCounter(prometheus.CounterOpts{Name: "siem_events_processed_total"})
	IngestionErrors    = prometheus.NewCounter(prometheus.CounterOpts{Name: "siem_ingestion_errors_total"})
	SearchesTotal      = prometheus.NewCounter(prometheus.CounterOpts{Name: "siem_searches_total"})
	DetectionsTriggered = prometheus.NewCounter(prometheus.CounterOpts{Name: "siem_detections_triggered_total"})
	AlertsCreated      = prometheus.NewCounter(prometheus.CounterOpts{Name: "siem_alerts_created_total"})
	IngestDuration     = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "siem_ingest_duration_seconds",
		Help:    "Duration of ingestion in seconds",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	})
	SearchDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "siem_search_duration_seconds",
		Help:    "Duration of search in seconds",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
	})
	DatabaseSizeBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "siem_database_size_bytes",
		Help: "Size of the SQLite database in bytes",
	})
	EventsPerSecond = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "siem_events_per_second",
		Help: "Current events per second rate",
	})
	SearchResultsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "siem_search_results_total",
	})
)

func init() {
	prometheus.MustRegister(EventsIngested, EventsRejected, EventsProcessed,
		IngestionErrors, SearchesTotal, DetectionsTriggered, AlertsCreated,
		IngestDuration, SearchDuration, DatabaseSizeBytes, EventsPerSecond, SearchResultsTotal)
}

func New() *Metrics {
	return &Metrics{}
}

func (m *Metrics) RegisterHTTP(addr string) *http.Server {
	m.server = &http.Server{
		Addr:    addr,
		Handler: promhttp.Handler(),
	}
	return m.server
}

func (m *Metrics) RecordEventsIngested(n int64) {
	m.eventsIngested.Add(n)
	EventsIngested.Add(float64(n))
}

func (m *Metrics) RecordEventsRejected(n int64) {
	m.eventsRejected.Add(n)
	EventsRejected.Add(float64(n))
}

func (m *Metrics) RecordEventsProcessed(n int64) {
	m.eventsProcessed.Add(n)
	EventsProcessed.Add(float64(n))
}

func (m *Metrics) RecordIngestionError() {
	m.ingestionErrors.Add(1)
	IngestionErrors.Inc()
}

func (m *Metrics) RecordSearch() {
	m.searchesTotal.Add(1)
	SearchesTotal.Inc()
}

func (m *Metrics) RecordSearchDuration(d time.Duration) {
	SearchDuration.Observe(d.Seconds())
}

func (m *Metrics) RecordDetectionsTriggered(n int64) {
	m.detectionsTriggered.Add(n)
	DetectionsTriggered.Add(float64(n))
}

func (m *Metrics) RecordAlertsCreated(n int64) {
	m.alertsCreated.Add(n)
	AlertsCreated.Add(float64(n))
}

func (m *Metrics) RecordIngestDuration(d time.Duration) {
	m.ingestDuration.Add(d.Nanoseconds())
	IngestDuration.Observe(d.Seconds())
}

func (m *Metrics) RecordSearchResults(n int64) {
	SearchResultsTotal.Add(float64(n))
}

func (m *Metrics) SetDatabaseSize(size int64) {
	DatabaseSizeBytes.Set(float64(size))
}

func (m *Metrics) RecordEvent() {
	EventsPerSecond.Inc()
}

func (m *Metrics) StartBackgroundUpdates(ctx context.Context, dbPath string, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.updateRates(dbPath)
			}
		}
	}()
}

func (m *Metrics) updateRates(dbPath string) {
	if dbPath != "" && dbPath != ":memory:" {
		if info, err := os.Stat(dbPath); err == nil {
			DatabaseSizeBytes.Set(float64(info.Size()))
		}
	}
}

func (m *Metrics) Shutdown(ctx context.Context) error {
	if m.server != nil {
		return m.server.Shutdown(ctx)
	}
	return nil
}
