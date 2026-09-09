package ingestion

import (
	"context"
	"log/slog"
	"quetzalog/internal/events"
	"quetzalog/pkg/event"
	"quetzalog/pkg/plugins"
	"sync"
	"time"
)

// Pipeline coordinates the ingestion flow: accepting events from multiple sources,
// enriching them, and persisting them in batches to the event store.
type Pipeline struct {
	store      *events.Store
	enrichers  []plugins.Enricher
	mu         sync.Mutex
	running    bool
	ctx        context.Context
	cancel     context.CancelFunc
	workerChan chan *event.Event
	workers    int
	batchSize  int
	logger     *slog.Logger
	wg         sync.WaitGroup
}

// NewPipeline creates a new ingestion pipeline with the given worker pool size
// and batch size for the underlying event store writes.
func NewPipeline(store *events.Store, workers, batchSize int, logger *slog.Logger) *Pipeline {
	if workers < 1 {
		workers = 1
	}
	if batchSize < 1 {
		batchSize = 1
	}
	return &Pipeline{
		store:      store,
		workerChan: make(chan *event.Event, workers*batchSize),
		workers:    workers,
		batchSize:  batchSize,
		logger:     logger,
	}
}

// Start launches the worker goroutines. Returns an error if the pipeline is already running.
func (p *Pipeline) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	p.ctx, p.cancel = context.WithCancel(ctx)
	p.running = true

	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(p.ctx)
	}

	p.logger.Info("ingestion pipeline started", "workers", p.workers, "batch_size", p.batchSize)
	return nil
}

// Stop gracefully terminates the pipeline, waiting for all in-flight events to be processed.
func (p *Pipeline) Stop(ctx context.Context) error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	cancel := p.cancel
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		return &PipelineError{Reason: "stop cancelled: " + ctx.Err().Error()}
	}

	p.mu.Lock()
	p.ctx = nil
	p.cancel = nil
	p.mu.Unlock()

	p.logger.Info("ingestion pipeline stopped")
	return nil
}

// Ingest accepts a single event into the pipeline. Returns an error if the pipeline is
// not running or if the worker channel is full.
func (p *Pipeline) Ingest(ctx context.Context, e *event.Event) error {
	if e == nil {
		return &PipelineError{Reason: "nil event"}
	}

	p.mu.Lock()
	running := p.running
	pipelineCtx := p.ctx
	p.mu.Unlock()

	if !running {
		return &PipelineError{Reason: "pipeline not running"}
	}

	select {
	case p.workerChan <- e:
		return nil
	case <-ctx.Done():
		return &PipelineError{Reason: "ingest cancelled: " + ctx.Err().Error()}
	case <-pipelineCtx.Done():
		return &PipelineError{Reason: "pipeline stopped"}
	default:
		return &PipelineError{Reason: "pipeline buffer full"}
	}
}

// IngestBatch accepts multiple events into the pipeline. Each event is sent to the
// worker channel individually. Returns the number of accepted events and a list of errors.
func (p *Pipeline) IngestBatch(ctx context.Context, events []*event.Event) error {
	if len(events) == 0 {
		return nil
	}

	p.mu.Lock()
	running := p.running
	pipelineCtx := p.ctx
	p.mu.Unlock()

	if !running {
		return &PipelineError{Reason: "pipeline not running"}
	}

	var errs []error
	for _, e := range events {
		if e == nil {
			continue
		}
		select {
		case p.workerChan <- e:
		case <-ctx.Done():
			errs = append(errs, &PipelineError{Reason: "batch ingest cancelled: " + ctx.Err().Error()})
		case <-pipelineCtx.Done():
			errs = append(errs, &PipelineError{Reason: "pipeline stopped"})
		default:
			errs = append(errs, &PipelineError{Reason: "pipeline buffer full"})
		}
	}

	if len(errs) > 0 {
		return &BatchIngestError{Errors: errs, Accepted: int64(len(events) - len(errs))}
	}
	return nil
}

// AddEnricher registers an enricher that will be called on every event before
// it is persisted. Enrichers are applied in the order they are registered.
func (p *Pipeline) AddEnricher(e plugins.Enricher) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.enrichers = append(p.enrichers, e)
}

// processEvent runs all registered enrichers on the event without persisting.
// Persistence is deliberately owned by the batch writer.
func (p *Pipeline) processEvent(ctx context.Context, e *event.Event) error {
	for _, enricher := range p.enrichers {
		if err := enricher.Enrich(ctx, e); err != nil {
			p.logger.Warn("enricher returned error", "enricher", enricher.Name(), "event_id", e.ID, "error", err)
		}
	}
	return nil
}

// worker is the main event processing loop. It reads events from the worker channel,
// batch collects them, and writes them to the store.
func (p *Pipeline) worker(ctx context.Context) {
	defer p.wg.Done()

	batch := make([]*event.Event, 0, p.batchSize)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.drainWorkerChan(batch)
			return
		case e, ok := <-p.workerChan:
			if !ok {
				p.flushBatch(ctx, batch)
				return
			}
			if err := p.processEvent(context.Background(), e); err != nil {
				p.logger.Error("failed to process event", "event_id", e.ID, "error", err)
			}
			batch = append(batch, e)
			if len(batch) >= p.batchSize {
				p.flushBatch(ctx, batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				p.flushBatch(ctx, batch)
				batch = batch[:0]
			}
		}
	}
}

// drainWorkerChan consumes any events still present when the pipeline is stopping.
func (p *Pipeline) drainWorkerChan(batch []*event.Event) {
	drained := false
	for {
		select {
		case e, ok := <-p.workerChan:
			if !ok {
				p.flushBatch(context.Background(), batch)
				return
			}
			drained = true
			if err := p.processEvent(context.Background(), e); err != nil {
				p.logger.Error("failed to process event", "event_id", e.ID, "error", err)
			}
			batch = append(batch, e)
			if len(batch) >= p.batchSize {
				p.flushBatch(context.Background(), batch)
				batch = batch[:0]
			}
		default:
			if drained {
				p.flushBatch(context.Background(), batch)
			} else {
				p.flushBatch(context.Background(), batch)
			}
			return
		}
	}
}

// flushBatch writes the accumulated batch to the store and clears it.
func (p *Pipeline) flushBatch(_ context.Context, batch []*event.Event) {
	if len(batch) == 0 {
		return
	}

	// Accepted events must still be persisted during shutdown. The worker
	// context is used only to stop accepting additional work, not to cancel
	// writes for work that was already admitted.
	if err := p.store.CreateBatch(context.Background(), batch); err != nil {
		p.logger.Error("failed to flush batch", "count", len(batch), "error", err)
	} else {
		p.logger.Debug("flushed batch", "count", len(batch))
	}
}

// getWorkerCount returns the number of worker goroutines in the pipeline.
func (p *Pipeline) getWorkerCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.workers
}

// PipelineError represents an error that occurred during pipeline processing.
type PipelineError struct {
	Reason string
}

func (e *PipelineError) Error() string {
	return "pipeline error: " + e.Reason
}

// BatchIngestError represents partial failure during batch ingestion.
type BatchIngestError struct {
	Accepted int64
	Errors   []error
}

func (e *BatchIngestError) Error() string {
	return "batch ingest: " + itoa(int(e.Accepted)) + " accepted, " + itoa(len(e.Errors)) + " failed"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	n := i
	if n < 0 {
		n = -n
	}
	var buf [32]byte
	idx := len(buf)
	for n > 0 || idx == len(buf) {
		idx--
		buf[idx] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[idx:])
}
