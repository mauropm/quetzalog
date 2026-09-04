package otlp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	v1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	pb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"quetzalog/internal/ingestion"
	"quetzalog/pkg/event"
)

type GRPCConfig struct {
	Port int
}

type GRPCServer struct {
	v1.UnimplementedLogsServiceServer
	pipeline *ingestion.Pipeline
	config   GRPCConfig
	logger   *slog.Logger
	server   *grpc.Server
}

func NewGRPCServer(pipeline *ingestion.Pipeline, config GRPCConfig, logger *slog.Logger) *GRPCServer {
	return &GRPCServer{
		pipeline: pipeline,
		config:   config,
		logger:   logger,
	}
}

func NewGRPCReceiver(pipeline *ingestion.Pipeline, port int, logger *slog.Logger) *GRPCServer {
	return NewGRPCServer(pipeline, GRPCConfig{Port: port}, logger)
}

func (s *GRPCServer) Start(ctx context.Context) error {
	s.server = grpc.NewServer()
	v1.RegisterLogsServiceServer(s.server, s)

	reflection.Register(s.server)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.config.Port, err)
	}

	s.logger.Info("OTLP gRPC server started", "port", s.config.Port)

	go func() {
		if err := s.server.Serve(lis); err != nil {
			s.logger.Error("gRPC server stopped with error", "error", err)
		}
	}()

	return nil
}

func (s *GRPCServer) Stop(ctx context.Context) error {
	s.server.GracefulStop()
	return nil
}

func (s *GRPCServer) Export(ctx context.Context, req *v1.ExportLogsServiceRequest) (*v1.ExportLogsServiceResponse, error) {
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			for _, logRecord := range sl.GetLogRecords() {
				event := s.logToEvent(rl, sl, logRecord)
				if err := s.pipeline.Ingest(ctx, event); err != nil {
					s.logger.Warn("failed to ingest OTLP event", "error", err)
				}
			}
		}
	}

	return &v1.ExportLogsServiceResponse{}, nil
}

func (s *GRPCServer) logToEvent(rl *pb.ResourceLogs, sl *pb.ScopeLogs, logRecord *pb.LogRecord) *event.Event {
	ev := event.NewEvent()

	if logRecord.GetTimeUnixNano() != 0 {
		ev.Timestamp = time.Unix(0, int64(logRecord.GetTimeUnixNano()))
	}

	if logRecord.GetObservedTimeUnixNano() != 0 {
		ev.Attributes["observed_time_unix_nano"] = logRecord.GetObservedTimeUnixNano()
	}

	severityText := pb.SeverityNumber_name[int32(logRecord.SeverityNumber)]
	if severityText != "" {
		ev.Severity = severityText
	}

	if logRecord.SeverityNumber != 0 {
		ev.Attributes["severity_number"] = int32(logRecord.SeverityNumber)
	}

	body := logRecord.GetBody()
	ev.Message = formatAnyValue(body)

	resource := rl.GetResource()
	for _, attr := range resource.GetAttributes() {
		key := attr.GetKey()
		val := attr.GetValue()
		switch key {
		case "service.name":
			ev.Service = val.GetStringValue()
		case "host.name":
			ev.Host = val.GetStringValue()
		default:
			if ev.Attributes == nil {
				ev.Attributes = make(map[string]any)
			}
			ev.Attributes["resource."+key] = val.GetStringValue()
		}
	}

	scope := sl.GetScope()
	if scope != nil {
		if scope.GetName() != "" {
			ev.Attributes["scope.name"] = scope.GetName()
		}
		if scope.GetVersion() != "" {
			ev.Attributes["scope.version"] = scope.GetVersion()
		}
		for _, attr := range scope.GetAttributes() {
			if ev.Attributes == nil {
				ev.Attributes = make(map[string]any)
			}
			ev.Attributes["scope."+attr.GetKey()] = attr.GetValue().GetStringValue()
		}
	}

	for _, attr := range logRecord.GetAttributes() {
		key := attr.GetKey()
		val := attr.GetValue()
		if ev.Attributes == nil {
			ev.Attributes = make(map[string]any)
		}
		ev.Attributes[key] = val.GetStringValue()

		switch key {
		case "http.method":
			ev.Attributes["http_method"] = val.GetStringValue()
		case "http.url":
			ev.Attributes["http_url"] = val.GetStringValue()
		case "http.status_code":
			ev.Attributes["http_status_code"] = val.GetStringValue()
		case "db.statement":
			ev.Attributes["db_statement"] = val.GetStringValue()
		case "error.type":
			ev.EventType = "error"
		case "source.ip":
			ev.SourceIP = val.GetStringValue()
		case "user.name":
			ev.User = val.GetStringValue()
		case "user.id":
			ev.UserID = val.GetStringValue()
		}
	}

	if len(logRecord.TraceId) > 0 {
		ev.TraceID = fmt.Sprintf("%x", logRecord.TraceId)
	}
	if len(logRecord.SpanId) > 0 {
		ev.SpanID = fmt.Sprintf("%x", logRecord.SpanId)
	}

	if et, ok := ev.Attributes["event.type"]; ok {
		if s, ok := et.(string); ok {
			ev.EventType = s
		}
	}
	if cat, ok := ev.Attributes["event.category"]; ok {
		if s, ok := cat.(string); ok {
			ev.Category = s
		}
	}

	return ev
}

func formatAnyValue(av *common.AnyValue) string {
	if av == nil {
		return ""
	}
	if v := av.GetStringValue(); v != "" {
		return v
	}
	if v := av.GetIntValue(); v != 0 {
		return fmt.Sprintf("%d", v)
	}
	if v := av.GetBoolValue(); v {
		return "true"
	}
	if v := av.GetDoubleValue(); v != 0 {
		return fmt.Sprintf("%f", v)
	}
	if v := av.GetBytesValue(); len(v) > 0 {
		return string(v)
	}
	return ""
}
