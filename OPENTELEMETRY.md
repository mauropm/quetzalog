# OpenTelemetry Compatibility

SIEMto accepts OpenTelemetry Protocol (OTLP) log exports, enabling seamless integration
with any OTLP-compatible telemetry agent or SDK.

## Supported OTLP Endpoints

### OTLP HTTP/JSON

**Endpoint:** `POST /v1/logs`
**Content-Type:** `application/json`

Accepts the OTLP JSON encoding format as defined in the OpenTelemetry Protocol Specification.

### OTLP HTTP/Protobuf

**Endpoint:** `POST /v1/logs`
**Content-Type:** `application/x-protobuf`

Accepts the OTLP protobuf encoding. The endpoint accepts requests but the protobuf
parsing is a stub implementation. Full protobuf support requires integrating the
OTLP protobuf library.

## Field Mapping

SIEMto automatically maps OTLP fields to its canonical Event model:

### Resource Attributes

Resource attributes (from the `resource` object) are mapped to event attributes:

| OTLP Field | SIEMto Field | Notes |
|------------|--------------|-------|
| `resource.attributes[i].key="service.name"` | `Event.Attributes["service.name"]` | Standard OpenTelemetry resource attribute |
| `resource.attributes[i].key="host.name"` | `Event.Attributes["host.name"]` | Standard OpenTelemetry resource attribute |
| `resource.attributes[i].key="deployment.environment"` | `Event.Attributes["deployment.environment"]` | Mapped as attribute |
| `resource.attributes[i].key="process.pid"` | `Event.Attributes["process.pid"]` | Mapped as attribute |
| Other custom attributes | `Event.Attributes["<key>"]` | All resource attributes become event attributes |

### Scope Attributes

Scope attributes (from the `scope` object) are mapped similarly:

| OTLP Field | SIEMto Field | Notes |
|------------|--------------|-------|
| `scope.attributes[i].key=<key>` | `Event.Attributes["<key>"]` | Scoped attributes become event attributes |
| `scope.name` | `Event.Source` | Scope name used as source identifier |
| `scope.version` | `Event.Attributes["scope.version"]` | Version mapped as attribute |

### Log Record Fields

| OTLP Field | SIEMto Field | Notes |
|------------|--------------|-------|
| `logRecords[i].body.stringValue` | `Event.Message` | String body -> message |
| `logRecords[i].body.numberValue` | `Event.Attributes["body"]` | Numeric body -> attribute |
| `logRecords[i].body.intValue` | `Event.Attributes["body"]` | Integer body -> attribute |
| `logRecords[i].body.boolValue` | `Event.Attributes["body"]` | Bool body -> attribute |
| `logRecords[i].body.jsonValue` | `Event.Attributes["body"]` | JSON body -> attribute (stored as string) |
| `logRecords[i].severityText` | `Event.Severity` | Mapped to canonical severity |
| `logRecords[i].severityNumber` | `Event.Severity` | Numeric severity mapped to level |
| `logRecords[i].timeUnixNano` | `Event.Timestamp` | Nanosecond Unix timestamp |
| `logRecords[i].observedTimeUnixNano` | `Event.ReceivedAt` | When SIEMto received the event |
| `logRecords[i].attributes[i].key="user"` | `Event.Attributes["user"]` | Log attributes become event attributes |
| `logRecords[i].traceId` | `Event.Attributes["trace_id"]` | Trace ID stored as hex string attribute |
| `logRecords[i].spanId` | `Event.Attributes["span_id"]` | Span ID stored as hex string attribute |

### Severity Mapping

OTLP severity numbers are mapped to SIEMto canonical severity levels:

| OTLP Severity Number | OTLP Severity Text | SIEMto Severity |
|---------------------|---------------------|-----------------|
| 1 | UNSPECIFIED | info |
| 2 | TRACE | debug |
| 3 | DEBUG | debug |
| 4 | INFO | info |
| 5 | INFO_2 | info |
| 6 | WARN | warning |
| 7 | WARN_2 | warning |
| 8 | ERROR | err |
| 9 | ERROR_2 | err |
| 10 | FATAL | critical |
| 11 | FATAL_2 | critical |
| 12+ | (higher) | critical |

Custom severity text (from `severityText`) takes precedence when available.

### Trace Context

Trace and span IDs are automatically stored as event attributes, enabling
correlation between application traces and security events:

- `trace_id` - 32-character hex string (16 bytes)
- `span_id` - 16-character hex string (8 bytes)

## Example OTLP Payload

### JSON Format (HTTP/JSON)

The endpoint accepts the OTLP JSON format. Example payload:

```
{
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          { "key": "service.name", "value": { "stringValue": "auth-service" } },
          { "key": "host.name", "value": { "stringValue": "server01" } }
        ]
      },
      "scopeLogs": [
        {
          "scope": { "name": "auth-service", "version": "1.0.0" },
          "logRecords": [
            {
              "timeUnixNano": "1725392400000000000",
              "severityText": "ERROR",
              "severityNumber": 8,
              "body": { "stringValue": "Failed SSH login for user admin" },
              "attributes": [
                { "key": "user", "value": { "stringValue": "admin" } },
                { "key": "source_ip", "value": { "stringValue": "10.0.0.20" } }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

### Multiple Resources

Multiple resource logs can be sent in a single request:

```
{
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          { "key": "service.name", "value": { "stringValue": "web-frontend" } }
        ]
      },
      "scopeLogs": [
        {
          "scope": { "name": "web-frontend", "version": "2.0.0" },
          "logRecords": [
            {
              "timeUnixNano": "1725392400000000000",
              "severityText": "INFO",
              "body": { "stringValue": "GET /api/login 200 OK" }
            }
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          { "key": "service.name", "value": { "stringValue": "api-backend" } }
        ]
      },
      "scopeLogs": [
        {
          "scope": { "name": "api-backend", "version": "1.5.0" },
          "logRecords": [
            {
              "timeUnixNano": "1725392400000000000",
              "severityText": "ERROR",
              "body": { "stringValue": "Database connection timeout" }
            }
          ]
        }
      ]
    }
  ]
}
```

## cURL Examples

### Send JSON OTLP

```bash
curl -X POST http://localhost:8080/v1/logs \
  -H "Content-Type: application/json" \
  -d '{
    "resourceLogs": [{
      "resource": {
        "attributes": [
          { "key": "service.name", "value": { "stringValue": "my-app" } }
        ]
      },
      "scopeLogs": [{
        "scope": { "name": "my-app", "version": "1.0.0" },
        "logRecords": [{
          "timeUnixNano": "1725392400000000000",
          "severityText": "ERROR",
          "body": { "stringValue": "Something went wrong" }
        }]
      }]
    }]
  }'
```

## Response Format

### JSON Response

```
{
  "partialSuccess": {
    "acceptedLogRecords": 2,
    "rejectedLogRecords": 0
  }
}
```

### Protobuf Response

```
Content-Type: application/x-protobuf

ExportLogsServiceResponse {
  partial_success {
    accepted_log_records: 2
    rejected_log_records: 0
  }
}
```

## Integration Examples

### OTel Collector Configuration

```yaml
receivers:
  filelog/app:
    include: [/var/log/app/*.log]
    start_at: beginning

  filelog/auth:
    include: [/var/log/auth.log]
    start_at: beginning

exporters:
  otlp/quetzalog:
    endpoint: "quetzalog:8080"
    tls:
      insecure: true

service:
  pipelines:
    logs:
      receivers: [filelog/app, filelog/auth]
      exporters: [otlp/quetzalog]
```

### Go OTel SDK

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
    "go.opentelemetry.io/otel/sdk/log"
)

// Create OTLP log exporter
exp, err := otlploghttp.New(ctx,
    otlploghttp.WithEndpoint("localhost:8080"),
    otlploghttp.WithInsecure(),
)

// Create OTel provider
provider := log.NewProvider(
    log.WithProcessor(
        sdklog.NewBatchProcessor(exp),
    ),
)
```

### Python OTel SDK

```python
from opentelemetry import sdk
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import OTLPLogExporter, BatchLogRecordProcessor

# Create OTLP exporter
exporter = OTLPLogExporter(endpoint="http://localhost:8080", insecure=True)

# Create logger provider
provider = LoggerProvider()
provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
```

### Node.js OTel SDK

```javascript
import { OTLPLogExporter } from "@opentelemetry/exporter-logs-otlp-http";
import { LoggerProvider, BatchLogRecordProcessor } from "@opentelemetry/sdk-logs";

const exporter = new OTLPLogExporter({
  url: "http://localhost:8080/v1/logs",
});

const provider = new LoggerProvider();
provider.addLogRecordProcessor(new BatchLogRecordProcessor(exporter));
```

## Future gRPC Support

The OTLP specification also defines a gRPC transport for log exports. This is planned for
future implementation.

### Planned: OTLP/gRPC

**Endpoint:** `POST grpc://localhost:4317/v1/logs`

The gRPC endpoint would use the `opentelemetry.proto.collector.logs.v1.ExportLogsService`
service with the standard `Export` RPC.

**Planned Features:**
- Full gRPC streaming support
- Compression (gzip)
- Connection pooling
- Keepalive configuration
- mTLS support

### Planned gRPC Configuration

```yaml
otlp:
  grpc:
    endpoint: 0.0.0.0:4317
    compression: gzip
    max_message_size: 4194304  # 4MB
    keepalive_time: 30s
    keepalive_timeout: 10s
  http:
    json:
      enabled: true
    protobuf:
      enabled: true  # stub
```

## Supported OTLP Data Models

### Resource Signals
- Resource attributes (all supported)
- Resource telemetry (service.name, host.name)

### Scope Signals
- Scope name (mapped to source)
- Scope version
- Scope attributes

### Log Records
- Body (string, number, int, bool, JSON, map, array)
- Severity text and number
- Attributes (all key-value pairs)
- Trace context (trace_id, span_id, flags)
- Timestamps (timeUnixNano, observedTimeUnixNano)

## Unsupported OTLP Features

- LogRecordBody with array/map values stored as string
- Exemplars on log records
- OTLP traces endpoint (not a SIEM feature)
- OTLP metrics endpoint (separate /metrics path)
- OTLP/gRPC transport (planned)
- OTLP/HTTP protobuf encoding (stub - accepts but does not parse)
