# Quetzalog REST API

Base URL: `http://localhost:8080/api/v1`

All API responses use `application/json` content type unless otherwise specified.

Authentication is handled via API tokens where applicable.

## Table of Contents

- [Authentication](#authentication)
- [Health](#health)
- [Events](#events)
- [Search](#search)
- [Stats](#stats)
- [Alerts](#alerts)
- [Incidents](#incidents)
- [Detections](#detections)
- [SOC Platform](#soc-platform)
- [Splunk HEC Compatibility](#splunk-hec-compatibility)
- [Splunk Search Compatibility](#splunk-search-compatibility)
- [OpenTelemetry Compatibility](#opentelemetry-compatibility)
- [Metrics](#metrics)
- [Error Responses](#error-responses)

---

## Authentication

API endpoints that require authentication use the `Authorization` header:

```
Authorization: Bearer <api-token>
```

Configure API tokens in the YAML configuration file:

```yaml
api:
  tokens:
    - my-api-token
```

---

## Health

### Check Health

```
GET /api/v1/health
```

**Response: 200 OK**

```json
{
  "status": "ok"
}
```

---

## Events

### Ingest Single Event

```
POST /api/v1/events
Content-Type: application/json
```

**Request Body:**

```json
{
  "timestamp": "2026-09-03T18:30:00Z",
  "source": "my-app",
  "host": "server01",
  "severity": "warning",
  "event_type": "authentication",
  "outcome": "failure",
  "message": "Failed SSH login attempt",
  "attributes": {
    "user": "admin",
    "source_ip": "10.0.0.20",
    "method": "password"
  }
}
```

**Response: 200 OK**

```json
{
  "accepted": 1,
  "rejected": 0
}
```

**Field Descriptions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | string (RFC3339) | No | Event timestamp (defaults to now) |
| `source` | string | No | Source identifier |
| `host` | string | No | Source host |
| `severity` | string | No | Severity level (debug, info, warning, err, critical) |
| `event_type` | string | No | Event type/category |
| `outcome` | string | No | Outcome (success, failure, unknown) |
| `message` | string | Yes | Human-readable event message |
| `attributes` | object | No | Key-value attributes |

### Batch Ingest Events

```
POST /api/v1/events/batch
Content-Type: application/json
```

**Request Body:**

```json
{
  "events": [
    {
      "message": "User logged in",
      "source": "auth-service",
      "host": "web01",
      "severity": "info",
      "event_type": "authentication",
      "outcome": "success",
      "attributes": {"user": "john"}
    },
    {
      "message": "Disk usage at 90%",
      "source": "monitoring",
      "host": "db01",
      "severity": "warning",
      "event_type": "system",
      "attributes": {"disk": "/dev/sda1", "usage_pct": 90}
    }
  ]
}
```

**Response: 200 OK**

```json
{
  "accepted": 2,
  "rejected": 0,
  "errors": []
}
```

### List Events

```
GET /api/v1/events?limit=20&offset=0&severity=err&source=auth
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 20 | Maximum number of events to return |
| `offset` | integer | 0 | Number of events to skip |
| `severity` | string | - | Filter by severity level |
| `source` | string | - | Filter by source |
| `host` | string | - | Filter by host |
| `event_type` | string | - | Filter by event type |
| `outcome` | string | - | Filter by outcome |
| `search` | string | - | Full-text search across message and attributes |

**Response: 200 OK**

```json
{
  "events": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "timestamp": "2026-09-03T18:30:00Z",
      "received_at": "2026-09-03T18:30:01Z",
      "source": "auth-service",
      "host": "server01",
      "severity": "error",
      "event_type": "authentication",
      "outcome": "failure",
      "message": "Failed SSH login for user admin from 10.0.0.20",
      "attributes": {
        "user": "admin",
        "source_ip": "10.0.0.20"
      }
    }
  ],
  "count": 1,
  "total": 42
}
```

### Get Single Event

```
GET /api/v1/events/{id}
```

**Response: 200 OK**

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2026-09-03T18:30:00Z",
  "received_at": "2026-09-03T18:30:01Z",
  "source": "auth-service",
  "host": "server01",
  "severity": "error",
  "event_type": "authentication",
  "outcome": "failure",
  "message": "Failed SSH login for user admin from 10.0.0.20",
  "attributes": {
    "user": "admin",
    "source_ip": "10.0.0.20"
  }
}
```

**Response: 404 Not Found**

```json
{
  "error": "event not found"
}
```

---

## Search

### Run SPL-like Query

```
POST /api/v1/search
Content-Type: application/json
```

**Request Body:**

```json
{
  "query": "source=auth | stats count by user",
  "limit": 100
}
```

**Response: 200 OK**

```json
{
  "columns": ["user", "count"],
  "results": [
    {"user": "admin", "count": 15},
    {"user": "john", "count": 3},
    {"user": "jane", "count": 1}
  ],
  "count": 3,
  "query": "source=auth | stats count by user"
}
```

**Request Body Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `query` | string | Yes | SPL-like query string |
| `limit` | integer | No | Maximum results (default: 100, max: 10000) |

See [SPL Compatibility](SPL_COMPATIBILITY.md) for supported commands and syntax.

---

## Stats

### Get System Statistics

```
GET /api/v1/stats
```

**Response: 200 OK**

```json
{
  "total_events": 152847,
  "events_last_hour": 3201,
  "events_last_24h": 48520,
  "events_by_severity": {
    "debug": 12040,
    "info": 89320,
    "warning": 35200,
    "err": 14500,
    "critical": 1787
  },
  "events_by_source": {
    "auth-service": 45200,
    "web-server": 38900,
    "database": 25400,
    "firewall": 18700,
    "monitoring": 24647
  },
  "total_alerts": 142,
  "active_alerts": 38,
  "total_incidents": 27,
  "active_incidents": 5
}
```

---

## Alerts

### List Alerts

```
GET /api/v1/alerts?limit=20&offset=0&severity=high&status=new
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 20 | Maximum alerts to return |
| `offset` | integer | 0 | Number of alerts to skip |
| `severity` | string | - | Filter by severity |
| `status` | string | - | Filter by alert status |
| `detection_id` | string | - | Filter by detection rule ID |

**Response: 200 OK**

```json
{
  "alerts": [
    {
      "id": "alert-001",
      "detection_id": "det-brute-force",
      "detection_name": "Brute Force Detection",
      "severity": "high",
      "status": "new",
      "title": "Brute force attempt detected from 10.0.0.50",
      "description": "5+ failed authentication attempts in 5 minutes",
      "created_at": "2026-09-03T18:30:00Z",
      "updated_at": "2026-09-03T18:30:00Z",
      "event_count": 12,
      "grouped_values": {
        "source_ip": "10.0.0.50"
      }
    }
  ],
  "count": 1,
  "total": 38
}
```

### Get Single Alert

```
GET /api/v1/alerts/{id}
```

**Response: 200 OK**

```json
{
  "id": "alert-001",
  "detection_id": "det-brute-force",
  "detection_name": "Brute Force Detection",
  "severity": "high",
  "status": "new",
  "title": "Brute force attempt detected from 10.0.0.50",
  "description": "5+ failed authentication attempts in 5 minutes",
  "created_at": "2026-09-03T18:30:00Z",
  "updated_at": "2026-09-03T18:30:00Z",
  "event_count": 12,
  "grouped_values": {
    "source_ip": "10.0.0.50"
  },
  "events": [
    {
      "id": "evt-001",
      "message": "Failed SSH login for user admin",
      "timestamp": "2026-09-03T18:25:00Z"
    }
  ]
}
```

### Acknowledge Alert

```
POST /api/v1/alerts/{id}/acknowledge
```

**Response: 200 OK**

```json
{
  "id": "alert-001",
  "status": "acknowledged",
  "updated_at": "2026-09-03T19:00:00Z"
}
```

### Resolve Alert

```
POST /api/v1/alerts/{id}/resolve
```

**Response: 200 OK**

```json
{
  "id": "alert-001",
  "status": "resolved",
  "updated_at": "2026-09-03T19:30:00Z"
}
```

---

## Incidents

### List Incidents

```
GET /api/v1/incidents?limit=20&offset=0&status=new
```

**Response: 200 OK**

```json
{
  "incidents": [
    {
      "id": "inc-001",
      "title": "Suspicious activity from 10.0.0.50",
      "status": "investigating",
      "severity": "high",
      "alert_count": 3,
      "event_count": 45,
      "created_at": "2026-09-03T18:30:00Z",
      "updated_at": "2026-09-03T19:00:00Z",
      "alerts": [
        {"id": "alert-001", "detection_name": "Brute Force"},
        {"id": "alert-002", "detection_name": "Unusual Access Time"},
        {"id": "alert-003", "detection_name": "Privilege Escalation"}
      ]
    }
  ],
  "count": 1,
  "total": 5
}
```

### Create Incident

```
POST /api/v1/incidents
Content-Type: application/json
```

**Request Body:**

```json
{
  "title": "Investigate suspicious activity from 10.0.0.50",
  "alert_ids": ["alert-001", "alert-002", "alert-003"],
  "notes": "Multiple detection rules triggered from the same source IP"
}
```

**Response: 201 Created**

```json
{
  "id": "inc-001",
  "title": "Investigate suspicious activity from 10.0.0.50",
  "status": "new",
  "created_at": "2026-09-03T20:00:00Z"
}
```

### Acknowledge Incident

```
POST /api/v1/incidents/{id}/acknowledge
```

**Response: 200 OK**

```json
{
  "id": "inc-001",
  "status": "investigating",
  "updated_at": "2026-09-03T20:30:00Z"
}
```

---

## Detections

### List Detection Rules

```
GET /api/v1/detections
```

**Response: 200 OK**

```json
{
  "detections": [
    {
      "id": "det-brute-force",
      "name": "Brute Force Detection",
      "query": "source=auth AND outcome=failure",
      "severity": "high",
      "threshold": {
        "count": 5,
        "window": "300s"
      },
      "group_by": "source_ip",
      "enabled": true,
      "created_at": "2026-09-01T10:00:00Z",
      "updated_at": "2026-09-03T12:00:00Z"
    }
  ],
  "count": 1
}
```

### Create Detection Rule

```
POST /api/v1/detections
Content-Type: application/json
```

**Request Body:**

```json
{
  "name": "Brute Force Detection",
  "query": "source=auth AND outcome=failure",
  "severity": "high",
  "threshold": {
    "count": 5,
    "window": "300s"
  },
  "group_by": "source_ip"
}
```

**Response: 201 Created**

```json
{
  "id": "det-brute-force",
  "name": "Brute Force Detection",
  "query": "source=auth AND outcome=failure",
  "severity": "high",
  "threshold": {
    "count": 5,
    "window": "300s"
  },
  "group_by": "source_ip",
  "enabled": true,
  "created_at": "2026-09-03T18:00:00Z",
  "updated_at": "2026-09-03T18:00:00Z"
}
```

### Update Detection Rule

```
PUT /api/v1/detections/{id}
Content-Type: application/json
```

**Request Body:** (omit fields to keep unchanged)

```json
{
  "name": "Brute Force Detection (Updated)",
  "threshold": {
    "count": 10,
    "window": "600s"
  }
}
```

**Response: 200 OK**

### Delete Detection Rule

```
DELETE /api/v1/detections/{id}
```

**Response: 200 OK**

```json
{
  "message": "detection rule deleted"
}
```

### Execute Detection Rule

```
POST /api/v1/detections/{id}/exec
Content-Type: application/json
```

**Request Body:**

```json
{
  "start_time": "2026-09-03T00:00:00Z",
  "end_time": "2026-09-03T23:59:59Z"
}
```

**Response: 200 OK**

```json
{
  "detection_id": "det-brute-force",
  "detection_name": "Brute Force Detection (Updated)",
  "results": [
    {
      "grouped_values": {"source_ip": "10.0.0.50"},
      "event_count": 15,
      "threshold_exceeded": true,
      "first_event": "2026-09-03T14:00:00Z",
      "last_event": "2026-09-03T14:05:00Z"
    },
    {
      "grouped_values": {"source_ip": "10.0.0.51"},
      "event_count": 8,
      "threshold_exceeded": true,
      "first_event": "2026-09-03T15:00:00Z",
      "last_event": "2026-09-03T15:02:00Z"
    }
  ],
  "alerts_triggered": 2
}
```

---

## Splunk HEC Compatibility

### Send Events via HEC

```
POST /services/collector
Authorization: Splunk <hec-token>
Content-Type: application/json
```

**Single Event:**

```json
{
  "event": {
    "message": "User john logged in successfully",
    "host": "web01",
    "source": "auth-service",
    "sourcetype": "auth:login",
    "index": "security"
  },
  "time": 1756900000.0
}
```

**Batch Events:**

```json
{
  "events": [
    {
      "event": {"message": "Event 1", "host": "server01"},
      "time": 1756900000
    },
    {
      "event": {"message": "Event 2", "host": "server02"},
      "time": 1756900001
    }
  ]
}
```

**Response: 200 OK**

```json
{
  "text": "OK",
  "code": 0
}
```

**Rejection Response:**

```json
{
  "text": "Invalid authentication",
  "code": 9
}
```

### Raw Text Ingestion

```
POST /services/collector/raw
Authorization: Splunk <hec-token>
```

**Request Body:** Plain text string

**Response: 200 OK**

```json
{
  "text": "OK",
  "code": 0
}
```

### HEC Token via Query Parameter

```
POST /services/collector?token=<hec-token>
```

---

## Splunk Search Compatibility

### List Search Jobs

```
GET /services/search/jobs
```

**Response: 200 OK**

```json
{
  "searchjobs": [
    {
      "sid": "1756900000.12345",
      "dispatchTime": "2026-09-03T18:30:00Z",
      "ready": true,
      "isDone": true,
      "isDoneSearch": true,
      "resultsAvailableTime": "2026-09-03T18:30:01Z"
    }
  ]
}
```

### Get Search Status

```
GET /services/search/jobs/{sid}
```

**Response: 200 OK**

```json
{
  "sid": "1756900000.12345",
  "dispatchTime": "2026-09-03T18:30:00Z",
  "ready": true,
  "isDone": true,
  "isDoneSearch": true,
  "totalProgress": 100,
  "elapsedTime": 0.847,
  "resultsAvailableTime": "2026-09-03T18:30:01Z"
}
```

### Get Search Results

```
GET /services/search/jobs/{sid}/results?output_mode=json&count=100&offset=0
```

**Response: 200 OK**

```json
{
  "results": [
    {"user": "admin", "count": "15"},
    {"user": "john", "count": "3"}
  ],
  "meta": {
    "fields": ["user", "count"],
    "total": 42,
    "returned": 2
  }
}
```

---

## OpenTelemetry Compatibility

### Ingest OTLP Logs (JSON)

```
POST /v1/logs
Content-Type: application/json
```

**JSON Format Request Body:**

The endpoint accepts the OTLP JSON format as defined in the OpenTelemetry Protocol specification.

```json
{
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          {"key": "service.name", "value": {"stringValue": "my-app"}},
          {"key": "host.name", "value": {"stringValue": "server01"}}
        ]
      },
      "scopeLogs": [
        {
          "scope": {
            "name": "my-scope",
            "version": "1.0.0"
          },
          "logRecords": [
            {
              "timeUnixNano": "1725392400000000000",
              "severityText": "ERROR",
              "body": {"stringValue": "Failed SSH login for user admin from 10.0.0.20"},
              "attributes": [
                {"key": "user", "value": {"stringValue": "admin"}},
                {"key": "source_ip", "value": {"stringValue": "10.0.0.20"}}
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

**Response: 200 OK**

```json
{
  "partialSuccess": {
    "acceptedLogRecords": 1,
    "rejectedLogRecords": 0
  }
}
```

### Ingest OTLP Logs (Protobuf)

```
POST /v1/logs
Content-Type: application/x-protobuf
```

**Request Body:** Binary OTLP protobuf encoded `ExportLogsServiceRequest`

**Response: 200 OK**

```
Content-Type: application/x-protobuf

ExportLogsServiceResponse {
  partial_success {
    accepted_log_records: 1
    rejected_log_records: 0
  }
}
```

> **Note:** Protobuf encoding support is a stub. The endpoint accepts the request but requires
> proper protobuf library integration for production use.

---

## Metrics

### Prometheus Metrics

```
GET /metrics
```

**Response: 200 OK** (Prometheus text format)

```
# HELP quetzalog_events_total Total number of events ingested
# TYPE quetzalog_events_total counter
quetzalog_events_total 152847

# HELP quetzalog_events_ingested_per_second Current ingestion rate
# TYPE quetzalog_events_ingested_per_second gauge
quetzalog_events_ingested_per_second 42.5

# HELP quetzalog_alerts_total Total alerts generated
# TYPE quetzalog_alerts_total counter
quetzalog_alerts_total{severity="critical"} 25
quetzalog_alerts_total{severity="high"} 117
quetzalog_alerts_total{severity="medium"} 342
quetzalog_alerts_total{severity="low"} 1500

# HELP quetzalog_alerts_active Current number of active alerts
# TYPE quetzalog_alerts_active gauge
quetzalog_alerts_active{status="new"} 12
quetzalog_alerts_active{status="acknowledged"} 8
quetzalog_alerts_active{status="investigating"} 18

# HELP quetzalog_queries_total Total number of queries executed
# TYPE quetzalog_queries_total counter
quetzalog_queries_total 5420

# HELP quetzalog_query_duration_seconds Duration of queries in seconds
# TYPE quetzalog_query_duration_seconds histogram
quetzalog_query_duration_seconds_bucket{le="0.01"} 4500
quetzalog_query_duration_seconds_bucket{le="0.05"} 5100
quetzalog_query_duration_seconds_bucket{le="0.1"} 5350
quetzalog_query_duration_seconds_bucket{le="0.5"} 5400
quetzalog_query_duration_seconds_bucket{le="1"} 5420
quetzalog_query_duration_seconds_bucket{le="+Inf"} 5420
quetzalog_query_duration_seconds_sum 23.45
quetzalog_query_duration_seconds_count 5420

# HELP quetzalog_db_size_bytes Current database size in bytes
# TYPE quetzalog_db_size_bytes gauge
quetzalog_db_size_bytes 524288000

# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0.5"} 0.00045
go_gc_duration_seconds{quantile="0.9"} 0.0012
```

---

## SOC Platform

The SOC platform turns detection output into triage work: **findings** are
deduplicated, risk-scored aggregates produced when detection rules run;
**investigations** are persistent security stories that collect findings,
events, entities, queries, techniques and notes; **entity risk** is an
accumulated, transparent score per entity; and **response actions** are
analyst actions with an audit ledger.

### SOC Overview

`GET /api/v1/soc/overview?range=24h`

Window: `range` is one of `15m`, `1h`, `6h`, `24h`, `7d` (or explicit
`start`/`end` RFC3339 times). Returns event/finding timelines (severity
folded onto the 4-level SOC scale), queue posture, detection counts and
top entities.

```json
{
  "status": 200,
  "data": {
    "window": {"start": "...", "end": "...", "bucket": 3600},
    "events": {"total": 207, "eps": 0.0, "timeline": [{"bucket": 1757000000, "total": 10, "critical": 1, "high": 2, "medium": 4, "low": 3}]},
    "findings": {"posture": {"open": 6, "critical": 2, "high": 2, "medium": 2, "low": 0, "status_new": 6}, "timeline": [{"bucket": 1757000000, "count": 2}]},
    "detections": {"total": 6, "enabled": 6},
    "top_entities": {"risky_users": [], "risky_hosts": [], "active_source_ips": [], "targeted_hosts": [], "at_risk_users": [], "at_risk_hosts": []}
  }
}
```

### Findings (analyst queue)

`GET /api/v1/findings` — filters: `severity`, `status`, `owner`,
`detection_id`, `user`, `host`, `source_ip`, `destination_ip`, `tactic`,
`technique`, `source`, `tag`, `q` (text), `start`/`end`, `risk_min`,
`has_risk=true`, `sort_by` (`last_seen`, `risk_score`, `first_seen`,
`created_at`, `severity`, `title`, `match_count`), `sort_order`, `limit`,
`offset`. Response: `{findings, total, pagination: {limit, offset, has_more}}`.

| Method & path | Body / notes |
|---------------|--------------|
| `GET /findings/{id}` | single finding (with notes) |
| `PATCH /findings/{id}` | `{title, description, severity, status, owner, risk_score, tags}` — status/owner/risk changes are audited |
| `POST /findings/{id}/notes` | `{content}` |
| `GET /findings/{id}/events` | linked + correlated events (`{events, total, window}`) |
| `GET /findings/{id}/risk` | `{finding_id, risk_score, entities: [{type, value, risk_score, contributions}]}` |

### Saved Views

| Method & path | Body |
|---------------|------|
| `GET /saved-views` | current user's views |
| `POST /saved-views` | `{name, filters: {severity, status, q, user, host, source_ip, sort_by}}` — same name updates in place (stable ID) |
| `DELETE /saved-views/{id}` | delete one of the current user's views |

### Investigations

| Method & path | Body / notes |
|---------------|--------------|
| `GET /investigations` | filters `severity`, `status`, `assignee`, `limit`, `offset` |
| `POST /investigations` | `{title, description, severity, assignee, finding_ids}` |
| `GET /investigations/{id}` | with notes |
| `PATCH /investigations/{id}` | `{title, description, severity, assignee, finding_ids, add_entities: [{type, value}], queries, techniques}` |
| `POST /investigations/{id}/status` | `{status}` — `new, in_progress, contained, resolved, false_positive, cancelled` |
| `GET/POST /investigations/{id}/notes` | `{body}` |
| `POST /investigations/{id}/evidence` | `{event_ids: []}` (max 500) |
| `POST /investigations/{id}/findings` | `{finding_ids: []}` (max 200) |
| `GET /investigations/{id}/findings` | `{findings, total}` |

### Entity Risk & Intel

| Method & path | Notes |
|---------------|-------|
| `GET /risk/entities?type=user&limit=20` | `type` ∈ `user, host, ip`; highest risk first |
| `GET /entities/{type}/{value}` | correlation graph record + `risk` + `risk_contributions` + `findings` + `neighbors`; `type` ∈ `user, host, ip, domain, file, process` |
| `GET /intel/{type}/{value}` | entity detail plus derived `reputation` (`malicious/suspicious/benign/unknown`), `risk_score`, `open_findings` |

### MITRE ATT&CK

| Method & path | Notes |
|---------------|-------|
| `GET /mitre/techniques` | static technique catalog `{id, name, tactic_ids, sub_of}` |
| `GET /mitre/tactics` | static tactic catalog `{id, name, order}` |
| `GET /mitre/active` | techniques carried by open findings `{tactic, technique, count, tactic_name, technique_name}` |

### Response Actions & Audit

| Method & path | Notes |
|---------------|-------|
| `GET /response-actions` | catalog `{name, key, description, sensitive, params}` |
| `POST /response-actions/execute` | `{action, target, owner, tag, points, title, query, url, event, payload}`; built-in keys: `finding.mark_false_positive`, `finding.assign`, `finding.add_tag`, `finding.increase_risk`, `investigation.create`, `search.run`, `url.open`, `webhook.execute` (SSRF-guarded: http(s) only, private/loopback/link-local denied, no redirects) |
| `GET /response-actions/history?limit=50` | execution ledger `{id, action, target, details, user, status, created_at}` |
| `GET /audit?limit=50&user=&action=` | analyst audit trail (403 for the `viewer` role) |

---

## Error Responses

All error responses follow a consistent format:

```json
{
  "error": "error_code",
  "message": "Human readable error message"
}
```

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | bad_request | Invalid request format or parameters |
| 401 | unauthorized | Missing or invalid API token |
| 404 | not_found | Resource not found |
| 409 | conflict | Resource already exists |
| 422 | validation_error | Request body failed validation |
| 429 | rate_limited | Too many requests |
| 500 | internal_error | Unexpected server error |
