# Detection Engine

The detection engine evaluates events against user-defined rules to generate security alerts.
It supports threshold-based detection with time-windowed grouping.

## Detection Rule Structure

A detection rule defines the conditions under which an alert should be generated.

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable rule name |
| `query` | string | Yes | SPL-like query to match events |
| `severity` | string | Yes | Alert severity: `debug`, `info`, `warning`, `err`, `critical` |
| `threshold.count` | int | Yes | Number of matching events to trigger alert |
| `threshold.window` | string | Yes | Time window for threshold (e.g., `300s`, `1h`, `24h`) |
| `group_by` | string | Yes | Event field to group by |
| `enabled` | bool | No | Whether rule is active (default: `true`) |
| `description` | string | No | Rule description |
| `tags` | []string | No | Tags for categorization |

### Example Rule YAML

```yaml
name: Brute Force Detection
description: Detects repeated failed authentication attempts from the same source IP
query: source=auth AND outcome=failure
severity: high
threshold:
  count: 5
  window: 300s
group_by: source_ip
enabled: true
tags:
  - auth
  - brute-force
  - security

---

name: Disk Space Critical
description: Alerts when multiple hosts report high disk usage
query: event_type=system AND message~=9[0-9]%
severity: critical
threshold:
  count: 1
  window: 60s
group_by: host
enabled: true
tags:
  - infrastructure
  - disk

---

name: Policy Violation - After Hours Access
description: Detects authentication outside business hours
query: source=auth AND outcome=success
severity: warning
threshold:
  count: 1
  window: 1h
group_by: user
enabled: true
tags:
  - compliance
  - access-control
```

## Supported Query Syntax

The detection query uses the same SPL-like syntax as the search engine, with a focus on
filtering expressions suitable for rule definitions.

### Field Matching

```
source=auth
severity=error
host=web01
event_type=authentication
```

### Boolean Operators

```
# AND (implicit)
source=auth outcome=failure

# Explicit AND
source=auth AND outcome=failure

# OR
severity=err OR severity=critical

# NOT
source!=firewall

# Parentheses
(severity=err OR severity=critical) AND source=auth
```

### Value Matching

```
# Exact match
source=auth

# Partial match (substring)
message=failed

# Regex match
message~=^[Ee]rror.*
```

### Pipe Commands (Limited)

Detection queries support a limited set of pipe commands. Most aggregation is handled by
the threshold and group_by fields.

```
# Sort (descending) - useful for review
query: severity=critical | sort -timestamp

# Limit for preview
query: source=auth | head 10
```

## Threshold Detection

The threshold engine works by:

1. **Filtering** -- Events matching the query are filtered
2. **Grouping** -- Events are grouped by the `group_by` field (e.g., `source_ip`)
3. **Windowing** -- For each group, events are evaluated within the time window
4. **Counting** -- If the count exceeds `threshold.count`, an alert is generated

### Example: Brute Force Detection

```yaml
name: Brute Force Detection
query: source=auth AND outcome=failure
severity: high
threshold:
  count: 5
  window: 300s
group_by: source_ip
```

**How it works:**

1. All events where `source=auth` AND `outcome=failure` are matched
2. Events are grouped by `source_ip`
3. For each IP, a 5-minute sliding window is maintained
4. When an IP has 5+ failures within any 5-minute window, an alert is created
5. The alert is grouped by `source_ip` so all related failures appear together

### Time Window Formats

| Format | Example | Meaning |
|--------|---------|---------|
| Seconds | `60s` | 60 seconds |
| Minutes | `10m` | 10 minutes |
| Hours | `1h` | 1 hour |
| Days | `1d` | 1 day |
| Composite | `2h 30m` | 2 hours 30 minutes |

## Alert Lifecycle

When a detection rule triggers, an alert is created with the following lifecycle states:

```
  +-------+     +----------------+     +----------------+
  |  NEW  | ----> | ACKNOWLEDGED  | ----> | INVESTIGATING  |
  +-------+     +----------------+     +----------------+
       |                                         |
       |                                         v
       |                                  +-------------+
       +---------------------------------> |  RESOLVED   |
                                            +-------------+
                                                    |
                                                    v
                                              +------------------+
                                              | FALSE_POSITIVE   |
                                              +------------------+
```

### States

| State | Description | Transitions |
|-------|-------------|-------------|
| `new` | Alert created, not yet reviewed | -> acknowledged, -> investigating, -> resolved, -> false_positive |
| `acknowledged` | Alert reviewed, assigned for investigation | -> investigating, -> resolved, -> false_positive |
| `investigating` | Alert under active investigation | -> resolved, -> false_positive, -> acknowledged |
| `resolved` | Alert investigated and resolved | (no outgoing transitions) |
| `false_positive` | Alert determined to be benign | (no outgoing transitions) |

### Alert Fields (API Response)

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

## Example Rules

### Brute Force Detection

Detects repeated failed authentication attempts from the same source.

```yaml
name: Brute Force Detection
query: source=auth AND outcome=failure
severity: high
threshold:
  count: 5
  window: 300s
group_by: source_ip
tags:
  - auth
  - brute-force
  - credential-attack
```

### Intrusion Attempt

Detects SQL injection or command injection patterns in web application logs.

```yaml
name: SQL Injection Attempt
query: source=webapp AND message~=select.*from.*union
severity: critical
threshold:
  count: 1
  window: 60s
group_by: source_ip
tags:
  - injection
  - sql-injection
  - web-attack
```

### Policy Violation - Admin Login from External IP

Detects administrative logins from external IP addresses.

```yaml
name: External Admin Login
query: source=auth AND user=superadmin AND source_ip!~^10\. AND source_ip!~^192\.168\.
severity: high
threshold:
  count: 1
  window: 1h
group_by: source_ip
tags:
  - policy
  - admin
  - external-access
```

### Multiple Failed Logins Per User

Detects users with repeated authentication failures (potential account compromise).

```yaml
name: User Account Compromise Indicator
query: source=auth AND outcome=failure
severity: warning
threshold:
  count: 3
  window: 600s
group_by: user
tags:
  - auth
  - account-compromise
  - credential-stuffing
```

### Infrastructure Alert - Disk Space

Detects when disk usage exceeds 90% on any host.

```yaml
name: Critical Disk Usage
query: event_type=system AND message~=9[0-9]%
severity: critical
threshold:
  count: 1
  window: 60s
group_by: host
tags:
  - infrastructure
  - disk
  - capacity
```

## Execution

### Automatic Execution

Detection rules are evaluated automatically at the configured interval (default: 30 seconds).
The check interval is set in the configuration:

```yaml
detection:
  check_interval: 30s
```

### Manual Execution via API

Execute a detection rule against a specific time range:

```bash
curl -X POST http://localhost:8080/api/v1/detections/{id}/exec \
  -H "Content-Type: application/json" \
  -d '{
    "start_time": "2026-09-03T00:00:00Z",
    "end_time": "2026-09-03T23:59:59Z"
  }'
```

**Response:**

```json
{
  "detection_id": "det-brute-force",
  "detection_name": "Brute Force Detection",
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

### Manual Execution via CLI

```bash
quetzalog detections exec <rule-id> --start "2026-09-03T00:00:00Z" --end "2026-09-03T23:59:59Z"
```

### Listing Detections

```bash
# API
curl http://localhost:8080/api/v1/detections

# CLI
quetzalog detections
```

### Creating a Detection

```bash
# API
curl -X POST http://localhost:8080/api/v1/detections \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom Detection",
    "query": "source=auth AND outcome=failure",
    "severity": "high",
    "threshold": {"count": 10, "window": "600s"},
    "group_by": "source_ip"
  }'

# CLI
quetzalog detections create \
  --name "Custom Detection" \
  --query "source=auth AND outcome=failure" \
  --severity high \
  --threshold-count 10 \
  --threshold-window 600s \
  --group-by source_ip
```

## Configuration

Detection rules can be loaded from a YAML file or created/updated via the API/CLI.

### YAML Rule File

```yaml
detection_rules:
  - path: /etc/quetzalog/rules/brute-force.yaml
  - path: /etc/quetzalog/rules/intrusion.yaml
  - path: /etc/quetzalog/rules/policy.yaml
```

### Inline Rules in Main Config

```yaml
detection:
  rules:
    - name: Inline Rule
      query: source=auth AND outcome=failure
      severity: high
      threshold:
        count: 5
        window: 300s
      group_by: source_ip
      enabled: true
```

## Best Practices

1. **Start broad, narrow down** -- Begin with simple rules and refine based on false positive rates
2. **Use tags** -- Tag rules for easy categorization and filtering
3. **Adjust thresholds** -- Use initial detection to gather data, then tune thresholds
4. **Test with CLI** -- Use manual execution to test rules against existing data before enabling
5. **Review regularly** -- Schedule regular reviews of all active rules and their alerts
6. **Combine detections** -- Use multiple rules that detect aspects of the same attack vector
7. **Monitor performance** -- Heavy queries with large time windows can impact performance
