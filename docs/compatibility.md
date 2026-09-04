# Splunk Compatibility Matrix

This document describes SIEMto's compatibility with Splunk HTTP Event Collector (HEC)
and Splunk Search REST API endpoints.

## Overview

SIEMto aims to provide Splunk-compatible ingestion and search endpoints for easy
migration and integration with existing Splunk tooling. Full Splunk compatibility is
not a goal -- the focus is on the most commonly used endpoints.

## Endpoint Matrix

| Endpoint | Method | Status | Notes |
|----------|--------|--------|-------|
| `/services/collector` | POST | Supported | HEC v1.0 compatible |
| `/services/collector/event` | POST | Supported | Single and batch events |
| `/services/collector/raw` | POST | Supported | Raw text ingestion |
| `/services/search/jobs` | POST | Supported | Async search support |
| `/services/search/jobs` | GET | Supported | List search jobs |
| `/services/search/jobs/{sid}` | GET | Supported | Get search status |
| `/services/search/jobs/{sid}/results` | GET | Supported | Paginated results |
| `/services/search/jobs/{sid}/output` | POST | Partial | Limited output modes |
| `/services/data/indexes` | GET | Partial | Only default index |
| `/services/data/sourcetypes` | GET | Partial | Basic support |
| `/services/data/sources` | GET | Partial | Basic support |
| `/services/data/inputs` | GET | Partial | Basic support |
| `/services/server/info` | GET | Supported | Basic server info |
| `/services/server/global-config` | GET | Not implemented | N/A |
| `/services/auth/login` | POST | Not implemented | Use API tokens |
| SPL full query language | - | Partial | Subset of commands |

## HEC Compatibility

### Supported Features

| Feature | Supported | Notes |
|---------|-----------|-------|
| Single event ingestion | Yes | Same as Splunk HEC v1.0 |
| Batch event ingestion | Yes | Up to 1000 events per batch |
| Timestamp support | Yes | Unix epoch or RFC3339 |
| Source specification | Yes | `source` field |
| Sourcetype specification | Yes | `sourcetype` field (metadata only) |
| Index specification | Yes | `index` field (metadata only) |
| Host specification | Yes | `host` field |
| Event-level fields | Yes | All standard HEC fields |
| Auth token validation | Yes | `Authorization: Splunk <token>` or `?token=` |
| Acknowledgement (ack) | Yes | `ack` header support |
| Compression | Yes | gzip, deflate |
| Chunked transfer | Yes | Streaming events |

### HEC Response Codes

| Code | Message | Description |
|------|---------|-------------|
| 0 | OK | Event accepted |
| 2 | Invalid authentication | Bad HEC token |
| 6 | Invalid content type | Wrong Content-Type header |
| 9 | Authentication failed | HEC token invalid or missing |
| 10 | No data, close connection | Empty payload |
| 40 | Too much data | Payload exceeds limit |
| 80 | Invalid value for field | Field validation error |
| 90 | Invalid event | Malformed event data |
| 100 | Internal error | Server error |

### HEC Example Requests

**Single Event:**

```bash
curl -k https://localhost:8088/services/collector \
  -H "Authorization: Splunk my-hec-token" \
  -H "Content-Type: application/json" \
  -d '{
    "event": "User login successful",
    "host": "web01",
    "source": "auth",
    "sourcetype": "auth:login",
    "time": 1725392400
  }'
```

**Batch Events:**

```bash
curl -k https://localhost:8088/services/collector \
  -H "Authorization: Splunk my-hec-token" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {"event": "Event 1", "host": "server01", "time": 1725392400},
      {"event": "Event 2", "host": "server02", "time": 1725392401}
    ]
  }'
```

**Raw Text:**

```bash
curl -k https://localhost:8088/services/collector/raw \
  -H "Authorization: Splunk my-hec-token" \
  -d "This is a raw log line"
```

## Search API Compatibility

### Supported Search Commands

| Splunk Command | SIEMto Support | Notes |
|---------------|----------------|-------|
| `search` | Full | Full support with field=value syntax |
| `where` | Full | Comparison and boolean expressions |
| `stats` | Partial | 8 aggregation functions |
| `sort` | Full | Ascending and descending |
| `head` | Full | Limit N results |
| `tail` | Full | Last N results |
| `dedup` | Partial | Single and multi-field dedup |
| `rename` | Full | Field renaming |
| `table` | Full | Column selection and ordering |
| `eval` | Partial | 7 functions (vs 80+ in Splunk) |
| `timechart` | Partial | Basic time-based aggregation |
| `chart` | Not supported | No multi-chart support |
| `transaction` | Not supported | No multi-event correlation |
| `join` | Not supported | No cross-query joins |
| `map` | Not supported | No iterative search |
| `append` | Not supported | No result set combining |
| `inputcsv` | Not supported | No CSV input |
| `outputcsv` | Not supported | No CSV output |

### Search Job Example

```bash
# Start a search job
curl -k https://localhost:8088/services/search/jobs \
  -H "Authorization: Splunk my-hec-token" \
  -d "search=source=auth | stats count by user" \
  -d "output_mode=json"

# Get job status
curl -k https://localhost:8088/services/search/jobs/1725392400.12345 \
  -H "Authorization: Splunk my-hec-token"

# Get results
curl -k https://localhost:8088/services/search/jobs/1725392400.12345/results \
  -H "Authorization: Splunk my-hec-token" \
  -d "output_mode=json" \
  -d "count=100" \
  -d "offset=0"
```

## Limitations

### What Is Not Supported

1. **Full Splunk SPL** - Only a subset of commands and functions are implemented
2. **Real-time search** - SIEMto uses batch processing, not real-time streams
3. **Search peering** - No distributed search across multiple Splunk instances
4. **Saved searches** - No pre-defined search templates (detection rules serve this purpose)
5. **Scheduled reports** - No recurring report generation
6. **Lookup commands** - No external lookup table operations
7. **Streaming commands** - No streaming processor support
8. **TStats** - No TSV-based fast search (SQLite backend)
9. **Authorization** - No Splunk auth integration (uses API tokens)
10. **Data models** - No CIM (Common Information Model) support

### Differences from Splunk

| Aspect | Splunk | SIEMto |
|--------|--------|--------|
| Storage | Proprietary index engine | SQLite |
| Scale | Distributed, petabyte-scale | Single-node, gigabyte-scale |
| Search | Distributed search peers | Single-node SQLite queries |
| SPL | Full 100+ commands | 12 commands |
| Eval functions | 80+ functions | 7 functions |
| Real-time search | Yes | No |
| Data models | CIM support | No |
| Licensing | Commercial | MIT Open Source |
| Setup | Complex, multi-component | Single binary |

## Integration Guide

### Migrating from Splunk HEC

1. Update the HEC endpoint in your forwarder configuration:
   - Splunk: `https://splunk-server:8088/services/collector`
   - SIEMto: `http://quetzalog:8080/services/collector`

2. Update the HEC token in your configuration

3. No changes needed to event format -- SIEMto accepts the same JSON format

### Migrating Search Queries

1. Test queries against SIEMto using the `POST /api/v1/search` endpoint
2. Some Splunk-specific functions (eval, stats) may need syntax adjustment
3. Use the [SPL Compatibility](../SPL_COMPATIBILITY.md) reference for supported commands

### Using with Splunk Forwarders

Heavy and Universal Forwarders can be configured to send data to SIEMto:

```
[http://localhost:8080/services/collector]
disabled = false
index = security
sourcetype = authtype
```

## Future Compatibility

Planned Splunk compatibility improvements:

- [ ] Full `eval` function support (target: 30+ functions)
- [ ] `transaction` command (basic event sequence correlation)
- [ ] `inputcsv` / `outputcsv` commands
- [ ] Lookup table operations (CSV-based)
- [ ] Streaming commands (`eval`, `rex`, etc.)
- [ ] `timechart` with multiple chart types
- [ ] Partial `join` support (inner join on indexed fields)
- [ ] `append` / `appendcols` for result set combination
