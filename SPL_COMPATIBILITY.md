# SPL Compatibility

Quetzalog implements a Splunk-like query language (SPL) for searching and analyzing events.
This document describes the supported commands, syntax, and limitations.

## Supported Commands

### search

The primary search command filters events based on field-value pairs and expressions.

**Syntax:**

```
search <field>=<value> [<field>=<value> ...]
```

**Examples:**

```
# Search for events containing "error"
search message=error

# Search with multiple conditions (AND)
search severity=error source=auth

# Search with OR
search severity=err OR severity=critical

# Search with regex
search message~=^[Ee]rror.*

# Search with exclusion
search source!=firewall

# Search combined with pipe
search severity=error | sort -timestamp | head 10
```

### where

Filters events using comparison and logical expressions. More powerful than `search` for
complex conditions.

**Syntax:**

```
where <expression>
```

**Examples:**

```
# Numeric comparison
where timestamp>2026-09-01

# String containment
where message CONTAINS "failed"

# Numeric threshold
where usage_pct > 90

# Multiple conditions
where severity IN (err, critical) AND source IN (auth, firewall)

# Negation
where source NOT IN (debug, test)

# Time range
where timestamp BETWEEN 2026-09-01 AND 2026-09-03
```

### stats

Aggregates events and computes statistics.

**Syntax:**

```
stats <stat_type>(<field>) | <stat_type>(*) BY <group_field>
```

**Available Statistics:**

| Function | Description |
|----------|-------------|
| `count` | Count of events |
| `count(field)` | Count of non-null values |
| `sum(field)` | Sum of numeric values |
| `avg(field)` | Average of numeric values |
| `min(field)` | Minimum value |
| `max(field)` | Maximum value |
| `values(field)` | Distinct values |
| `dc(field)` | Distinct count |

**Examples:**

```
# Count events by user
stats count BY user

# Count events by source and severity
stats count BY source, severity

# Sum of usage percentage by host
stats sum(usage_pct) BY host

# Average response time by service
stats avg(response_time_ms) BY service

# Count and distinct sources by user
stats count, dc(source) BY user

# Count all matching events
stats count(*) WHERE severity=error
```

### sort

Sorts results by field(s).

**Syntax:**

```
sort <field> [<field> ...]
sort -<field>  (descending)
```

**Examples:**

```
# Sort ascending by timestamp
sort timestamp

# Sort descending by severity
sort -severity

# Multi-field sort
sort source, -timestamp

# Combined with stats
stats count BY user | sort -count
```

### head

Returns the first N results.

**Syntax:**

```
head <N>
```

**Examples:**

```
# Get top 10 results
search severity=error | head 10

# Top 5 sources by event count
stats count BY source | sort -count | head 5
```

### tail

Returns the last N results.

**Syntax:**

```
tail <N>
```

**Examples:**

```
# Get last 5 events
search source=auth | sort timestamp | tail 5
```

### dedup

Removes duplicate events based on field(s).

**Syntax:**

```
dedup <field> [<field> ...]
```

**Examples:**

```
# Remove duplicates by source_ip
search source_ip=* | dedup source_ip

# Remove duplicates by user and source_ip
dedup user, source_ip
```

### rename

Renames fields in the output.

**Syntax:**

```
rename <old_field> AS <new_field>
```

**Examples:**

```
# Rename a single field
rename count AS total_count

# Rename multiple fields
rename source AS log_source, timestamp AS time
```

### table

Selects and orders specific fields for output.

**Syntax:**

```
table <field> [<field> ...]
```

**Examples:**

```
# Show only specific fields
search severity=error | table timestamp, source, message

# Ordered fields
table message, source, severity, host
```

### eval

Creates new fields by evaluating expressions.

**Syntax:**

```
eval <new_field> = <expression>
```

**Available Functions:**

| Function | Description | Example |
|----------|-------------|---------|
| `if(cond, true_val, false_val)` | Conditional expression | `if(severity="critical", 1, 0)` |
| `isnull(field)` | Check if null | `isnull(source_ip)` |
| `len(str)` | String length | `len(message)` |
| `upper(str)` | Uppercase | `upper(user)` |
| `lower(str)` | Lowercase | `lower(source)` |
| `substr(str, start, len)` | Substring | `substr(message, 0, 10)` |
| `tonumber(str)` | Convert to number | `tonumber(usage_pct)` |

**Examples:**

```
# Create a flag field
eval is_critical = if(severity="critical", "yes", "no")

# Convert string to number
eval usage_num = tonumber(usage_pct)

# Compute ratio
eval error_rate = count / total * 100

# Extract user from message
eval short_msg = if(len(message) > 50, substr(message, 0, 50), message)
```

### timechart

Creates time-based charts by binning events into time intervals.

**Syntax:**

```
timechart <stat>(field) BY <field> span(<interval>)
```

**Supported Intervals:**

| Format | Example |
|--------|---------|
| Seconds | `10s` |
| Minutes | `5m` |
| Hours | `1h` |
| Days | `1d` |

**Examples:**

```
# Error count per hour by source
timechart count BY source span=1h

# Average response time per minute by service
timechart avg(response_time_ms) BY service span=5m

# Distinct user count per hour
timechart dc(user) BY user span=1h
```

### rex

Extracts fields from event messages using regular expressions.

**Syntax:**

```
rex field=<source_field> "<regex>" AS <new_field>
```

**Examples:**

```
# Extract IP address from message
rex field=message "(?<ip>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)" AS source_ip

# Extract status code from log line
rex field=message "status=(?<code>\d+)" AS status_code

# Extract key-value pairs from message
rex field=message "(?P<key>\w+)=(?P<value>\S+)"
```

## Query Planning

Queries are processed through several stages:

```
User Query String
       |
       v
  +---------+
  |  Lexer  |  -> Token stream (field, operator, value, pipe, etc.)
  +---------+
       |
       v
  +---------+
  |  Parser |  -> AST (abstract syntax tree)
  +---------+
       |
       v
  +---------+
  | Planner |  -> SQL query plan (optimized SQLite query)
  +---------+
       |
       v
  +---------+
  | Executor|  -> Result set (paginated, filtered)
  +---------+
```

### Parsing Stages

1. **Lexical Analysis** - Tokenizes the query string into components
   - Field names, values, operators (`=`, `!=`, `>`, `<`, `>=`, `<=`, `~=`)
   - Boolean operators (`AND`, `OR`, `NOT`, `IN`, `NOT IN`, `BETWEEN`)
   - Pipe (`|`) for chaining commands
   - Command keywords (`search`, `where`, `stats`, `sort`, `head`, etc.)

2. **Parsing** - Builds an AST from tokens
   - Boolean expression tree
   - Command pipeline
   - Aggregation specifications

3. **Planning** - Translates AST to SQLite queries
   - `search` and `where` -> `WHERE` clauses with FTS5 or indexed columns
   - `stats` -> `GROUP BY` with aggregation functions
   - `sort` -> `ORDER BY` clause
   - `head`/`tail` -> `LIMIT`/`OFFSET` clauses
   - `dedup` -> `DISTINCT` or post-processing
   - `table` -> Column selection (`SELECT col1, col2`)
   - `eval` -> `CASE WHEN` or computed columns
   - `timechart` -> Time bucketing with `strftime` or similar

4. **Execution** - Runs the SQL query against SQLite
   - Uses FTS5 for full-text search
   - Uses indexed columns for field filters
   - Uses SQLite aggregation functions for stats
   - Applies post-processing for dedup, rename, table

## Limitations vs Splunk SPL

Quetzalog's SPL implementation covers the most commonly used commands but does not aim for
full Splunk SPL compatibility. Key differences:

| Feature | Splunk SPL | Quetzalog |
|---------|-----------|--------|
| Core search/filter | Full | Supported |
| Boolean operators | Full | Supported |
| Regex matching | Full | Supported |
| stats | Full (15+ functions) | 8 functions |
| eval | Full (80+ functions) | 7 functions |
| timechart | Full (multiple chart types) | Line charts only (via JSON) |
| rex | Full PCRE | Basic regex |
| transaction | Full complex transactions | Not supported |
| join | Full outer/join operations | Not supported |
| map | Map search | Not supported |
| metadata | Event metadata operations | Not supported |
| append/appendcols | Result set combining | Not supported |
| outputcsv/outputjson | File output formats | Not supported (API returns JSON) |
| streamstats | Running statistics | Not supported |
| chart/timeseries | Multiple chart types | Timechart only |
| iplocation/lookup | External data lookup | Not supported |
| rest | REST data input | Not supported |
| tstats | TSV-based fast search | Not applicable (SQLite backend) |

### Unsupported SPL Patterns

The following Splunk SPL patterns are not supported:

- `transaction` command - Complex multi-event sequence correlation
- `join` command - Cross-query joins
- `map` command - Iterative search over result sets
- `append` / `appendcols` - Result set combination
- `rest` command - REST API data source
- `metadata` - Event metadata operations
- `tstats` - TSV-based fast search (not applicable)
- `streamstats` - Running/waterfall statistics
- `chart` with multiple chart types - Only line charts via timechart
- `iplocation` - IP geolocation lookup (GeoIP stub exists but not via SPL)
- `lookup` - External lookup table operations
- `outputcsv` / `outputxml` / `outputjson` - File output (API returns JSON)
- `multikv` - Multi-key value extraction from table output
- `makemv` - Multi-value field splitting
- `makecontinuous` - Time series gaps

## Performance Considerations

### Index Usage

The query planner uses the following indexes:

| Index | Used By | Description |
|-------|---------|-------------|
| `idx_events_timestamp` | `search`, `where` with time conditions | Timestamp range queries |
| `idx_events_severity` | `search`, `where` with severity filter | Severity filter |
| `idx_events_source` | `search`, `where` with source filter | Source filter |
| `idx_events_host` | `search`, `where` with host filter | Host filter |
| `events_fts` | `search` with text queries | Full-text search |

### Optimizations

1. **FTS5 for text search** - `search message=error` uses SQLite FTS5 virtual tables
   for efficient full-text matching. This is significantly faster than `LIKE '%error%'`.

2. **Indexed columns** - Commonly filtered fields (severity, source, host, event_type) have
   dedicated B-tree indexes.

3. **Query pushdown** - Where clauses are pushed down to SQLite before post-processing,
   reducing the number of rows processed.

4. **Lazy evaluation** - Pipe stages are evaluated lazily, allowing early termination
   with `head` commands.

### Best Practices

- **Filter early** - Put the most restrictive conditions first in your query
- **Use indexed fields** - Filtering by `source`, `severity`, `host`, and `event_type`
  uses indexed columns and is significantly faster than filtering only in `message`
- **Limit results** - Use `head` or `limit` to avoid loading large result sets
- **Avoid excessive pipe chains** - Each pipe adds overhead; combine conditions when possible
- **Use exact matches over regex** - `source=auth` uses index; `message~=auth` does not
- **Time range queries** - Always include time range filters for large datasets:
  `search timestamp>2026-09-01 timestamp<2026-09-02 | stats count BY source`

### FTS5 Limitations

- FTS5 searches are case-insensitive by default
- Regex (`~=`) falls back to LIKE-based matching, not FTS5
- FTS5 does not support stemming or phonetic matching
- Very long messages (>8KB) may be truncated in the FTS index
