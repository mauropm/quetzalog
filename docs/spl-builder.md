# SPL Builder

The SPL Builder is a Splunk-style visual query composer in the Web UI. It produces a
structured query language (SPL) **AST**, which is the single contract shared between the
browser and the backend. The builder never executes its own search: the AST is serialized to
canonical SPL and executed through the normal pipeline.

## Pipeline

```
UI cards ── AST ──▶ POST /spl/build ── canonical SPL
                                      │
UI preview ─ AST ─▶ POST /spl/preview ┼▶ parser ─▶ planner ─▶ SQLite (events)
                                      ▼
POST /api/v1/search ──────────────▶ executor (Run)
```

The browser ships the AST as JSON (`{ version: 1, commands: [...] }`). The server re-parses
that AST (or raw SPL text) with the same `internal/spl` parser used by free-text search, so
visual and typed queries are provably equivalent.

## Open the builder

- Click the **factory/sliders icon** in the Search page header (next to the `?` SPL reference),
  or press **`b`** anywhere (when not typing and no modal is open).
- Toggle **Visual ⇄ SPL** to move between cards and raw text. Editing raw text and clicking
  Build/Run re-syncs the cards.

## API (`/api/v1/spl/*`)

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/spl/parse` | raw SPL → `{ ast, spl, unsupported_commands }` |
| POST | `/spl/build` | AST → canonical `{ spl }` |
| POST | `/spl/validate` | AST validity + `unsupported_commands` |
| POST | `/spl/preview` | AST → `{ ok, fields, results, count, execution_ms }` |
| GET | `/spl/fields` | canonical + attribute field names |
| GET | `/spl/values?field=&limit=` | distinct values for autocomplete |
| GET | `/spl/{indexes,sourcetypes,sources,hosts}` | distinct metadata for pickers |

All responses use the standard `{ status, message, data }` envelope. Preview/validate return
HTTP 200 with `{ ok: false, error: {...} }` for user-facing query errors so the UI can render
inline messages. The regular `POST /api/v1/search` maps invalid SPL to HTTP 400.

## AST wire format

```json
{
  "version": 1,
  "commands": [
    { "type": "search", "fields": { "index": "auth" }, "text": "login",
      "expr": { "kind": "or", "args": [
        { "kind": "and", "args": [
          { "kind": "cmp", "field": "status", "op": "=", "value": "failed" }
        ]},
        { "kind": "cmp", "field": "response_time", "op": ">", "value": "1000", "not": false }
      ]}},
    { "type": "stats", "aggs": [{ "func": "count", "field": "", "alias": "fails" }], "groupby": ["user"] },
    { "type": "sort", "sort": [{ "field": "fails", "desc": true }] },
    { "type": "head", "n": 20 }
  ]
}
```

Expression kinds: `and`, `or`, `cmp`, `in`, `isnull`, `like`, `text`. Command nodes cover
`search`, `where`, `eval`, `stats`/`eventstats`/`streamstats`, `timechart`, `sort`, `head`,
`tail`, `dedup`, `fields`, `table`, `rename`, `rex`, `bin`. Unrecognized pipe commands parse to
an `unsupported` node (preserving raw text) and are surfaced via `unsupported_commands`.

## Supported commands

See [SPL Compatibility](../SPL_COMPATIBILITY.md) for the full matrix.
