package event

// Provenance attribute keys. Every ingestion source stamps these so a
// normalized event can be traced back to the parser and collector that
// produced it, and so the raw payload is preserved for all sources.
const (
	AttrParser        = "parser"
	AttrParserVersion = "parser_version"
	AttrCollector     = "collector"
)

// Provenance records the raw payload and parser provenance on an event.
// raw is the unmodified input the event was built from (wire bytes for
// line/delimited formats, the per-event JSON object for JSON batch
// endpoints). rawFormat names that input ("syslog", "ndjson", "json", ...).
// parser/version identify the parser; collector identifies the receiving
// source. All arguments may be empty, in which case the corresponding
// field is left untouched.
func Provenance(e *Event, raw []byte, rawFormat, parser, version, collector string) {
	if e == nil {
		return
	}
	if raw != nil {
		e.Raw = raw
	}
	if rawFormat != "" {
		e.RawFormat = rawFormat
	}
	if parser == "" && collector == "" {
		return
	}
	if e.Attributes == nil {
		e.Attributes = make(map[string]any)
	}
	if parser != "" {
		e.Attributes[AttrParser] = parser
		e.Attributes[AttrParserVersion] = version
	}
	if collector != "" {
		e.Attributes[AttrCollector] = collector
	}
}
