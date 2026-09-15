package detections

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// SigmaError is returned when a Sigma rule contains constructs the importer
// does not support. It lists every unsupported clause so the failure is
// actionable — never a partial, silent import (spec §42).
type SigmaError struct {
	Title       string
	Unsupported []string
}

func (e *SigmaError) Error() string {
	return fmt.Sprintf("sigma import %q failed: %d unsupported construct(s): %s",
		e.Title, len(e.Unsupported), strings.Join(e.Unsupported, "; "))
}

// SigmaRule is the subset of the Sigma 2.x schema the importer understands.
// Note: `condition` is a top-level key in Sigma, a sibling of `detection`.
type SigmaRule struct {
	Title            string         `yaml:"title"`
	ID               string         `yaml:"id"`
	Status           string         `yaml:"status"`
	Version          string         `yaml:"version"`
	Description      string         `yaml:"description"`
	Level            string         `yaml:"level"`
	LogSource        SigmaLogSource `yaml:"logsource"`
	Detection        map[string]any `yaml:"detection"`
	Condition        string         `yaml:"condition"`
	Fields           map[string]any `yaml:"fields"`
	Tags             []string       `yaml:"tags"`
	FalsePositives   []string       `yaml:"falsepositives"`
	References       []string       `yaml:"references"`
	LogPath          string         `yaml:"logpath"`
}

// SigmaLogSource is the Sigma logsource block.
type SigmaLogSource struct {
	Product    string `yaml:"product"`
	Category   string `yaml:"category"`
	Service    string `yaml:"service"`
	Definition string `yaml:"definition"`
}

// sigUnsupported collects unsupported constructs while converting.
type sigUnsupported struct {
	clauses []string
}

func (s *sigUnsupported) add(what string) {
	s.clauses = append(s.clauses, what)
}

// sigPred is one boolean predicate on an event.
type sigPred struct {
	// text is the rendered SPL fragment, e.g. `process = 'powershell.exe'`
	// or `message LIKE '%-enc%'`.
	text   string
	field  string
	branch string // "eq" | "in" | "like" (used for N-of-them counting)
}

// sigSelection is one named detection block (selection, selection1, ...).
type sigSelection struct {
	name     string
	preds    []sigPred
}

// ImportSigma converts a Sigma rule YAML document into a Quetzalog detection
// rule (kind=spl). Unsupported constructs are accumulated and reported as a
// single structured error; nothing is written on failure.
func ImportSigma(data []byte) (*DetectionRule, error) {
	var rule SigmaRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parse sigma yaml: %w", err)
	}
	if rule.Title == "" {
		return nil, fmt.Errorf("sigma rule missing title")
	}
	if strings.ToLower(strings.TrimSpace(rule.Status)) != "active" {
		return nil, fmt.Errorf("sigma import supports only detection.status: active (got %q)", rule.Status)
	}
	if len(rule.Detection) == 0 {
		return nil, fmt.Errorf("sigma rule %q has no detection block", rule.Title)
	}

	su := &sigUnsupported{clauses: []string{}}
	selByName := map[string]*sigSelection{}
	for name, val := range rule.Detection {
		sel, err := sigConvertBlock(name, val, su)
		if err != nil {
			return nil, &SigmaError{Title: rule.Title, Unsupported: su.clauses}
		}
		selByName[name] = sel
	}

	sourceType, err := mapSigmaLogSource(rule.LogSource, su)
	if err != nil {
		return nil, &SigmaError{Title: rule.Title, Unsupported: su.clauses}
	}

	cond, err := rule.sigCondition()
	if err != nil {
		su.add("condition: " + err.Error())
		return nil, &SigmaError{Title: rule.Title, Unsupported: su.clauses}
	}

	// Build the combined predicate from the condition.
	whereText, thresholdCount, err := sigCombine(cond, selByName, sourceType, su)
	if err != nil {
		return nil, &SigmaError{Title: rule.Title, Unsupported: su.clauses}
	}
	if len(su.clauses) > 0 {
		return nil, &SigmaError{Title: rule.Title, Unsupported: su.clauses}
	}

	ver := 1
	if rule.Version != "" {
		if n, err := strconv.Atoi(rule.Version); err == nil && n > 0 {
			ver = n
		}
	}

	sev := mapSigmaLevel(rule.Level)
	tactic, technique, tags := sigMitreTags(rule.Tags)

	q := "search"
	if sourceType != "" {
		q += " source_type=" + sourceType
	}
	if whereText != "" {
		q += " | where " + whereText
	}

	out := &DetectionRule{
		Name:          rule.Title,
		Description:   rule.Description,
		Severity:      sev,
		Kind:          "spl",
		Query:         q,
		Enabled:       true,
		Version:       ver,
		DataSources:   []string{sourceType},
		References:    rule.References,
		MITRETactic:   tactic,
		MITRETechnique: technique,
	}
	if len(rule.FalsePositives) > 0 {
		out.FalsePositiveNotes = strings.Join(rule.FalsePositives, "\n")
	}
	tags = append(tags, "sigma:"+strings.ToLower(strings.ReplaceAll(strings.ToLower(rule.Title), " ", "_"))+"@"+strconv.Itoa(ver))
	out.Tags = tags
	if thresholdCount > 0 {
		out.Threshold = &Threshold{Count: thresholdCount, Window: cond.window}
	} else if cond.window != "" {
		out.Threshold = &Threshold{Count: 1, Window: cond.window}
	}

	return out, nil
}

// sigCondition holds the parsed condition expression.
type sigCondition struct {
	// terms in evaluation order; joins are implicit AND unless orGroup set.
	terms     []string // selection names
	negative  []string // terms wrapped in NOT
	orGroup   bool
	allOfThem bool
	// ofThem is N when the condition is "N of them"; 0 when absent.
	ofThem int
	window string
}

func (r *SigmaRule) sigCondition() (*sigCondition, error) {
	cond := strings.TrimSpace(r.Condition)
	if cond == "" {
		// Some documents nest the condition inside detection; fall back.
		var ok bool
		cond, ok = rawCondition(r.Detection)
		if !ok {
			// No explicit condition: treat every top-level selection as AND.
			return &sigCondition{terms: selOrderNames(r.Detection)}, nil
		}
	}
	c := &sigCondition{}
	// "last: 5m" may appear inside a nested and/or block.
	if last, ok := lastWindow(r.Detection); ok {
		c.window = last
	}

	// "N of them" / "all of them" / "any of them"
	lm := strings.ToLower(cond)
	switch {
	case strings.Contains(lm, "all of them"):
		c.allOfThem = true
	case strings.Contains(lm, "any of them"):
		c.ofThem = 1
		c.orGroup = true
	default:
		if idx := strings.Index(lm, " of them"); idx > 0 {
			nStr := strings.TrimSpace(lm[:idx])
			if n, err := strconv.Atoi(nStr); err == nil {
				c.ofThem = n
			} else {
				return nil, fmt.Errorf("unparseable of-them count %q", nStr)
			}
		}
	}

	// Extract named selections referenced in the condition, preserving
	// order and whether they are negated ("not filter").
	seen := map[string]bool{}
	for _, name := range selOrderNames(r.Detection) {
		if !strings.Contains(cond, name) {
			continue
		}
		neg := sigCondNegates(cond, name)
		if !seen[name] {
			c.terms = append(c.terms, name)
			seen[name] = true
		}
		if neg {
			c.negative = append(c.negative, name)
		}
	}
	// "N of them" usually names no selection explicitly — it quantifies
	// over all of them.
	if c.ofThem > 0 && len(c.terms) == 0 {
		c.terms = selOrderNames(r.Detection)
	}
	if len(c.terms) == 0 {
		// Condition names no resolvable selection.
		return nil, fmt.Errorf("condition %q does not reference a known selection", cond)
	}
	if strings.Contains(lm, " or ") {
		c.orGroup = true
	}
	return c, nil
}

// selOrderNames lists detection block names in a stable order, skipping the
// condition pseudo-key.
func selOrderNames(d map[string]any) []string {
	out := make([]string, 0, len(d))
	for n := range d {
		if strings.ToLower(n) != "condition" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// sigCondNegates reports whether the condition negates the selection.
func sigCondNegates(cond, name string) bool {
	re := regexp.MustCompile(`(?i)(^|\s)not\s+` + regexp.QuoteMeta(name) + `(\s|$)`)
	return re.MatchString(cond)
}

// rawCondition returns the explicit "condition" string when present.
func rawCondition(d map[string]any) (string, bool) {
	for k, v := range d {
		if strings.ToLower(k) == "condition" {
			if s, ok := v.(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

// lastWindow finds a "last: <window>" entry anywhere in the detection blocks.
func lastWindow(d map[string]any) (string, bool) {
	for _, v := range d {
		block, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for k, wv := range block {
			if strings.ToLower(k) == "last" {
				if s, ok := wv.(string); ok && s != "" {
					return s, true
				}
			}
		}
	}
	return "", false
}

// sigConvertBlock converts one named detection block into a selection.
func sigConvertBlock(name string, val any, su *sigUnsupported) (*sigSelection, error) {
	sel := &sigSelection{name: name}
	switch v := val.(type) {
	case map[string]any:
		for field, fv := range v {
			// Sigma's pipe syntax: `field|contains: value`
			if sub, mod, ok := strings.Cut(field, "|"); ok {
				preds, err := sigModifierPred(strings.TrimSpace(sub), strings.TrimSpace(mod), fv, su)
				if err != nil {
					return nil, err
				}
				sel.preds = append(sel.preds, preds...)
				continue
			}
			preds, err := sigFieldPreds(field, fv, su)
			if err != nil {
				return nil, err
			}
			sel.preds = append(sel.preds, preds...)
		}
	case []any:
		// A bare list under a named block is treated as a field OR-set only
		// when the block name is a field; otherwise unsupported.
		su.add(fmt.Sprintf("detection.%s: bare list block", name))
		return nil, fmt.Errorf("bare list")
	default:
		su.add(fmt.Sprintf("detection.%s: unsupported block type %T", name, val))
		return nil, fmt.Errorf("unsupported block")
	}
	return sel, nil
}

// sigModifierPred handles `field|contains`, `field|startswith`, `field|endswith`,
// `field|re`, `field|allfields`, `field|base64` value specs.
func sigModifierPred(field, mod string, fv any, su *sigUnsupported) ([]sigPred, error) {
	switch lk := strings.ToLower(mod); lk {
	case "contains", "startswith", "endswith":
		vals, ok := sigStringList(fv)
		if !ok {
			su.add(fmt.Sprintf("%s|%s: non-string values", field, lk))
			return nil, fmt.Errorf("non-string values")
		}
		preds := make([]sigPred, 0, len(vals))
		for _, s := range vals {
			preds = append(preds, sigPred{text: sigLikeExpr(field, s, lk), field: field, branch: "like"})
		}
		if len(preds) == 1 {
			return preds, nil
		}
		return parenJoin(preds, " OR ")
	case "re":
		su.add(fmt.Sprintf("%s|re: regular expressions are not supported", field))
		return nil, fmt.Errorf("re")
	case "allfields":
		su.add(fmt.Sprintf("%s|allfields: allfields matching is not supported", field))
		return nil, fmt.Errorf("allfields")
	case "base64":
		su.add(fmt.Sprintf("%s|base64: base64 matching is not supported", field))
		return nil, fmt.Errorf("base64")
	case "bindcontext":
		su.add(fmt.Sprintf("%s|bindcontext: bindcontext is not supported", field))
		return nil, fmt.Errorf("bindcontext")
	default:
		su.add(fmt.Sprintf("%s|%s: unsupported modifier", field, mod))
		return nil, fmt.Errorf("unsupported modifier")
	}
}

// sigFieldPreds converts one field's value spec into predicates.
func sigFieldPreds(field string, fv any, su *sigUnsupported) ([]sigPred, error) {
	// Modifier map: field: {contains: [...]}, {re: [...]}, {and: [...]}, {or: [...]}, {requires: [...]}
	if m, ok := fv.(map[string]any); ok {
		for key, mv := range m {
			lk := strings.ToLower(key)
			switch lk {
			case "contains", "startswith", "endswith":
				vals, ok := sigStringList(mv)
				if !ok {
					su.add(fmt.Sprintf("%s|%s: non-string values", field, lk))
					return nil, fmt.Errorf("non-string values")
				}
				preds := make([]sigPred, 0, len(vals))
				for _, s := range vals {
					preds = append(preds, sigPred{text: sigLikeExpr(field, s, lk), field: field, branch: "like"})
				}
				if len(preds) == 1 {
					return preds, nil
				}
				joined, err := parenJoin(preds, " OR ")
				return joined, err
			case "re":
				su.add(fmt.Sprintf("%s|re: regular expressions are not supported", field))
				return nil, fmt.Errorf("re")
			case "allfields":
				su.add(fmt.Sprintf("%s|allfields: allfields matching is not supported", field))
				return nil, fmt.Errorf("allfields")
			case "base64":
				su.add(fmt.Sprintf("%s|base64: base64 matching is not supported", field))
				return nil, fmt.Errorf("base64")
			case "bindcontext":
				su.add(fmt.Sprintf("%s|bindcontext: bindcontext is not supported", field))
				return nil, fmt.Errorf("bindcontext")
			case "and", "or", "requires":
				// Nested list of selection names or field conditions.
				items, ok := mv.([]any)
				if !ok {
					su.add(fmt.Sprintf("%s|%s: expected a list", field, lk))
					return nil, fmt.Errorf("expected list")
				}
				preds := make([]sigPred, 0, len(items))
				for _, it := range items {
					p, err := sigNestedItem(field, lk, it, su)
					if err != nil {
						return nil, err
					}
					preds = append(preds, p)
				}
				if len(preds) == 0 {
					return nil, nil
				}
				joined, err := parenJoin(preds, " AND ")
				return joined, err
			default:
				// field: {SomeOtherField: value} — treat the key as a sub-field.
				vals, ok := sigStringList(mv)
				if !ok {
					su.add(fmt.Sprintf("%s|%s: unsupported modifier map", field, key))
					return nil, fmt.Errorf("unsupported modifier")
				}
				preds := make([]sigPred, 0, len(vals))
				for _, s := range vals {
					preds = append(preds, sigPred{text: sigEqExpr(field+"."+key, s), field: field, branch: "eq"})
				}
				return preds, nil
			}
		}
		return nil, nil
	}
	// String value: "value", "contains value", "re value", ...
	if s, ok := fv.(string); ok {
		p, err := sigStringPred(field, s, su)
		if err != nil {
			return nil, err
		}
		return []sigPred{p}, nil
	}
	// Numeric value: EventID: 4688 → equality.
	switch n := fv.(type) {
	case int:
		return []sigPred{{text: sigEqExpr(field, strconv.Itoa(n)), field: field, branch: "eq"}}, nil
	case int64:
		return []sigPred{{text: sigEqExpr(field, strconv.FormatInt(n, 10)), field: field, branch: "eq"}}, nil
	case float64:
		if n == float64(int64(n)) {
			return []sigPred{{text: sigEqExpr(field, strconv.FormatInt(int64(n), 10)), field: field, branch: "eq"}}, nil
		}
		return []sigPred{{text: sigEqExpr(field, strconv.FormatFloat(n, 'f', -1, 64)), field: field, branch: "eq"}}, nil
	case bool:
		v := "false"
		if n {
			v = "true"
		}
		return []sigPred{{text: sigEqExpr(field, v), field: field, branch: "eq"}}, nil
	}
	// List of scalars: field: [a, b] → field in (...)
	list, ok := fv.([]any)
	if !ok {
		su.add(fmt.Sprintf("%s: unsupported value type %T", field, fv))
		return nil, fmt.Errorf("unsupported value type")
	}
	vals := make([]string, 0, len(list))
	for _, it := range list {
		if s, ok := it.(string); ok {
			vals = append(vals, s)
		} else if n, ok := it.(int); ok {
			vals = append(vals, strconv.Itoa(n))
		} else if n, ok := it.(float64); ok {
			vals = append(vals, strconv.FormatFloat(n, 'f', -1, 64))
		}
	}
	if len(vals) == 0 {
		return nil, nil
	}
	if len(vals) == 1 {
		return []sigPred{{text: sigEqExpr(field, vals[0]), field: field, branch: "eq"}}, nil
	}
	return []sigPred{{text: sigInExpr(field, vals), field: field, branch: "in"}}, nil
}

// sigNestedItem converts one item of a nested and/or/requires list.
func sigNestedItem(field, join string, it any, su *sigUnsupported) (sigPred, error) {
	switch v := it.(type) {
	case string:
		// Could be a selection reference or a "field: value" / "field|contains value" string.
		if strings.Contains(v, ":") {
			parts := strings.SplitN(v, ":", 2)
			subField := strings.TrimSpace(parts[0])
			subVal := strings.TrimSpace(parts[1])
			p, err := sigStringPred(subField, subVal, su)
			if err != nil {
				return sigPred{}, err
			}
			return p, nil
		}
		su.add(fmt.Sprintf("%s|%s: bare string item %q (selection refs are resolved in condition)", field, join, v))
		return sigPred{}, fmt.Errorf("bare string")
	case map[string]any:
		for f, fv := range v {
			preds, err := sigFieldPreds(f, fv, su)
			if err != nil {
				return sigPred{}, err
			}
			if len(preds) == 0 {
				continue
			}
			return preds[0], nil
		}
		su.add(fmt.Sprintf("%s|%s: empty nested condition", field, join))
		return sigPred{}, fmt.Errorf("empty nested")
	default:
		su.add(fmt.Sprintf("%s|%s: unsupported item type %T", field, join, it))
		return sigPred{}, fmt.Errorf("unsupported item")
	}
}

// sigStringPred handles "value", "contains value", "startswith value", "endswith value", "re value".
func sigStringPred(field, s string, su *sigUnsupported) (sigPred, error) {
	trimmed := strings.TrimSpace(s)
	for _, mod := range []string{"contains ", "startswith ", "endswith ", "re ", "allfields ", "base64 "} {
		if strings.HasPrefix(strings.ToLower(trimmed), mod) {
			val := strings.TrimSpace(trimmed[len(mod):])
			lk := strings.ToLower(strings.TrimSuffix(mod, " "))
			switch lk {
			case "contains", "startswith", "endswith":
				return sigPred{text: sigLikeExpr(field, val, lk), field: field, branch: "like"}, nil
			case "re":
				su.add(fmt.Sprintf("%s|re: regular expressions are not supported", field))
				return sigPred{}, fmt.Errorf("re")
			case "allfields":
				su.add(fmt.Sprintf("%s|allfields: allfields matching is not supported", field))
				return sigPred{}, fmt.Errorf("allfields")
			case "base64":
				su.add(fmt.Sprintf("%s|base64: base64 matching is not supported", field))
				return sigPred{}, fmt.Errorf("base64")
			}
		}
	}
	return sigPred{text: sigEqExpr(field, trimmed), field: field, branch: "eq"}, nil
}

func sigLikeExpr(field, val, mod string) string {
	esc := strings.ReplaceAll(val, "'", "''")
	like := "'%" + esc + "%'"
	switch mod {
	case "startswith":
		like = "'" + esc + "%'"
	case "endswith":
		like = "'%" + esc + "'"
	}
	return fmt.Sprintf("%s LIKE %s", sigFieldExpr(field), like)
}

func sigEqExpr(field, val string) string {
	return fmt.Sprintf("%s = '%s'", sigFieldExpr(field), strings.ReplaceAll(val, "'", "''"))
}

func sigInExpr(field string, vals []string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = "'" + strings.ReplaceAll(v, "'", "''") + "'"
	}
	return fmt.Sprintf("%s IN (%s)", sigFieldExpr(field), strings.Join(parts, ", "))
}

// sigFieldExpr renders a Sigma field as an SPL field reference. The SPL
// planner resolves identifiers verbatim (canonical column or flat
// attribute key), so no quoting is applied.
func sigFieldExpr(field string) string {
	return strings.TrimSpace(field)
}

func parenJoin(preds []sigPred, join string) ([]sigPred, error) {
	if len(preds) == 0 {
		return nil, nil
	}
	if len(preds) == 1 {
		return preds, nil
	}
	texts := make([]string, len(preds))
	for i, p := range preds {
		texts[i] = "(" + p.text + ")"
	}
	return []sigPred{{text: strings.Join(texts, " " + join + " ")}}, nil
}

func sigStringList(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return []string{t}, true
	case []any:
		out := make([]string, 0, len(t))
		for _, it := range t {
			if s, ok := it.(string); ok {
				out = append(out, s)
			} else {
				return nil, false
			}
		}
		return out, true
	}
	return nil, false
}

// sigCombine renders the combined where-clause and an optional event threshold.
func sigCombine(cond *sigCondition, selByName map[string]*sigSelection, sourceType string, su *sigUnsupported) (string, int, error) {
	_ = sourceType

	negSet := map[string]bool{}
	for _, n := range cond.negative {
		negSet[n] = true
	}

	// "N of them" semantics.
	if cond.allOfThem || (cond.ofThem > 0 && cond.ofThem == len(cond.terms)) {
		// "all of them" (or N == M) → every selection must match.
		return sigAndTerms(cond.terms, selByName), 0, nil
	}
	if cond.ofThem > 0 {
		// "any of them" → disjunction of the selections.
		if cond.orGroup {
			joins := []string{}
			for _, name := range cond.terms {
				sel := selByName[name]
				if len(sel.preds) == 0 {
					continue
				}
				joins = append(joins, "("+strings.Join(sel.predTexts(), " AND ")+")")
			}
			if len(joins) == 0 {
				return "", 0, nil
			}
			return sigApplyNegation(strings.Join(joins, " OR "), cond, selByName), 0, nil
		}
		// "N of them" with a single-predicate selection is an event count
		// threshold within the window.
		if len(cond.terms) == 1 {
			sel := selByName[cond.terms[0]]
			if len(sel.preds) == 1 {
				return sel.preds[0].text, cond.ofThem, nil
			}
		}
		su.add(fmt.Sprintf("condition: %d of %d selections is not supported", cond.ofThem, len(cond.terms)))
		return "", 0, fmt.Errorf("of-them")
	}

	// Plain conjunction / disjunction (negated terms applied last).
	joins := []string{}
	for _, name := range cond.terms {
		if negSet[name] {
			continue
		}
		sel := selByName[name]
		if len(sel.preds) == 0 {
			continue
		}
		if cond.orGroup {
			joins = append(joins, "("+strings.Join(sel.predTexts(), " AND ")+")")
		} else {
			joins = append(joins, sel.predTexts()...)
		}
	}
	if len(joins) == 0 {
		if len(cond.negative) == 0 {
			return "", 0, nil
		}
	}
	joiner := " AND "
	if cond.orGroup {
		joiner = " OR "
	}
	return sigApplyNegation(strings.Join(joins, joiner), cond, selByName), 0, nil
}

// sigPredGroup returns a selection's predicates as individual join parts.
func sigPredGroup(sel *sigSelection) []string {
	return sel.predTexts()
}

// sigApplyNegation wraps NOT(selection) terms into the combined predicate.
func sigApplyNegation(combined string, cond *sigCondition, selByName map[string]*sigSelection) string {
	if len(cond.negative) == 0 {
		return combined
	}
	extra := []string{}
	for _, name := range cond.negative {
		sel := selByName[name]
		if len(sel.preds) == 0 {
			continue
		}
		extra = append(extra, "NOT ("+strings.Join(sel.predTexts(), " AND ")+")")
	}
	if len(extra) == 0 {
		return combined
	}
	return combined + " AND " + strings.Join(extra, " AND ")
}

func (s *sigSelection) predTexts() []string {
	out := make([]string, 0, len(s.preds))
	for _, p := range s.preds {
		out = append(out, p.text)
	}
	return out
}

func sigAndTerms(terms []string, selByName map[string]*sigSelection) string {
	var out []sigPred
	for _, name := range terms {
		sel := selByName[name]
		out = append(out, sel.preds...)
	}
	if len(out) == 0 {
		return ""
	}
	texts := make([]string, len(out))
	for i, p := range out {
		texts[i] = p.text
	}
	return strings.Join(texts, " AND ")
}

// mapSigmaLogSource maps a Sigma logsource to a Quetzalog source_type.
func mapSigmaLogSource(ls SigmaLogSource, su *sigUnsupported) (string, error) {
	product := strings.ToLower(strings.TrimSpace(ls.Product))
	category := strings.ToLower(strings.TrimSpace(ls.Category))
	switch {
	case product == "windows":
		switch category {
		case "security":
			return "os.windows.security", nil
		case "sysmon":
			return "os.windows.sysmon", nil
		case "powershell":
			return "os.windows.powershell", nil
		case "system":
			return "os.windows.system", nil
		case "":
			return "os.windows.security", nil
		default:
			su.add(fmt.Sprintf("logsource: windows category %q not mappable", category))
			return "", fmt.Errorf("logsource")
		}
	case product == "linux":
		switch category {
		case "auditd":
			return "os.linux.auditd", nil
		case "auth", "sshd":
			return "os.linux.sshd", nil
		case "process":
			return "os.linux.process", nil
		case "":
			return "os.linux.auditd", nil
		default:
			su.add(fmt.Sprintf("logsource: linux category %q not mappable", category))
			return "", fmt.Errorf("logsource")
		}
	case product == "darwin":
		return "os.darwin.unified", nil
	case product == "webserver", product == "web-server":
		switch category {
		case "nginx", "":
			return "web.nginx.access", nil
		case "apache", "iis":
			return "web.apache.access", nil
		default:
			su.add(fmt.Sprintf("logsource: webserver category %q not mappable", category))
			return "", fmt.Errorf("logsource")
		}
	case product == "firewall", product == "net":
		return "net.firewall.generic", nil
	case product == "dns":
		return "net.dns.generic", nil
	case product == "kerberos":
		return "id.kerberos", nil
	case product == "cloud":
		return "cloud.generic", nil
	case product == "", category == "":
		su.add("logsource: product/category not mappable to a source_type")
		return "", fmt.Errorf("logsource")
	default:
		// Unknown product: fall back to service if present.
		if ls.Service != "" {
			return "generic." + strings.ToLower(ls.Service), nil
		}
		su.add(fmt.Sprintf("logsource: product %q not mappable to a source_type", product))
		return "", fmt.Errorf("logsource")
	}
}

// mapSigmaLevel maps Sigma levels to Quetzalog severities.
func mapSigmaLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical", "emergency":
		return "critical"
	case "high", "error":
		return "high"
	case "medium", "warning":
		return "medium"
	case "low", "informational", "info", "notice":
		return "low"
	default:
		return "medium"
	}
}

// sigTacticNames maps MITRE tactic names to tactic IDs (Sigma tags use the
// name, e.g. attack.execution → TA0002).
var sigTacticNames = map[string]string{
	"initial-access":      "TA0001",
	"execution":           "TA0002",
	"persistence":         "TA0003",
	"privilege-escalation": "TA0004",
	"defense-evasion":     "TA0005",
	"credential-access":   "TA0006",
	"discovery":           "TA0007",
	"lateral-movement":    "TA0008",
	"collection":          "TA0009",
	"exfiltration":        "TA0010",
	"command-and-control": "TA0011",
	"impact":              "TA0040",
	"reconnaissance":      "TA0043",
}

var sigTechRe = regexp.MustCompile(`^t\d+(\.\d+)?`)

// sigMitreTags extracts MITRE tactic/technique from Sigma tags
// (attack.tactic.<name>, attack.<name>, attack.t<id>).
func sigMitreTags(tags []string) (tactic, technique string, rest []string) {
	rest = []string{}
	for _, t := range tags {
		lower := strings.ToLower(t)
		if strings.HasPrefix(lower, "attack.tactic.") {
			if code, ok := sigTacticNames[taNorm(strings.TrimPrefix(lower, "attack.tactic."))]; ok && tactic == "" {
				tactic = code
			}
			continue
		}
		if strings.HasPrefix(lower, "attack.") {
			v := strings.TrimPrefix(lower, "attack.")
			if m := sigTechRe.FindString(v); m != "" {
				if technique == "" {
					technique = "T" + m[1:]
				}
				continue
			}
			if code, ok := sigTacticNames[taNorm(v)]; ok && tactic == "" {
				tactic = code
				continue
			}
		}
		rest = append(rest, t)
	}
	return tactic, technique, rest
}

// taNorm normalizes a tactic name (Sigma uses underscores: credential_access).
func taNorm(name string) string {
	return strings.ReplaceAll(name, "_", "-")
}
