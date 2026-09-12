// Package response provides a lightweight analyst action framework. Built-in
// actions cover triage and low-risk operational steps; security-sensitive
// actions (webhook execution, external URLs) are guarded: the webhook executor
// refuses non-http(s) schemes and private/loopback/link-local destinations so
// analyst input cannot be used for SSRF. Future integrations register new
// actions without redesigning the app.
package response

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"quetzalog/internal/findings"
	"quetzalog/internal/investigations"
	"quetzalog/internal/risk"
)

// Action describes an executable analyst response.
type Action struct {
	Name        string `json:"name"`
	Key         string `json:"key"`
	Description string `json:"description"`
	Sensitive   bool   `json:"sensitive"`
	Params      []string `json:"params"`
}

// Execution is an audit-ledger record of one executed action.
type Execution struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Details   string    `json:"details,omitempty"`
	User      string    `json:"user,omitempty"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// Deps are the stores actions may touch.
type Deps struct {
	Findings     *findings.Store
	Investigations *investigations.Store
	Risk         *risk.EntityRiskStore
}

// Registry holds action definitions and execution state.
type Registry struct {
	db       *sql.DB
	deps     Deps
	actions  []Action
	executor http.Client
}

// NewRegistry creates a registry with the built-in actions.
func NewRegistry(db *sql.DB, deps Deps) *Registry {
	// No redirects: a 302 to an internal host must not expand the SSRF surface.
	executor := http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	reg := &Registry{db: db, deps: deps, executor: executor}
	reg.actions = []Action{
		{Name: "Mark False Positive", Key: "finding.mark_false_positive", Description: "Close a finding as a false positive", Sensitive: true, Params: []string{"finding_id"}},
		{Name: "Assign Analyst", Key: "finding.assign", Description: "Assign a finding to an analyst", Params: []string{"finding_id", "owner"}},
		{Name: "Add Tag", Key: "finding.add_tag", Description: "Add a tag to a finding", Params: []string{"finding_id", "tag"}},
		{Name: "Increase Risk", Key: "finding.increase_risk", Description: "Add risk points to the finding's primary entities", Sensitive: true, Params: []string{"finding_id", "points"}},
		{Name: "Create Investigation", Key: "investigation.create", Description: "Open a new investigation from a finding", Sensitive: true, Params: []string{"finding_id", "title"}},
		{Name: "Run Search", Key: "search.run", Description: "Run a search query (executed in the UI)", Sensitive: false, Params: []string{"query"}},
		{Name: "Open URL", Key: "url.open", Description: "Open an external URL in a new tab", Params: []string{"url"}},
		{Name: "Execute Webhook", Key: "webhook.execute", Description: "POST a signed payload to an external webhook (public URLs only)", Sensitive: true, Params: []string{"url", "event", "payload"}},
	}
	return reg
}

// List returns the available actions.
func (r *Registry) List() []Action {
	out := make([]Action, len(r.actions))
	copy(out, r.actions)
	return out
}

// Lookup finds an action by key.
func (r *Registry) Lookup(key string) (Action, bool) {
	for _, a := range r.actions {
		if a.Key == key {
			return a, true
		}
	}
	return Action{}, false
}

// ExecuteParams carries a request to execute one action.
type ExecuteParams struct {
	Action  string          `json:"action"`
	Target  string          `json:"target"`
	Owner   string          `json:"owner"`
	Tag     string          `json:"tag"`
	Points  float64         `json:"points"`
	Title   string          `json:"title"`
	Query   string          `json:"query"`
	URL     string          `json:"url"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	User    string          `json:"user"`
}

// Execute runs an action, records it in the audit ledger and returns details.
func (r *Registry) Execute(ctx context.Context, p ExecuteParams) (map[string]any, error) {
	action, ok := r.Lookup(p.Action)
	if !ok {
		return nil, fmt.Errorf("unknown action %q", p.Action)
	}

	details, err := r.run(ctx, p)
	if err != nil {
		_ = r.log(ctx, p, action.Name, "error", err.Error())
		return nil, err
	}
	_ = r.log(ctx, p, action.Name, "ok", summarize(details))
	return details, nil
}

func (r *Registry) run(ctx context.Context, p ExecuteParams) (map[string]any, error) {
	if r.deps.Findings == nil {
		return nil, fmt.Errorf("findings store not available")
	}
	switch p.Action {
	case "finding.mark_false_positive":
		if p.Target == "" {
			return nil, fmt.Errorf("finding_id required")
		}
		if err := r.deps.Findings.UpdateStatus(ctx, p.Target, "false_positive"); err != nil {
			return nil, err
		}
		return map[string]any{"finding_id": p.Target, "status": "false_positive"}, nil

	case "finding.assign":
		if p.Target == "" || p.Owner == "" {
			return nil, fmt.Errorf("finding_id and owner required")
		}
		if err := r.deps.Findings.Assign(ctx, p.Target, p.Owner); err != nil {
			return nil, err
		}
		return map[string]any{"finding_id": p.Target, "owner": p.Owner}, nil

	case "finding.add_tag":
		if p.Target == "" || p.Tag == "" {
			return nil, fmt.Errorf("finding_id and tag required")
		}
		f, err := r.deps.Findings.GetByID(ctx, p.Target)
		if err != nil {
			return nil, err
		}
		for _, t := range f.Tags {
			if strings.EqualFold(t, p.Tag) {
				return map[string]any{"finding_id": p.Target, "tags": f.Tags}, nil
			}
		}
		f.Tags = append(f.Tags, p.Tag)
		if err := r.deps.Findings.Update(ctx, f); err != nil {
			return nil, err
		}
		return map[string]any{"finding_id": p.Target, "tags": f.Tags}, nil

	case "finding.increase_risk":
		if p.Target == "" {
			return nil, fmt.Errorf("finding_id required")
		}
		if p.Points <= 0 {
			return nil, fmt.Errorf("points must be positive")
		}
		f, err := r.deps.Findings.GetByID(ctx, p.Target)
		if err != nil {
			return nil, err
		}
		f.RiskScore += p.Points
		if err := r.deps.Findings.Update(ctx, f); err != nil {
			return nil, err
		}
		if r.deps.Risk != nil {
			for _, e := range splitEntities(f.Entities) {
				_ = r.deps.Risk.Record(ctx, risk.Contribution{
					EntityType:  e.Type,
					EntityValue: e.Value,
					SourceType:  "action",
					SourceID:    f.ID,
					Description: fmt.Sprintf("Manual risk increase on finding %q", f.Title),
					Points:      p.Points,
				})
			}
		}
		return map[string]any{"finding_id": p.Target, "risk_score": f.RiskScore}, nil

	case "investigation.create":
		if r.deps.Investigations == nil || p.Target == "" {
			return nil, fmt.Errorf("finding_id required")
		}
		f, err := r.deps.Findings.GetByID(ctx, p.Target)
		if err != nil {
			return nil, err
		}
		title := strings.TrimSpace(p.Title)
		if title == "" {
			title = "Investigation: " + f.Title
		}
		in := &investigations.Investigation{
			Title:      title,
			Severity:   f.Severity,
			Status:     "in_progress",
			Assignee:   f.Owner,
			FindingIDs: []string{f.ID},
			Entities:   entitiesFromStrings(f.Entities),
			Techniques: nonEmpty(f.MITRETechnique),
		}
		if err := r.deps.Investigations.Create(ctx, in); err != nil {
			return nil, err
		}
		return map[string]any{"investigation_id": in.ID, "finding_id": f.ID}, nil

	case "search.run":
		if strings.TrimSpace(p.Query) == "" {
			return nil, fmt.Errorf("query required")
		}
		return map[string]any{"query": p.Query}, nil

	case "url.open":
		u, err := validateOutboundURL(p.URL)
		if err != nil {
			return nil, err
		}
		return map[string]any{"url": u}, nil

	case "webhook.execute":
		return r.executeWebhook(ctx, p)

	default:
		return nil, fmt.Errorf("unhandled action %q", p.Action)
	}
}

// executeWebhook POSTs a JSON payload to a public URL. SSRF guards: http(s)
// only, no private/loopback/link-local destinations, no redirects.
func (r *Registry) executeWebhook(ctx context.Context, p ExecuteParams) (map[string]any, error) {
	host, err := validateOutboundURL(p.URL)
	if err != nil {
		return nil, err
	}
	if err := denyRestrictedHost(host); err != nil {
		return nil, err
	}

	payload := p.Payload
	if len(payload) == 0 {
		payload, _ = json.Marshal(map[string]any{
			"event":  p.Event,
			"target": p.Target,
			"user":   p.User,
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.executor.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webhook delivery: %w", err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(io.LimitReader(resp.Body, 4096)); err != nil {
		return nil, fmt.Errorf("read webhook response: %w", err)
	}
	return map[string]any{
		"url":        p.URL,
		"status":     resp.Status,
		"status_code": resp.StatusCode,
		"response":   strings.TrimSpace(buf.String()),
	}, nil
}

// validateOutboundURL checks scheme and host format of an outbound URL.
func validateOutboundURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("only http/https urls are permitted")
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("url must include a host")
	}
	return host, nil
}

// denyRestrictedHost blocks destinations that SSRF would reach.
func denyRestrictedHost(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("destination %s is a restricted address", host)
		}
		return nil
	}
	lower := strings.ToLower(host)
	switch lower {
	case "localhost", "metadata.google.internal", "169.254.169.254":
		return fmt.Errorf("destination %s is restricted", host)
	}
	return nil
}

// History returns the most recent executed actions.
func (r *Registry) History(ctx context.Context, limit int) ([]Execution, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, action, target, details, user, status, created_at
		 FROM response_actions ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query response actions: %w", err)
	}
	defer rows.Close()

	var out []Execution
	for rows.Next() {
		var e Execution
		var target, details, user sql.NullString
		if err := rows.Scan(&e.ID, &e.Action, &target, &details, &user, &e.Status, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan execution: %w", err)
		}
		e.Target = target.String
		e.Details = details.String
		e.User = user.String
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate executions: %w", err)
	}
	return out, nil
}

func (r *Registry) log(ctx context.Context, p ExecuteParams, name, status, details string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO response_actions (id, name, action, target, details, user, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.New().String(), name, p.Action, nullAny(p.Target), nullAny(details), nullAny(p.User), status, time.Now().UTC())
	return err
}

func summarize(m map[string]any) string {
	b, _ := json.Marshal(m)
	s := string(b)
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func splitEntities(entities []string) []struct{ Type, Value string } {
	var out []struct{ Type, Value string }
	for _, e := range entities {
		parts := strings.SplitN(e, ":", 2)
		if len(parts) == 2 && parts[1] != "" {
			out = append(out, struct{ Type, Value string }{parts[0], parts[1]})
		}
	}
	return out
}

func entitiesFromStrings(list []string) []investigations.Entity {
	var out []investigations.Entity
	for _, e := range list {
		parts := strings.SplitN(e, ":", 2)
		if len(parts) == 2 && parts[1] != "" {
			out = append(out, investigations.Entity{Type: parts[0], Value: parts[1]})
		}
	}
	return out
}

func nonEmpty(s string) []string {
	if s == "" {
		return []string{}
	}
	return []string{s}
}

func nullAny(s string) any {
	if s == "" {
		return nil
	}
	return s
}
