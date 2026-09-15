package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AbuseChConfig configures the Abuse.ch provider. No API key is required
// for the public feed endpoints.
type AbuseChConfig struct {
	// BaseURL defaults to https://urlhaus.abuse.ch / https://threatfox.abuse.ch
	// via the two well-known hosts; it exists for tests.
	BaseURL   string        `json:"-"`
	UserAgent string
	Timeout   time.Duration
}

// AbuseChProvider pulls URLhaus + ThreatFox entries. Every item is
// validated and quarantined: malformed entries are dropped, never stored.
type AbuseChProvider struct {
	cfg      AbuseChConfig
	http     *http.Client
	urlhaus  string
	threatfox string
}

// NewAbuseChProvider creates the provider. An empty BaseURL selects the
// public production endpoints.
func NewAbuseChProvider(cfg AbuseChConfig) *AbuseChProvider {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "quetzalog-threatintel/1.0"
	}
	// When a base URL is supplied (tests, mirrors) both feeds are served
	// from it; otherwise the two production hosts are used.
	urlhausHost, foxHost := "https://urlhaus.abuse.ch", "https://threatfox.abuse.ch"
	if cfg.BaseURL != "" {
		urlhausHost, foxHost = cfg.BaseURL, cfg.BaseURL
	}
	return &AbuseChProvider{
		cfg:       cfg,
		http:      &http.Client{Timeout: cfg.Timeout},
		urlhaus:   urlhausHost + "/urlhaus/api.php",
		threatfox: foxHost + "/threatfox/api.php",
	}
}

// Name returns the provider name.
func (p *AbuseChProvider) Name() string { return "abuse-ch" }

// urlhausEntry is one URLhaus API record.
type urlhausEntry struct {
	URL       string `json:"url"`
	Threat    string `json:"threat"`
	Status    string `json:"urlstatus"`
	LastSeen  string `json:"lastseen"`
}

// threatfoxEntry is one ThreatFox API record.
type threatfoxEntry struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Threat     string `json:"threat"`
	Confidence int    `json:"confidence"`
	FirstSeen  string `json:"firstseen"`
}

// Sync fetches both feeds and returns validated indicators.
func (p *AbuseChProvider) Sync(ctx context.Context) ([]InIndicator, error) {
	out := []InIndicator{}

	entries, err := p.fetchURLhaus(ctx)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: %w", err)
	}
	for _, e := range entries {
		url := strings.TrimSpace(e.URL)
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			continue
		}
		out = append(out, InIndicator{
			Type:        "url",
			Value:       url,
			Severity:    "medium",
			Description: "URLhaus: " + strings.TrimSpace(e.Threat),
			Source:      "abuse-ch/urlhaus",
			Confidence:  0.7,
			Reliability: 0.9,
		})
	}

	fox, err := p.fetchThreatFox(ctx)
	if err != nil {
		return nil, fmt.Errorf("threatfox: %w", err)
	}
	for _, e := range fox {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			continue
		}
		typ, ok := mapThreatFoxType(e.Type)
		if !ok {
			continue
		}
		conf := float64(e.Confidence) / 100.0
		if conf < 0 {
			conf = 0
		}
		if conf > 1 {
			conf = 1
		}
		out = append(out, InIndicator{
			Type:        typ,
			Value:       name,
			Severity:    "medium",
			Description: "ThreatFox: " + strings.TrimSpace(e.Threat),
			Source:      "abuse-ch/threatfox",
			Confidence:  conf,
			Reliability: 0.9,
		})
	}
	return out, nil
}

func mapThreatFoxType(typ string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "domain":
		return "domain", true
	case "ip":
		return "ip", true
	case "malicious url", "url":
		return "url", true
	case "email":
		return "email", true
	case "md5", "sha1", "sha256", "file":
		return "hash", true
	}
	return "", false
}

func (p *AbuseChProvider) getJSON(ctx context.Context, url string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", p.cfg.UserAgent)
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dest)
}

func (p *AbuseChProvider) fetchURLhaus(ctx context.Context) ([]urlhausEntry, error) {
	var entries []urlhausEntry
	if err := p.getJSON(ctx, p.urlhaus, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (p *AbuseChProvider) fetchThreatFox(ctx context.Context) ([]threatfoxEntry, error) {
	var payload struct {
		Data []threatfoxEntry `json:"data"`
	}
	if err := p.getJSON(ctx, p.threatfox, &payload); err != nil {
		return nil, err
	}
	return payload.Data, nil
}
