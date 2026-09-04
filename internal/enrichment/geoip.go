package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"quetzalog/pkg/event"
)

// GeoIPConfig holds configuration for GeoIP enrichment.
type GeoIPConfig struct {
	APIKey  string
	DBPath  string // path to local GeoIP2 database file (MaxMind)
	Enabled bool
	Timeout time.Duration
	UseCache bool
	CacheSize int // max cached results
}

// GeoIPEntry holds geolocation information for an IP address.
type GeoIPEntry struct {
	City      string  `json:"city"`
	Region    string  `json:"region"`
	Country   string  `json:"country"`
	CountryCode string `json:"country_code"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ISP       string  `json:"isp"`
	ASN       string  `json:"asn"`
}

// GeoIPEnricher provides GeoIP enrichment using an external API or local database.
type GeoIPEnricher struct {
	config GeoIPConfig
	client *http.Client
	cache  map[string]*GeoIPEntry
	mu     sync.RWMutex
}

// NewGeoIPEnricher creates a new GeoIPEnricher with the given configuration.
func NewGeoIPEnricher(config GeoIPConfig) (*GeoIPEnricher, error) {
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}

	g := &GeoIPEnricher{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		cache: make(map[string]*GeoIPEntry),
	}

	if config.CacheSize > 0 {
		g.cache = make(map[string]*GeoIPEntry, config.CacheSize)
	}

	if config.UseCache {
		if err := g.loadCache(); err != nil {
			return nil, fmt.Errorf("load cache: %w", err)
		}
	}

	return g, nil
}

// Name returns the name of the enricher.
func (g *GeoIPEnricher) Name() string {
	return "geoip"
}

// Enrich adds geographic information to the event based on its source IP.
func (g *GeoIPEnricher) Enrich(ctx context.Context, ev *event.Event) error {
	if !g.config.Enabled {
		return nil
	}

	if ev.SourceIP == "" {
		return nil
	}

	// Check cache first
	g.mu.RLock()
	if entry, ok := g.cache[ev.SourceIP]; ok {
		g.mu.RUnlock()
		if ev.Attributes == nil {
			ev.Attributes = make(map[string]any)
		}
		ev.Attributes["geoip.city"] = entry.City
		ev.Attributes["geoip.country"] = entry.Country
		ev.Attributes["geoip.country_code"] = entry.CountryCode
		ev.Attributes["geoip.latitude"] = entry.Latitude
		ev.Attributes["geoip.longitude"] = entry.Longitude
		ev.Attributes["geoip.isp"] = entry.ISP
		ev.Attributes["geoip.asn"] = entry.ASN
		return nil
	}
	g.mu.RUnlock()

	// Use local database if available
	if g.config.DBPath != "" {
		return g.lookupLocal(ev)
	}

	// Use API
	return g.lookupAPI(ctx, ev)
}

type geoAPIResponse struct {
	Status    string  `json:"status"`
	City      string  `json:"city"`
	Region    string  `json:"regionName"`
	Country   string  `json:"country"`
	CountryCode string `json:"countryCode"`
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	ISP       string  `json:"isp"`
	AS        string  `json:"as"`
}

func (g *GeoIPEnricher) lookupAPI(ctx context.Context, ev *event.Event) error {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=city,country,lat,lon,isp,as,countryCode", ev.SourceIP)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil // Silently skip if API fails
	}

	var result geoAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}

	if result.Status != "success" {
		return nil
	}

	entry := &GeoIPEntry{
		City:        result.City,
		Region:      result.Region,
		Country:     result.Country,
		CountryCode: result.CountryCode,
		Latitude:    result.Lat,
		Longitude:   result.Lon,
		ISP:         result.ISP,
		ASN:         result.AS,
	}

	// Update event
	if ev.Attributes == nil {
		ev.Attributes = make(map[string]any)
	}
	ev.Attributes["geoip.city"] = entry.City
	ev.Attributes["geoip.country"] = entry.Country
	ev.Attributes["geoip.country_code"] = entry.CountryCode
	ev.Attributes["geoip.latitude"] = entry.Latitude
	ev.Attributes["geoip.longitude"] = entry.Longitude
	ev.Attributes["geoip.isp"] = entry.ISP
	ev.Attributes["geoip.asn"] = entry.ASN

	// Cache if enabled
	g.mu.Lock()
	g.cache[ev.SourceIP] = entry
	g.mu.Unlock()

	return nil
}

type geoIPRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Postal  string `maxminddb:"postal"`
	Subdivisions []struct {
		ISOCode   string `maxminddb:"iso_code"`
		Names     map[string]string `maxminddb:"names"`
		GeoNameID *int `maxminddb:"geoname_id"`
	} `maxminddb:"subdivisions"`
	IP struct {
		ASN        int    `maxminddb:"autonomous_system_number"`
		Organization string `maxminddb:"autonomous_system_organization"`
	} `maxminddb:"ip,omitempty"`
}

func (g *GeoIPEnricher) lookupLocal(ev *event.Event) error {
	db, err := maxminddb.Open(g.config.DBPath)
	if err != nil {
		ev.Attributes["geoip.status"] = "db_open_error"
		return fmt.Errorf("open geoip db: %w", err)
	}
	defer db.Close()

	var record geoIPRecord
	ip := net.ParseIP(ev.SourceIP)
	if ip == nil {
		return nil
	}

	if err := db.Lookup(ip, &record); err != nil {
		return fmt.Errorf("lookup: %w", err)
	}

	city := ""
	if record.City.Names != nil {
		city = record.City.Names["en"]
	}
	country := ""
	if record.Country.Names != nil {
		country = record.Country.Names["en"]
	}
	countryCode := record.Country.ISOCode
	region := ""
	if len(record.Subdivisions) > 0 && record.Subdivisions[0].Names != nil {
		region = record.Subdivisions[0].Names["en"]
	}
	lat := record.Location.Latitude
	lon := record.Location.Longitude
	isp := ""
	if record.IP.ASN > 0 {
		isp = record.IP.Organization
	}
	asn := fmt.Sprintf("AS%d", record.IP.ASN)

	entry := &GeoIPEntry{
		City:      city,
		Region:    region,
		Country:   country,
		CountryCode: countryCode,
		Latitude:  lat,
		Longitude: lon,
		ISP:       isp,
		ASN:       asn,
	}

	if ev.Attributes == nil {
		ev.Attributes = make(map[string]any)
	}
	ev.Attributes["geoip.city"] = entry.City
	ev.Attributes["geoip.country"] = entry.Country
	ev.Attributes["geoip.country_code"] = entry.CountryCode
	ev.Attributes["geoip.latitude"] = entry.Latitude
	ev.Attributes["geoip.longitude"] = entry.Longitude
	ev.Attributes["geoip.isp"] = entry.ISP
	ev.Attributes["geoip.asn"] = entry.ASN
	ev.Attributes["geoip.status"] = "resolved"

	// Cache if enabled
	g.mu.Lock()
	g.cache[ev.SourceIP] = entry
	g.mu.Unlock()

	return nil
}

// SaveCache persists the GeoIP cache to disk.
func (g *GeoIPEnricher) SaveCache() error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	data, err := json.Marshal(g.cache)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	return os.WriteFile(".geoip_cache.json", data, 0600)
}

func (g *GeoIPEnricher) loadCache() error {
	data, err := os.ReadFile(".geoip_cache.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read cache: %w", err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if err := json.Unmarshal(data, &g.cache); err != nil {
		return fmt.Errorf("unmarshal cache: %w", err)
	}

	return nil
}
