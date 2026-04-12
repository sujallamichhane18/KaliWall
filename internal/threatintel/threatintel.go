// Package threatintel provides reputation lookups via the VirusTotal API.
// It caches results to avoid hammering the API (free tier: 4 req/min).
package threatintel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Verdict summarises the VirusTotal reputation of an IP address.
type Verdict struct {
	IP          string    `json:"ip"`
	Malicious   int       `json:"malicious"`
	Suspicious  int       `json:"suspicious"`
	Harmless    int       `json:"harmless"`
	Undetected  int       `json:"undetected"`
	Reputation  int       `json:"reputation"`
	Country     string    `json:"country"`
	Owner       string    `json:"owner"`
	ThreatLevel string    `json:"threat_level"` // safe, suspicious, malicious
	CheckedAt   time.Time `json:"checked_at"`
}

// IndicatorVerdict summarizes VirusTotal verdict for a domain or URL.
type IndicatorVerdict struct {
	Indicator     string    `json:"indicator"`
	IndicatorType string    `json:"indicator_type"` // domain, url
	Malicious     int       `json:"malicious"`
	Suspicious    int       `json:"suspicious"`
	Harmless      int       `json:"harmless"`
	Undetected    int       `json:"undetected"`
	Reputation    int       `json:"reputation"`
	ThreatLevel   string    `json:"threat_level"`
	CheckedAt     time.Time `json:"checked_at"`
}

// DomainURLAssessment contains both domain-level and URL-level VT checks.
type DomainURLAssessment struct {
	Domain IndicatorVerdict `json:"domain"`
	URL    IndicatorVerdict `json:"url"`
	Error  string           `json:"error,omitempty"`
}

// Service manages VirusTotal API key and caches lookup results.
type Service struct {
	mu          sync.RWMutex
	apiKey      string
	cache       map[string]Verdict           // ip -> verdict
	domainCache map[string]IndicatorVerdict  // domain -> verdict
	urlCache    map[string]IndicatorVerdict  // normalized URL -> verdict
	cacheTTL    time.Duration
	client      *http.Client
}

// New creates a new threat intel service.
func New() *Service {
	return &Service{
		cache:       make(map[string]Verdict),
		domainCache: make(map[string]IndicatorVerdict),
		urlCache:    make(map[string]IndicatorVerdict),
		cacheTTL:    30 * time.Minute,
		client:      &http.Client{Timeout: 15 * time.Second},
	}
}

// SetAPIKey stores the VirusTotal API key.
func (s *Service) SetAPIKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKey = key
	s.cache = make(map[string]Verdict)
	s.domainCache = make(map[string]IndicatorVerdict)
	s.urlCache = make(map[string]IndicatorVerdict)
}

// HasAPIKey returns whether an API key is configured.
func (s *Service) HasAPIKey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.apiKey != ""
}

// CheckIP looks up an IP against VirusTotal.
// Returns a cached result if available, otherwise queries the API.
func (s *Service) CheckIP(ip string) (Verdict, error) {
	if isPrivateIP(ip) {
		return Verdict{IP: ip, ThreatLevel: "internal", CheckedAt: time.Now()}, nil
	}

	s.mu.RLock()
	if v, ok := s.cache[ip]; ok && time.Since(v.CheckedAt) < s.cacheTTL {
		s.mu.RUnlock()
		return v, nil
	}
	key := s.apiKey
	s.mu.RUnlock()

	if key == "" {
		return Verdict{IP: ip, ThreatLevel: "unknown"}, fmt.Errorf("no API key configured")
	}

	url := "https://www.virustotal.com/api/v3/ip_addresses/" + ip
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("x-apikey", key)

	resp, err := s.client.Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("VT API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return Verdict{IP: ip, ThreatLevel: "rate_limited"}, fmt.Errorf("VirusTotal rate limit exceeded")
	}
	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("VT API returned status %d", resp.StatusCode)
	}

	var result vtResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return Verdict{}, fmt.Errorf("failed to parse VT response: %w", err)
	}

	stats := result.Data.Attributes.LastAnalysisStats
	verdict := Verdict{
		IP:          ip,
		Malicious:   stats.Malicious,
		Suspicious:  stats.Suspicious,
		Harmless:    stats.Harmless,
		Undetected:  stats.Undetected,
		Reputation:  result.Data.Attributes.Reputation,
		Country:     result.Data.Attributes.Country,
		Owner:       result.Data.Attributes.ASOwner,
		ThreatLevel: threatLevelFromStats(stats.Malicious, stats.Suspicious),
		CheckedAt:   time.Now(),
	}

	s.mu.Lock()
	s.cache[ip] = verdict
	s.mu.Unlock()

	return verdict, nil
}

// CheckDomainAndURL checks both domain and URL indicators via VirusTotal.
func (s *Service) CheckDomainAndURL(domain, rawURL string) (DomainURLAssessment, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	rawURL = strings.TrimSpace(rawURL)
	out := DomainURLAssessment{}

	if domain != "" {
		v, err := s.CheckDomain(domain)
		out.Domain = v
		if err != nil {
			out.Error = err.Error()
		}
	}

	if rawURL != "" {
		v, err := s.CheckURL(rawURL)
		out.URL = v
		if err != nil {
			if out.Error != "" {
				out.Error += "; " + err.Error()
			} else {
				out.Error = err.Error()
			}
		}
	}

	if out.Error != "" {
		return out, fmt.Errorf(out.Error)
	}
	return out, nil
}

// CheckDomain checks a domain indicator via VirusTotal.
func (s *Service) CheckDomain(domain string) (IndicatorVerdict, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return IndicatorVerdict{}, fmt.Errorf("domain is empty")
	}

	s.mu.RLock()
	if v, ok := s.domainCache[domain]; ok && time.Since(v.CheckedAt) < s.cacheTTL {
		s.mu.RUnlock()
		return v, nil
	}
	key := s.apiKey
	s.mu.RUnlock()

	if key == "" {
		return IndicatorVerdict{Indicator: domain, IndicatorType: "domain", ThreatLevel: "unknown", CheckedAt: time.Now()}, fmt.Errorf("no API key configured")
	}

	apiURL := "https://www.virustotal.com/api/v3/domains/" + domain
	verdict, err := s.checkIndicator(apiURL, key, domain, "domain")
	if err != nil {
		return verdict, err
	}

	s.mu.Lock()
	s.domainCache[domain] = verdict
	s.mu.Unlock()

	return verdict, nil
}

// CheckURL checks a URL indicator via VirusTotal.
func (s *Service) CheckURL(rawURL string) (IndicatorVerdict, error) {
	normalized := normalizeURL(rawURL)
	if normalized == "" {
		return IndicatorVerdict{}, fmt.Errorf("url is empty")
	}

	s.mu.RLock()
	if v, ok := s.urlCache[normalized]; ok && time.Since(v.CheckedAt) < s.cacheTTL {
		s.mu.RUnlock()
		return v, nil
	}
	key := s.apiKey
	s.mu.RUnlock()

	if key == "" {
		return IndicatorVerdict{Indicator: normalized, IndicatorType: "url", ThreatLevel: "unknown", CheckedAt: time.Now()}, fmt.Errorf("no API key configured")
	}

	id := base64.RawURLEncoding.EncodeToString([]byte(normalized))
	apiURL := "https://www.virustotal.com/api/v3/urls/" + id
	verdict, err := s.checkIndicator(apiURL, key, normalized, "url")
	if err != nil {
		return verdict, err
	}

	s.mu.Lock()
	s.urlCache[normalized] = verdict
	s.mu.Unlock()

	return verdict, nil
}

func (s *Service) checkIndicator(apiURL, key, indicator, indicatorType string) (IndicatorVerdict, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return IndicatorVerdict{}, err
	}
	req.Header.Set("x-apikey", key)

	resp, err := s.client.Do(req)
	if err != nil {
		return IndicatorVerdict{Indicator: indicator, IndicatorType: indicatorType, ThreatLevel: "unknown", CheckedAt: time.Now()}, fmt.Errorf("VT API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return IndicatorVerdict{Indicator: indicator, IndicatorType: indicatorType, ThreatLevel: "rate_limited", CheckedAt: time.Now()}, fmt.Errorf("VirusTotal rate limit exceeded")
	}
	if resp.StatusCode != http.StatusOK {
		return IndicatorVerdict{Indicator: indicator, IndicatorType: indicatorType, ThreatLevel: "unknown", CheckedAt: time.Now()}, fmt.Errorf("VT API returned status %d", resp.StatusCode)
	}

	var result vtIndicatorResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return IndicatorVerdict{Indicator: indicator, IndicatorType: indicatorType, ThreatLevel: "unknown", CheckedAt: time.Now()}, fmt.Errorf("failed to parse VT response: %w", err)
	}

	stats := result.Data.Attributes.LastAnalysisStats
	v := IndicatorVerdict{
		Indicator:     indicator,
		IndicatorType: indicatorType,
		Malicious:     stats.Malicious,
		Suspicious:    stats.Suspicious,
		Harmless:      stats.Harmless,
		Undetected:    stats.Undetected,
		Reputation:    result.Data.Attributes.Reputation,
		ThreatLevel:   threatLevelFromStats(stats.Malicious, stats.Suspicious),
		CheckedAt:     time.Now(),
	}
	return v, nil
}

// CacheStats returns the number of cached entries.
func (s *Service) CacheStats() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cache)
}

// ClearCache removes all cached verdicts.
func (s *Service) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = make(map[string]Verdict)
	s.domainCache = make(map[string]IndicatorVerdict)
	s.urlCache = make(map[string]IndicatorVerdict)
}

// CacheEntries returns all cached IP verdicts for display.
func (s *Service) CacheEntries() []Verdict {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Verdict, 0, len(s.cache))
	for _, v := range s.cache {
		out = append(out, v)
	}
	return out
}

// GetAPIKey returns the raw API key (for persistence).
func (s *Service) GetAPIKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.apiKey
}

// isPrivateIP returns true for RFC1918, loopback, or link-local addresses.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}
	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	return raw
}

func threatLevelFromStats(malicious, suspicious int) string {
	switch {
	case malicious >= 1:
		return "malicious"
	case suspicious >= 2:
		return "suspicious"
	default:
		return "safe"
	}
}

// ---------- VirusTotal API response types ----------

type vtResponse struct {
	Data struct {
		Attributes struct {
			Reputation        int    `json:"reputation"`
			Country           string `json:"country"`
			ASOwner           string `json:"as_owner"`
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

type vtIndicatorResponse struct {
	Data struct {
		Attributes struct {
			Reputation        int `json:"reputation"`
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}
