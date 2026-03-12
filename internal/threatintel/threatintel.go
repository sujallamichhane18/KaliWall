// Package threatintel provides IP reputation lookups via the VirusTotal API.
// It caches results to avoid hammering the API (free tier: 4 req/min).
package threatintel

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// Verdict summarises the VirusTotal reputation of an IP address.
type Verdict struct {
	IP            string    `json:"ip"`
	Malicious     int       `json:"malicious"`
	Suspicious    int       `json:"suspicious"`
	Harmless      int       `json:"harmless"`
	Undetected    int       `json:"undetected"`
	Reputation    int       `json:"reputation"`
	Country       string    `json:"country"`
	Owner         string    `json:"owner"`
	ThreatLevel   string    `json:"threat_level"` // safe, suspicious, malicious
	CheckedAt     time.Time `json:"checked_at"`
}

// Service manages VirusTotal API key and caches lookup results.
type Service struct {
	mu       sync.RWMutex
	apiKey   string
	cache    map[string]Verdict // ip -> verdict
	cacheTTL time.Duration
	client   *http.Client
}

// New creates a new threat intel service.
func New() *Service {
	return &Service{
		cache:    make(map[string]Verdict),
		cacheTTL: 30 * time.Minute,
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

// SetAPIKey stores the VirusTotal API key.
func (s *Service) SetAPIKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKey = key
	// Clear cache when key changes
	s.cache = make(map[string]Verdict)
}

// GetAPIKey returns whether an API key is configured (masked).
func (s *Service) HasAPIKey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.apiKey != ""
}

// CheckIP looks up an IP against VirusTotal.
// Returns a cached result if available, otherwise queries the API.
func (s *Service) CheckIP(ip string) (Verdict, error) {
	// Skip private/reserved IPs
	if isPrivateIP(ip) {
		return Verdict{
			IP:          ip,
			ThreatLevel: "internal",
			CheckedAt:   time.Now(),
		}, nil
	}

	// Check cache first
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

	// Query VirusTotal v3 API
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
	if resp.StatusCode != 200 {
		return Verdict{}, fmt.Errorf("VT API returned status %d", resp.StatusCode)
	}

	var result vtResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return Verdict{}, fmt.Errorf("failed to parse VT response: %w", err)
	}

	stats := result.Data.Attributes.LastAnalysisStats
	verdict := Verdict{
		IP:         ip,
		Malicious:  stats.Malicious,
		Suspicious: stats.Suspicious,
		Harmless:   stats.Harmless,
		Undetected: stats.Undetected,
		Reputation: result.Data.Attributes.Reputation,
		Country:    result.Data.Attributes.Country,
		Owner:      result.Data.Attributes.ASOwner,
		CheckedAt:  time.Now(),
	}

	// Determine threat level
	switch {
	case stats.Malicious >= 3:
		verdict.ThreatLevel = "malicious"
	case stats.Malicious >= 1 || stats.Suspicious >= 3:
		verdict.ThreatLevel = "suspicious"
	default:
		verdict.ThreatLevel = "safe"
	}

	// Cache the result
	s.mu.Lock()
	s.cache[ip] = verdict
	s.mu.Unlock()

	return verdict, nil
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
}

// CacheEntries returns all cached verdicts for display.
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
