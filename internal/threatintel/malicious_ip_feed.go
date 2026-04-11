package threatintel

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// MaliciousIPFeed stores IP/CIDR indicators loaded from a local feed file.
type MaliciousIPFeed struct {
	mu          sync.RWMutex
	path        string
	ips         map[string]struct{}
	cidrs       []*net.IPNet
	lastLoad    time.Time
	lastModTime time.Time
}

// MaliciousIPFeedStats exposes feed metadata for diagnostics.
type MaliciousIPFeedStats struct {
	Path          string    `json:"path"`
	IndicatorCount int      `json:"indicator_count"`
	CIDRCount     int       `json:"cidr_count"`
	LastLoadedAt  time.Time `json:"last_loaded_at"`
	LastFileModAt time.Time `json:"last_file_mod_at"`
}

// NewMaliciousIPFeed creates a feed reader and loads the file immediately.
func NewMaliciousIPFeed(path string) (*MaliciousIPFeed, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("malicious IP feed path cannot be empty")
	}

	f := &MaliciousIPFeed{
		path:  path,
		ips:   make(map[string]struct{}),
		cidrs: make([]*net.IPNet, 0, 64),
	}
	if _, err := f.Reload(); err != nil {
		return nil, err
	}
	return f, nil
}

// ReloadIfChanged reloads indicators only when file modification time changed.
func (f *MaliciousIPFeed) ReloadIfChanged() (bool, int, error) {
	st, err := os.Stat(f.path)
	if err != nil {
		return false, 0, fmt.Errorf("stat malicious IP feed: %w", err)
	}
	mod := st.ModTime().UTC()

	f.mu.RLock()
	unchanged := !mod.After(f.lastModTime)
	count := len(f.ips) + len(f.cidrs)
	f.mu.RUnlock()

	if unchanged {
		return false, count, nil
	}

	newCount, err := f.Reload()
	if err != nil {
		return false, 0, err
	}
	return true, newCount, nil
}

// Reload forces a full feed reload from disk.
func (f *MaliciousIPFeed) Reload() (int, error) {
	file, err := os.Open(f.path)
	if err != nil {
		return 0, fmt.Errorf("open malicious IP feed: %w", err)
	}
	defer file.Close()

	ips := make(map[string]struct{})
	cidrs := make([]*net.IPNet, 0, 64)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		token := parseFeedToken(scanner.Text())
		if token == "" {
			continue
		}

		if ip := net.ParseIP(token); ip != nil {
			ips[normalizeIP(ip)] = struct{}{}
			continue
		}

		_, network, err := net.ParseCIDR(token)
		if err == nil && network != nil {
			cidrs = append(cidrs, network)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan malicious IP feed: %w", err)
	}

	st, err := os.Stat(f.path)
	if err != nil {
		return 0, fmt.Errorf("stat malicious IP feed: %w", err)
	}

	f.mu.Lock()
	f.ips = ips
	f.cidrs = cidrs
	f.lastLoad = time.Now().UTC()
	f.lastModTime = st.ModTime().UTC()
	count := len(ips) + len(cidrs)
	f.mu.Unlock()

	return count, nil
}

// IsMaliciousIP returns true when the given IP exists in the loaded feed.
func (f *MaliciousIPFeed) IsMaliciousIP(raw string) bool {
	ip := normalizeIPString(raw)
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	f.mu.RLock()
	_, exists := f.ips[ip]
	if exists {
		f.mu.RUnlock()
		return true
	}
	for _, network := range f.cidrs {
		if network.Contains(parsed) {
			f.mu.RUnlock()
			return true
		}
	}
	f.mu.RUnlock()

	return false
}

// Count returns the number of loaded IP + CIDR indicators.
func (f *MaliciousIPFeed) Count() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.ips) + len(f.cidrs)
}

// Stats returns feed metadata.
func (f *MaliciousIPFeed) Stats() MaliciousIPFeedStats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return MaliciousIPFeedStats{
		Path:           f.path,
		IndicatorCount: len(f.ips) + len(f.cidrs),
		CIDRCount:      len(f.cidrs),
		LastLoadedAt:   f.lastLoad,
		LastFileModAt:  f.lastModTime,
	}
}

func parseFeedToken(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	token := strings.TrimSpace(fields[0])
	token = strings.Trim(token, "[]")
	if idx := strings.IndexByte(token, ','); idx >= 0 {
		token = token[:idx]
	}
	return strings.TrimSpace(token)
}

func normalizeIPString(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return ""
	}
	return normalizeIP(ip)
}

func normalizeIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
