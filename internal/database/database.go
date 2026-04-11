// Package database provides a simple JSON-file-backed persistent store
// for KaliWall configuration: blocked IPs, website blocks, rules, and settings.
// It uses a mutex-protected in-memory cache with auto-save to disk.
package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"kaliwall/internal/models"
)

// Store is the persistent configuration database.
type Store struct {
	mu   sync.RWMutex
	path string
	data StoreData
}

// StoreData is the on-disk JSON structure.
type StoreData struct {
	BlockedIPs     []models.BlockedIP     `json:"blocked_ips"`
	WebsiteBlocks  []models.WebsiteBlock  `json:"website_blocks"`
	Rules          []models.Rule          `json:"rules"`
	Settings       map[string]string      `json:"settings"`
}

// Open loads or creates the database file at the given path.
func Open(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	s := &Store{
		path: path,
		data: StoreData{
			BlockedIPs:    make([]models.BlockedIP, 0),
			WebsiteBlocks: make([]models.WebsiteBlock, 0),
			Rules:         make([]models.Rule, 0),
			Settings:      make(map[string]string),
		},
	}

	if _, err := os.Stat(path); err == nil {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read db: %w", err)
		}
		migratedWebsiteBlocks := false
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &s.data); err != nil {
				return nil, fmt.Errorf("parse db: %w", err)
			}
		}
		// Ensure maps/slices are not nil after unmarshal
		if s.data.BlockedIPs == nil {
			s.data.BlockedIPs = make([]models.BlockedIP, 0)
		}
		if s.data.WebsiteBlocks == nil {
			s.data.WebsiteBlocks = make([]models.WebsiteBlock, 0)
		}
		for i := range s.data.WebsiteBlocks {
			// Website blocks were historically saved without the Enabled flag,
			// which defaults to false after JSON unmarshal.
			if !s.data.WebsiteBlocks[i].Enabled {
				s.data.WebsiteBlocks[i].Enabled = true
				migratedWebsiteBlocks = true
			}
		}
		if s.data.Rules == nil {
			s.data.Rules = make([]models.Rule, 0)
		}
		if s.data.Settings == nil {
			s.data.Settings = make(map[string]string)
		}
		if migratedWebsiteBlocks {
			if err := s.flush(); err != nil {
				return nil, fmt.Errorf("migrate website blocks: %w", err)
			}
		}
	}

	fmt.Printf("[+] Database loaded: %s (%d rules, %d blocked IPs, %d website blocks)\n",
		path, len(s.data.Rules), len(s.data.BlockedIPs), len(s.data.WebsiteBlocks))
	return s, nil
}

// flush writes current state to disk. Caller must hold lock.
func (s *Store) flush() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0640)
}

// ---------- Blocked IPs ----------

// AddBlockedIP adds an IP to the blocklist.
// It returns the entry and whether the IP was newly added.
func (s *Store) AddBlockedIP(ip, reason string) (models.BlockedIP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already blocked
	for _, b := range s.data.BlockedIPs {
		if b.IP == ip {
			return b, false
		}
	}

	entry := models.BlockedIP{
		IP:        ip,
		Reason:    reason,
		CreatedAt: time.Now(),
	}
	s.data.BlockedIPs = append(s.data.BlockedIPs, entry)
	s.flush()
	return entry, true
}

// RemoveBlockedIP removes an IP from the blocklist.
func (s *Store) RemoveBlockedIP(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, b := range s.data.BlockedIPs {
		if b.IP == ip {
			s.data.BlockedIPs = append(s.data.BlockedIPs[:i], s.data.BlockedIPs[i+1:]...)
			s.flush()
			return true
		}
	}
	return false
}

// ListBlockedIPs returns all blocked IPs.
func (s *Store) ListBlockedIPs() []models.BlockedIP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.BlockedIP, len(s.data.BlockedIPs))
	copy(out, s.data.BlockedIPs)
	return out
}

// IsBlocked checks if an IP is blocked.
func (s *Store) IsBlocked(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.data.BlockedIPs {
		if b.IP == ip {
			return true
		}
	}
	return false
}

// ---------- Website Blocks ----------

// AddWebsiteBlock adds a domain to the website blocklist.
func (s *Store) AddWebsiteBlock(domain, reason string) models.WebsiteBlock {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, w := range s.data.WebsiteBlocks {
		if w.Domain == domain {
			return w
		}
	}

	entry := models.WebsiteBlock{
		Domain:    domain,
		Reason:    reason,
		Enabled:   true,
		CreatedAt: time.Now(),
	}
	s.data.WebsiteBlocks = append(s.data.WebsiteBlocks, entry)
	s.flush()
	return entry
}

// RemoveWebsiteBlock removes a domain from the website blocklist.
func (s *Store) RemoveWebsiteBlock(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, w := range s.data.WebsiteBlocks {
		if w.Domain == domain {
			s.data.WebsiteBlocks = append(s.data.WebsiteBlocks[:i], s.data.WebsiteBlocks[i+1:]...)
			s.flush()
			return true
		}
	}
	return false
}

// ListWebsiteBlocks returns all blocked websites.
func (s *Store) ListWebsiteBlocks() []models.WebsiteBlock {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.WebsiteBlock, len(s.data.WebsiteBlocks))
	copy(out, s.data.WebsiteBlocks)
	return out
}

// ---------- Rules Persistence ----------

// SaveRules replaces all stored rules.
func (s *Store) SaveRules(rules []models.Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Rules = make([]models.Rule, len(rules))
	copy(s.data.Rules, rules)
	s.flush()
}

// LoadRules returns all stored rules.
func (s *Store) LoadRules() []models.Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.Rule, len(s.data.Rules))
	copy(out, s.data.Rules)
	return out
}

// ---------- Settings ----------

// SetSetting stores a key-value setting.
func (s *Store) SetSetting(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Settings[key] = value
	s.flush()
}

// GetSetting retrieves a setting value.
func (s *Store) GetSetting(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data.Settings[key]
	return v, ok
}

// DeleteSetting removes a setting.
func (s *Store) DeleteSetting(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Settings, key)
	s.flush()
}
