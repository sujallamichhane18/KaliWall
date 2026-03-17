package geoip

import (
	"net"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"

	"kaliwall/internal/models"
)

type cacheEntry struct {
	loc       models.GeoLocation
	expiresAt time.Time
}

// Service performs cached IP->location lookups using a free MaxMind GeoLite2 DB.
type Service struct {
	db       *geoip2.Reader
	cacheTTL time.Duration

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// New opens a local GeoLite2-City.mmdb database.
func New(path string) (*Service, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, cacheTTL: 12 * time.Hour, cache: make(map[string]cacheEntry)}, nil
}

func (s *Service) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Lookup returns location data for a public IP. Private/local addresses are ignored.
func (s *Service) Lookup(ipStr string) (models.GeoLocation, bool) {
	if s == nil || s.db == nil {
		return models.GeoLocation{}, false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || isNonPublic(ip) {
		return models.GeoLocation{}, false
	}

	now := time.Now()
	s.mu.RLock()
	if c, ok := s.cache[ipStr]; ok && now.Before(c.expiresAt) {
		s.mu.RUnlock()
		return c.loc, true
	}
	s.mu.RUnlock()

	rec, err := s.db.City(ip)
	if err != nil || rec == nil {
		return models.GeoLocation{}, false
	}
	loc := models.GeoLocation{
		IP:        ipStr,
		Country:   rec.Country.Names["en"],
		City:      rec.City.Names["en"],
		Latitude:  rec.Location.Latitude,
		Longitude: rec.Location.Longitude,
	}
	if loc.Country == "" || (loc.Latitude == 0 && loc.Longitude == 0) {
		return models.GeoLocation{}, false
	}

	s.mu.Lock()
	s.cache[ipStr] = cacheEntry{loc: loc, expiresAt: now.Add(s.cacheTTL)}
	s.mu.Unlock()
	return loc, true
}

func isNonPublic(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 10 || ip4[0] == 127 || ip4[0] == 0 {
			return true
		}
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}
	return false
}
