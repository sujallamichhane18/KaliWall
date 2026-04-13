package geoip

import (
	"encoding/binary"
	"encoding/csv"
	"hash/fnv"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"

	"kaliwall/internal/models"
)

type cacheEntry struct {
	loc       models.GeoLocation
	expiresAt time.Time
}

type ip2LocationRange struct {
	start      uint32
	end        uint32
	country    string
	countryISO string
	latitude   float64
	longitude  float64
}

// Service performs cached IP->location lookups using a free MaxMind GeoLite2 DB.
type Service struct {
	db       *geoip2.Reader
	ranges   []ip2LocationRange
	cacheTTL time.Duration

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// New opens a local GeoLite2-City.mmdb database.
func New(path string) (*Service, error) {
	if strings.EqualFold(filepath.Ext(path), ".csv") {
		return newFromIP2LocationCSV(path)
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, cacheTTL: 12 * time.Hour, cache: make(map[string]cacheEntry)}, nil
}

func newFromIP2LocationCSV(path string) (*Service, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1

	ranges := make([]ip2LocationRange, 0, 1<<16)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) < 4 {
			continue
		}

		startU, err1 := strconv.ParseUint(strings.TrimSpace(rec[0]), 10, 32)
		endU, err2 := strconv.ParseUint(strings.TrimSpace(rec[1]), 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		iso := strings.TrimSpace(rec[2])
		country := strings.TrimSpace(rec[3])
		if iso == "-" || country == "-" || country == "" {
			continue
		}

		lat, lon := approximateCountryCoordinate(iso, country)
		ranges = append(ranges, ip2LocationRange{
			start:      uint32(startU),
			end:        uint32(endU),
			country:    country,
			countryISO: iso,
			latitude:   lat,
			longitude:  lon,
		})
	}

	if len(ranges) == 0 {
		return nil, io.ErrUnexpectedEOF
	}

	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	return &Service{ranges: ranges, cacheTTL: 12 * time.Hour, cache: make(map[string]cacheEntry)}, nil
}

func (s *Service) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Lookup returns location data for a public IP. Private/local addresses are ignored.
func (s *Service) Lookup(ipStr string) (models.GeoLocation, bool) {
	if s == nil || (s.db == nil && len(s.ranges) == 0) {
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

	var loc models.GeoLocation
	if s.db != nil {
		rec, err := s.db.City(ip)
		if err != nil || rec == nil {
			return models.GeoLocation{}, false
		}
		loc = models.GeoLocation{
			IP:        ipStr,
			Country:   rec.Country.Names["en"],
			City:      rec.City.Names["en"],
			Latitude:  rec.Location.Latitude,
			Longitude: rec.Location.Longitude,
			Source:    "ip",
		}
		if loc.Country == "" || (loc.Latitude == 0 && loc.Longitude == 0) {
			return models.GeoLocation{}, false
		}
	} else {
		ip4 := ip.To4()
		if ip4 == nil {
			return models.GeoLocation{}, false
		}
		n := binary.BigEndian.Uint32(ip4)
		idx := sort.Search(len(s.ranges), func(i int) bool { return s.ranges[i].start > n }) - 1
		if idx < 0 || idx >= len(s.ranges) {
			return models.GeoLocation{}, false
		}
		rg := s.ranges[idx]
		if n < rg.start || n > rg.end {
			return models.GeoLocation{}, false
		}
		loc = models.GeoLocation{
			IP:        ipStr,
			Country:   rg.country,
			Latitude:  rg.latitude,
			Longitude: rg.longitude,
			Source:    "ip",
		}
	}

	s.mu.Lock()
	s.cache[ipStr] = cacheEntry{loc: loc, expiresAt: now.Add(s.cacheTTL)}
	s.mu.Unlock()
	return loc, true
}

func approximateCountryCoordinate(iso, country string) (float64, float64) {
	var countryCenter = map[string][2]float64{
		"US": {39.50, -98.35}, "CN": {35.86, 104.20}, "RU": {61.52, 105.31}, "BR": {-14.23, -51.93},
		"IN": {20.59, 78.96}, "GB": {55.38, -3.44}, "DE": {51.16, 10.45}, "FR": {46.23, 2.21},
		"JP": {36.20, 138.25}, "AU": {-25.27, 133.77}, "CA": {56.13, -106.35}, "ID": {-0.79, 113.92},
		"KR": {35.91, 127.77}, "TH": {15.87, 100.99}, "VN": {14.06, 108.28}, "TR": {38.96, 35.24},
		"IR": {32.43, 53.69}, "SA": {23.89, 45.08}, "EG": {26.82, 30.80}, "ZA": {-30.56, 22.94},
		"NG": {9.08, 8.68}, "MX": {23.63, -102.55}, "AR": {-38.42, -63.62}, "ES": {40.46, -3.75},
		"IT": {41.87, 12.57}, "NL": {52.13, 5.29}, "PL": {51.92, 19.15}, "SE": {60.13, 18.64},
		"UA": {48.38, 31.17}, "PK": {30.38, 69.35}, "BD": {23.68, 90.36}, "MY": {4.21, 101.98},
		"SG": {1.35, 103.82}, "PH": {12.88, 121.77}, "NZ": {-40.90, 174.89},
	}
	iso = strings.ToUpper(strings.TrimSpace(iso))
	if v, ok := countryCenter[iso]; ok {
		return v[0], v[1]
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToUpper(strings.TrimSpace(country)) + ":" + iso))
	v := h.Sum32()
	lat := float64(int(v%140)-70) + 0.37
	lon := float64(int((v/140)%320)-160) + 0.19
	return lat, lon
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
