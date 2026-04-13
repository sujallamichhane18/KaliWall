package ndpi

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"

	"kaliwall/internal/dpi/types"
)

// Classifier provides optional advanced protocol classification.
type Classifier interface {
	ClassifyPacket(flowKey string, pkt gopacket.Packet, decoded types.DecodedPacket, inspected types.InspectResult, now time.Time) (Result, bool)
	Stats() map[string]uint64
	Close()
}

// Stats tracks classifier-level counters that are independent from lite DPI stats.
type Stats struct {
	mu             sync.RWMutex
	flowCount      uint64
	classifyHits   uint64
	classifyMisses uint64
	giveups        uint64
	errors         uint64
	cleanups       uint64
}

func (s *Stats) snapshot() map[string]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]uint64{
		"flow_count":       s.flowCount,
		"classify_hits":    s.classifyHits,
		"classify_misses":  s.classifyMisses,
		"giveups":          s.giveups,
		"errors":           s.errors,
		"cleanup_passes":   s.cleanups,
	}
}

func (s *Stats) incFlow() {
	s.mu.Lock()
	s.flowCount++
	s.mu.Unlock()
}

func (s *Stats) incHit() {
	s.mu.Lock()
	s.classifyHits++
	s.mu.Unlock()
}

func (s *Stats) incMiss() {
	s.mu.Lock()
	s.classifyMisses++
	s.mu.Unlock()
}

func (s *Stats) incGiveup() {
	s.mu.Lock()
	s.giveups++
	s.mu.Unlock()
}

func (s *Stats) incError() {
	s.mu.Lock()
	s.errors++
	s.mu.Unlock()
}

func (s *Stats) incCleanup() {
	s.mu.Lock()
	s.cleanups++
	s.mu.Unlock()
}

// BuildFlowKey returns a stable 5-tuple key used by advanced DPI flow engines.
func BuildFlowKey(decoded types.DecodedPacket) string {
	return fmt.Sprintf("%s|%s|%d|%d|%s", decoded.Tuple.SrcIP, decoded.Tuple.DstIP, decoded.Tuple.SrcPort, decoded.Tuple.DstPort, strings.ToLower(strings.TrimSpace(decoded.Tuple.Protocol)))
}

func normalizeName(v string) string {
	n := strings.TrimSpace(v)
	if n == "" {
		return "Unknown"
	}
	return n
}
