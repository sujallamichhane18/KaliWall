package flow

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kaliwall/internal/dpi/types"
)

// State stores flow counters and timestamps.
type State struct {
	FirstSeen   time.Time
	LastSeen    time.Time
	PacketCount int64
	ByteCount   int64
}

// FlowLifecycle captures high-level flow lifecycle transitions.
type FlowLifecycle string

const (
	FlowLifecycleNew         FlowLifecycle = "new"
	FlowLifecycleActive      FlowLifecycle = "active"
	FlowLifecycleEstablished FlowLifecycle = "established"
	FlowLifecycleClosing     FlowLifecycle = "closing"
	FlowLifecycleClosed      FlowLifecycle = "closed"
)

// FlowProtocol labels protocol families tracked by the flow table.
type FlowProtocol string

const (
	FlowProtocolOther FlowProtocol = "other"
	FlowProtocolTCP   FlowProtocol = "tcp"
	FlowProtocolUDP   FlowProtocol = "udp"
	FlowProtocolDNS   FlowProtocol = "dns"
	FlowProtocolTLS   FlowProtocol = "tls"
)

// TCPState captures protocol state machine milestones.
type TCPState string

const (
	TCPStateNew         TCPState = "new"
	TCPStateSynSeen     TCPState = "syn_seen"
	TCPStateEstablished TCPState = "established"
	TCPStateClosing     TCPState = "closing"
	TCPStateClosed      TCPState = "closed"
	TCPStateReset       TCPState = "reset"
)

// DNSState captures query-response lifecycle.
type DNSState string

const (
	DNSStateUnknown      DNSState = "unknown"
	DNSStateQuerySeen    DNSState = "query_seen"
	DNSStateResponseSeen DNSState = "response_seen"
	DNSStateComplete     DNSState = "complete"
)

// TLSState captures handshake milestones without payload decryption.
type TLSState string

const (
	TLSStateUnknown      TLSState = "unknown"
	TLSStateClientHello TLSState = "client_hello"
	TLSStateEstablished TLSState = "established"
)

// TrackerConfig controls flow table capacity, lifecycle, and cleanup.
type TrackerConfig struct {
	ShardCount       int
	MaxFlows         int
	MaxFlowsPerShard int
	FlowTimeout      time.Duration
	ClosedFlowTTL    time.Duration
	CleanupInterval  time.Duration
	RateLimitPerSec  int
}

// FlowKey canonicalizes a 5-tuple for bidirectional flow tracking.
type FlowKey struct {
	Protocol FlowProtocol
	AIP      string
	APort    uint16
	BIP      string
	BPort    uint16
}

// DNSLifecycle stores DNS-specific counters and terminal state.
type DNSLifecycle struct {
	State         DNSState
	QueryCount    uint32
	ResponseCount uint32
	LastQuery     string
}

// TCPLifecycle stores TCP-state milestones used for eviction and analytics.
type TCPLifecycle struct {
	State         TCPState
	SynSeen       bool
	SynAckSeen    bool
	AckSeen       bool
	ClientFinSeen bool
	ServerFinSeen bool
	RstSeen       bool
}

// TLSLifecycle stores SNI and handshake progression.
type TLSLifecycle struct {
	State           TLSState
	ClientHelloSeen bool
	SNI             string
}

// FlowRecord is a memory-safe, bounded per-flow summary.
type FlowRecord struct {
	Key             FlowKey
	ClientIP        string
	ClientPort      uint16
	ServerIP        string
	ServerPort      uint16
	Lifecycle       FlowLifecycle
	FirstSeen       time.Time
	LastSeen        time.Time
	LastStateChange time.Time

	TotalPackets  uint64
	TotalBytes    uint64
	ClientPackets uint64
	ServerPackets uint64
	ClientBytes   uint64
	ServerBytes   uint64

	DNS DNSLifecycle
	TCP TCPLifecycle
	TLS TLSLifecycle
}

// Stats exposes flow-table health and pressure signals.
type Stats struct {
	ActiveFlows      int
	ObservedPackets  uint64
	NewFlows         uint64
	EvictedFlows     uint64
	ExpiredFlows     uint64
	ClosedFlows      uint64
	RateLimitedFlows uint64
}

type srcRateState struct {
	WindowStart time.Time
	Count       int
}

type flowShard struct {
	mu    sync.RWMutex
	flows map[FlowKey]*FlowRecord
}

type srcRateShard struct {
	mu    sync.Mutex
	rates map[string]*srcRateState
}

// Tracker is a concurrent-safe 5-tuple flow table.
type Tracker struct {
	cfg       TrackerConfig
	shards    []flowShard
	rateShard []srcRateShard

	stopMu  sync.Mutex
	stopCh  chan struct{}
	running bool

	activeFlows     atomic.Int64
	observedPackets atomic.Uint64
	newFlows        atomic.Uint64
	evictedFlows    atomic.Uint64
	expiredFlows    atomic.Uint64
	closedFlows     atomic.Uint64
	rateLimited     atomic.Uint64
}

func New(flowTimeout, cleanupInterval time.Duration, rateLimitPerSec int) *Tracker {
	return NewWithConfig(TrackerConfig{
		FlowTimeout:     flowTimeout,
		CleanupInterval: cleanupInterval,
		RateLimitPerSec: rateLimitPerSec,
	})
}

func NewWithConfig(cfg TrackerConfig) *Tracker {
	if cfg.ShardCount <= 0 {
		cfg.ShardCount = 64
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = 120000
	}
	if cfg.MaxFlowsPerShard <= 0 {
		cfg.MaxFlowsPerShard = maxInt(1024, (cfg.MaxFlows/cfg.ShardCount)+256)
	}
	if cfg.ClosedFlowTTL <= 0 {
		cfg.ClosedFlowTTL = 20 * time.Second
	}
	if cfg.FlowTimeout <= 0 {
		cfg.FlowTimeout = 2 * time.Minute
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 30 * time.Second
	}

	shardCount := nextPowerOfTwo(cfg.ShardCount)
	shards := make([]flowShard, shardCount)
	rateShards := make([]srcRateShard, shardCount)
	for i := range shards {
		shards[i] = flowShard{flows: make(map[FlowKey]*FlowRecord, cfg.MaxFlowsPerShard/2)}
		rateShards[i] = srcRateShard{rates: make(map[string]*srcRateState, 1024)}
	}

	return &Tracker{
		cfg:       cfg,
		shards:    shards,
		rateShard: rateShards,
		stopCh:    make(chan struct{}),
	}
}

func (t *Tracker) Start() {
	if t == nil {
		return
	}
	t.stopMu.Lock()
	defer t.stopMu.Unlock()
	if t.running {
		return
	}
	if t.stopCh == nil || isClosedChan(t.stopCh) {
		t.stopCh = make(chan struct{})
	}
	t.running = true
	go t.cleanupLoop(t.stopCh)
}

func (t *Tracker) Stop() {
	if t == nil {
		return
	}
	t.stopMu.Lock()
	if !t.running {
		t.stopMu.Unlock()
		return
	}
	stopCh := t.stopCh
	t.running = false
	t.stopMu.Unlock()
	close(stopCh)
}

// Touch updates flow stats and returns current state copy.
func (t *Tracker) Touch(tuple types.FiveTuple, payloadBytes int) State {
	if t == nil {
		return State{}
	}
	rec, ok := t.observeTuple(tuple, time.Now(), payloadBytes, nil)
	if !ok {
		return State{}
	}
	return State{
		FirstSeen:   rec.FirstSeen,
		LastSeen:    rec.LastSeen,
		PacketCount: int64(rec.TotalPackets),
		ByteCount:   int64(rec.TotalBytes),
	}
}

// ObserveDecoded updates lifecycle state from decoded packets.
func (t *Tracker) ObserveDecoded(pkt *types.DecodedPacket) {
	if t == nil || pkt == nil {
		return
	}
	ts := pkt.Timestamp
	_, _ = t.observeTuple(pkt.Tuple, ts, len(pkt.Payload), func(flow *FlowRecord, fromClient bool, now time.Time) {
		applyDecodedState(flow, pkt, fromClient, now)
	})
}

// ObserveInspection updates protocol state from inspection outputs.
func (t *Tracker) ObserveInspection(result types.InspectResult) {
	if t == nil {
		return
	}
	ts := result.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	_, _ = t.observeTuple(result.Tuple, ts, len(result.Payload), func(flow *FlowRecord, fromClient bool, now time.Time) {
		applyInspectState(flow, result, fromClient, now)
	})
}

// IsRateLimited applies a simple per-source per-second limiter.
func (t *Tracker) IsRateLimited(srcIP string) bool {
	if t == nil || t.cfg.RateLimitPerSec <= 0 || srcIP == "" {
		return false
	}
	idx := t.rateShardIndex(srcIP)
	shard := &t.rateShard[idx]
	now := time.Now()
	shard.mu.Lock()
	defer shard.mu.Unlock()
	rs, ok := shard.rates[srcIP]
	if !ok {
		shard.rates[srcIP] = &srcRateState{WindowStart: now, Count: 1}
		return false
	}
	if now.Sub(rs.WindowStart) >= time.Second {
		rs.WindowStart = now
		rs.Count = 1
		return false
	}
	rs.Count++
	limited := rs.Count > t.cfg.RateLimitPerSec
	if limited {
		t.rateLimited.Add(1)
	}
	return limited
}

func (t *Tracker) SnapshotSize() int {
	if t == nil {
		return 0
	}
	return int(t.activeFlows.Load())
}

// Snapshot returns up to limit flow records, newest first.
func (t *Tracker) Snapshot(limit int) []FlowRecord {
	if t == nil {
		return nil
	}
	if limit <= 0 {
		limit = 200
	}
	out := make([]FlowRecord, 0, limit)
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.RLock()
		for _, rec := range sh.flows {
			out = append(out, *rec)
			if len(out) >= limit {
				sh.mu.RUnlock()
				sort.Slice(out, func(i, j int) bool {
					return out[i].LastSeen.After(out[j].LastSeen)
				})
				return out
			}
		}
		sh.mu.RUnlock()
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// Stats returns flow-table counters for observability.
func (t *Tracker) Stats() Stats {
	if t == nil {
		return Stats{}
	}
	return Stats{
		ActiveFlows:      int(t.activeFlows.Load()),
		ObservedPackets:  t.observedPackets.Load(),
		NewFlows:         t.newFlows.Load(),
		EvictedFlows:     t.evictedFlows.Load(),
		ExpiredFlows:     t.expiredFlows.Load(),
		ClosedFlows:      t.closedFlows.Load(),
		RateLimitedFlows: t.rateLimited.Load(),
	}
}

func (t *Tracker) cleanupLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(t.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			t.cleanupExpired()
		}
	}
}

func (t *Tracker) cleanupExpired() {
	now := time.Now()
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.Lock()
		for k, rec := range sh.flows {
			ttl := t.cfg.FlowTimeout
			if rec.Lifecycle == FlowLifecycleClosed || rec.Lifecycle == FlowLifecycleClosing {
				ttl = minDuration(ttl, t.cfg.ClosedFlowTTL)
			}
			if now.Sub(rec.LastSeen) > ttl {
				delete(sh.flows, k)
				t.activeFlows.Add(-1)
				t.expiredFlows.Add(1)
			}
		}
		sh.mu.Unlock()
	}
	for i := range t.rateShard {
		sh := &t.rateShard[i]
		sh.mu.Lock()
		for ip, rs := range sh.rates {
			if now.Sub(rs.WindowStart) > 3*time.Second {
				delete(sh.rates, ip)
			}
		}
		sh.mu.Unlock()
	}
}

func (t *Tracker) String() string {
	if t == nil {
		return "flows=0"
	}
	stats := t.Stats()
	return fmt.Sprintf("flows=%d timeout=%s evicted=%d expired=%d", stats.ActiveFlows, t.cfg.FlowTimeout, stats.EvictedFlows, stats.ExpiredFlows)
}

func (t *Tracker) observeTuple(tuple types.FiveTuple, ts time.Time, payloadBytes int, updater func(flow *FlowRecord, fromClient bool, now time.Time)) (FlowRecord, bool) {
	key, clientIP, clientPort, serverIP, serverPort, ok := buildFlowKey(tuple)
	if !ok {
		return FlowRecord{}, false
	}
	if ts.IsZero() {
		ts = time.Now()
	}

	sh := &t.shards[t.flowShardIndex(key)]
	sh.mu.Lock()
	rec, exists := sh.flows[key]
	if !exists {
		if len(sh.flows) >= t.cfg.MaxFlowsPerShard || int(t.activeFlows.Load()) >= t.cfg.MaxFlows {
			t.evictOneLocked(sh)
		}
		if len(sh.flows) >= t.cfg.MaxFlowsPerShard || int(t.activeFlows.Load()) >= t.cfg.MaxFlows {
			sh.mu.Unlock()
			return FlowRecord{}, false
		}
		rec = &FlowRecord{
			Key:             key,
			ClientIP:        clientIP,
			ClientPort:      clientPort,
			ServerIP:        serverIP,
			ServerPort:      serverPort,
			Lifecycle:       FlowLifecycleNew,
			FirstSeen:       ts,
			LastSeen:        ts,
			LastStateChange: ts,
			DNS: DNSLifecycle{State: DNSStateUnknown},
			TCP: TCPLifecycle{State: TCPStateNew},
			TLS: TLSLifecycle{State: TLSStateUnknown},
		}
		sh.flows[key] = rec
		t.activeFlows.Add(1)
		t.newFlows.Add(1)
	}

	fromClient := rec.ClientIP == tuple.SrcIP && rec.ClientPort == tuple.SrcPort
	prevLifecycle := rec.Lifecycle
	rec.LastSeen = ts
	rec.TotalPackets++
	if payloadBytes > 0 {
		rec.TotalBytes += uint64(payloadBytes)
	}
	if fromClient {
		rec.ClientPackets++
		if payloadBytes > 0 {
			rec.ClientBytes += uint64(payloadBytes)
		}
	} else {
		rec.ServerPackets++
		if payloadBytes > 0 {
			rec.ServerBytes += uint64(payloadBytes)
		}
	}

	if rec.Lifecycle == FlowLifecycleNew {
		rec.Lifecycle = FlowLifecycleActive
		rec.LastStateChange = ts
	}

	if updater != nil {
		updater(rec, fromClient, ts)
	}
	if prevLifecycle != FlowLifecycleClosed && rec.Lifecycle == FlowLifecycleClosed {
		t.closedFlows.Add(1)
	}

	snapshot := *rec
	sh.mu.Unlock()
	t.observedPackets.Add(1)
	return snapshot, true
}

func applyDecodedState(rec *FlowRecord, pkt *types.DecodedPacket, fromClient bool, now time.Time) {
	proto := strings.ToLower(strings.TrimSpace(pkt.Tuple.Protocol))
	switch proto {
	case "tcp":
		if rec.Key.Protocol == FlowProtocolOther || rec.Key.Protocol == FlowProtocolUDP {
			rec.Key.Protocol = FlowProtocolTCP
		}
	case "udp":
		if rec.Key.Protocol == FlowProtocolOther {
			rec.Key.Protocol = FlowProtocolUDP
		}
	}

	if pkt.DNSQuery != "" || pkt.Tuple.SrcPort == 53 || pkt.Tuple.DstPort == 53 {
		rec.Key.Protocol = FlowProtocolDNS
		if pkt.DNSQuery != "" {
			rec.DNS.QueryCount++
			rec.DNS.LastQuery = strings.ToLower(strings.TrimSpace(pkt.DNSQuery))
			rec.DNS.State = DNSStateQuerySeen
		}
		if pkt.Tuple.SrcPort == 53 {
			rec.DNS.ResponseCount++
			if rec.DNS.QueryCount > 0 {
				rec.DNS.State = DNSStateComplete
				rec.Lifecycle = FlowLifecycleClosed
				rec.LastStateChange = now
			} else {
				rec.DNS.State = DNSStateResponseSeen
			}
		}
	}

	if pkt.Tuple.SrcPort == 443 || pkt.Tuple.DstPort == 443 {
		if rec.Key.Protocol != FlowProtocolDNS {
			rec.Key.Protocol = FlowProtocolTLS
		}
	}

	seg := pkt.TCPSegment
	if seg == nil {
		return
	}

	if rec.TCP.State == TCPStateNew {
		rec.TCP.State = TCPStateSynSeen
	}
	if seg.SYN && !seg.ACK {
		rec.TCP.SynSeen = true
		rec.TCP.State = TCPStateSynSeen
	}
	if seg.SYN && seg.ACK {
		rec.TCP.SynAckSeen = true
	}
	if seg.ACK {
		rec.TCP.AckSeen = true
	}
	if rec.TCP.SynSeen && rec.TCP.SynAckSeen && rec.TCP.AckSeen {
		rec.TCP.State = TCPStateEstablished
		rec.Lifecycle = FlowLifecycleEstablished
		rec.LastStateChange = now
	}
	if seg.FIN {
		if fromClient {
			rec.TCP.ClientFinSeen = true
		} else {
			rec.TCP.ServerFinSeen = true
		}
		rec.TCP.State = TCPStateClosing
		rec.Lifecycle = FlowLifecycleClosing
		rec.LastStateChange = now
		if rec.TCP.ClientFinSeen && rec.TCP.ServerFinSeen {
			rec.TCP.State = TCPStateClosed
			rec.Lifecycle = FlowLifecycleClosed
			rec.LastStateChange = now
		}
	}
	if seg.RST {
		rec.TCP.RstSeen = true
		rec.TCP.State = TCPStateReset
		rec.Lifecycle = FlowLifecycleClosed
		rec.LastStateChange = now
	}
}

func applyInspectState(rec *FlowRecord, result types.InspectResult, fromClient bool, now time.Time) {
	if result.DNSDomain != "" {
		rec.Key.Protocol = FlowProtocolDNS
		rec.DNS.LastQuery = strings.ToLower(strings.TrimSpace(result.DNSDomain))
		if rec.DNS.QueryCount == 0 {
			rec.DNS.QueryCount = 1
		}
		if rec.DNS.ResponseCount > 0 {
			rec.DNS.State = DNSStateComplete
			rec.Lifecycle = FlowLifecycleClosed
			rec.LastStateChange = now
		} else {
			rec.DNS.State = DNSStateQuerySeen
		}
	}

	if result.TLSSNI != "" {
		rec.Key.Protocol = FlowProtocolTLS
		rec.TLS.ClientHelloSeen = true
		rec.TLS.SNI = strings.ToLower(strings.TrimSpace(result.TLSSNI))
		rec.TLS.State = TLSStateClientHello
		rec.Lifecycle = FlowLifecycleEstablished
		rec.LastStateChange = now
	}

	if rec.Key.Protocol == FlowProtocolTLS && rec.TLS.ClientHelloSeen && !fromClient && rec.ServerPackets > 0 {
		rec.TLS.State = TLSStateEstablished
		rec.Lifecycle = FlowLifecycleEstablished
		rec.LastStateChange = now
	}
}

func (t *Tracker) evictOneLocked(sh *flowShard) {
	if len(sh.flows) == 0 {
		return
	}
	var victimKey FlowKey
	var victim *FlowRecord
	for key, flow := range sh.flows {
		if victim == nil {
			victimKey = key
			victim = flow
			continue
		}
		if flow.LastSeen.Before(victim.LastSeen) {
			victimKey = key
			victim = flow
			continue
		}
		if flow.LastSeen.Equal(victim.LastSeen) && flow.Lifecycle == FlowLifecycleClosed && victim.Lifecycle != FlowLifecycleClosed {
			victimKey = key
			victim = flow
		}
	}
	if victim != nil {
		delete(sh.flows, victimKey)
		t.activeFlows.Add(-1)
		t.evictedFlows.Add(1)
	}
}

func (t *Tracker) flowShardIndex(key FlowKey) int {
	return int(hashFlowKey(key) & uint64(len(t.shards)-1))
}

func (t *Tracker) rateShardIndex(srcIP string) int {
	return int(hashString(srcIP) & uint64(len(t.rateShard)-1))
}

func buildFlowKey(tuple types.FiveTuple) (FlowKey, string, uint16, string, uint16, bool) {
	srcIP := strings.TrimSpace(tuple.SrcIP)
	dstIP := strings.TrimSpace(tuple.DstIP)
	if srcIP == "" || dstIP == "" {
		return FlowKey{}, "", 0, "", 0, false
	}
	proto := mapProtocol(tuple)

	aIP, aPort := srcIP, tuple.SrcPort
	bIP, bPort := dstIP, tuple.DstPort
	clientIP, clientPort := srcIP, tuple.SrcPort
	serverIP, serverPort := dstIP, tuple.DstPort

	if endpointGreater(aIP, aPort, bIP, bPort) {
		aIP, bIP = bIP, aIP
		aPort, bPort = bPort, aPort
	}

	return FlowKey{Protocol: proto, AIP: aIP, APort: aPort, BIP: bIP, BPort: bPort}, clientIP, clientPort, serverIP, serverPort, true
}

func endpointGreater(ipA string, portA uint16, ipB string, portB uint16) bool {
	if ipA != ipB {
		return ipA > ipB
	}
	return portA > portB
}

func mapProtocol(tuple types.FiveTuple) FlowProtocol {
	proto := strings.ToLower(strings.TrimSpace(tuple.Protocol))
	switch proto {
	case "tcp":
		if tuple.SrcPort == 443 || tuple.DstPort == 443 {
			return FlowProtocolTLS
		}
		return FlowProtocolTCP
	case "udp":
		if tuple.SrcPort == 53 || tuple.DstPort == 53 {
			return FlowProtocolDNS
		}
		return FlowProtocolUDP
	default:
		return FlowProtocolOther
	}
}

func isClosedChan(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func hashFlowKey(key FlowKey) uint64 {
	h := uint64(1469598103934665603)
	h = hashAppendString(h, string(key.Protocol))
	h = hashAppendString(h, key.AIP)
	h = hashAppendUint16(h, key.APort)
	h = hashAppendString(h, key.BIP)
	h = hashAppendUint16(h, key.BPort)
	return h
}

func hashString(s string) uint64 {
	h := uint64(1469598103934665603)
	return hashAppendString(h, s)
}

func hashAppendString(h uint64, s string) uint64 {
	const prime = uint64(1099511628211)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	return h
}

func hashAppendUint16(h uint64, v uint16) uint64 {
	const prime = uint64(1099511628211)
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], v)
	for i := 0; i < len(buf); i++ {
		h ^= uint64(buf[i])
		h *= prime
	}
	return h
}

func nextPowerOfTwo(v int) int {
	if v <= 1 {
		return 1
	}
	p := 1
	for p < v {
		p <<= 1
	}
	return p
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
