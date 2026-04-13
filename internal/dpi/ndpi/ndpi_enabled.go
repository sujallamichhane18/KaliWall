//go:build ndpi

package ndpi

import (
	"sync"
	"time"

	"github.com/fs714/go-ndpi/gondpi"
	ndpitypes "github.com/fs714/go-ndpi/gondpi/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	dpitypes "kaliwall/internal/dpi/types"
)

type flowState struct {
	flow      *gondpi.NdpiFlow
	ipProto   uint8
	processed int
	completed bool
	result    Result
	lastSeen  time.Time
}

type classifier struct {
	mu          sync.Mutex
	cfg         Config
	dm          *gondpi.NdpiDetectionModule
	flows       map[string]*flowState
	lastCleanup time.Time
	stats       Stats
	closed      bool
}

// NewClassifier initializes an nDPI-backed flow classifier.
func NewClassifier(cfg Config) (Classifier, error) {
	resolved := cfg.withDefaults()

	bitmask := gondpi.NewNdpiProtocolBitmask()
	bitmask = gondpi.NdpiProtocolBitmaskSetAll(bitmask)

	dm, err := gondpi.NdpiDetectionModuleInitialize(ndpitypes.NDPI_NO_PREFS, bitmask)
	if err != nil {
		return nil, err
	}

	return &classifier{
		cfg:   resolved,
		dm:    dm,
		flows: make(map[string]*flowState),
	}, nil
}

func (c *classifier) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	for key, state := range c.flows {
		if state != nil && state.flow != nil {
			state.flow.Close()
		}
		delete(c.flows, key)
	}
	if c.dm != nil {
		c.dm.Close()
	}
	c.closed = true
}

func (c *classifier) Stats() map[string]uint64 {
	base := c.stats.snapshot()
	c.mu.Lock()
	base["active_flows"] = uint64(len(c.flows))
	c.mu.Unlock()
	return base
}

func (c *classifier) ClassifyPacket(flowKey string, pkt gopacket.Packet, decoded dpitypes.DecodedPacket, _ dpitypes.InspectResult, now time.Time) (Result, bool) {
	if pkt == nil {
		c.stats.incMiss()
		return Result{}, false
	}

	if flowKey == "" {
		flowKey = BuildFlowKey(decoded)
	}

	ipPacket, ok := extractIPPacket(pkt)
	if !ok || len(ipPacket) == 0 {
		c.stats.incMiss()
		return Result{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Result{}, false
	}

	state, err := c.getOrCreateFlowLocked(flowKey, decoded, now)
	if err != nil {
		c.stats.incError()
		return Result{}, false
	}

	state.lastSeen = now
	if state.completed {
		c.stats.incHit()
		c.cleanupLocked(now)
		return state.result, true
	}

	proto := c.dm.PacketProcessing(state.flow, ipPacket, uint16(len(ipPacket)), now.UnixMilli())
	state.processed++

	res, complete := c.tryFinalizeLocked(state, proto)
	if !complete {
		c.stats.incMiss()
		c.cleanupLocked(now)
		return Result{}, false
	}

	state.completed = true
	state.result = res
	c.stats.incHit()
	c.cleanupLocked(now)
	return res, true
}

func (c *classifier) getOrCreateFlowLocked(flowKey string, decoded dpitypes.DecodedPacket, now time.Time) (*flowState, error) {
	if state, exists := c.flows[flowKey]; exists {
		return state, nil
	}

	flow, err := gondpi.NewNdpiFlow()
	if err != nil {
		return nil, err
	}

	state := &flowState{
		flow:     flow,
		ipProto:  tupleProtocolToIPProto(decoded.Tuple.Protocol),
		lastSeen: now,
	}
	c.flows[flowKey] = state
	c.stats.incFlow()
	return state, nil
}

func (c *classifier) tryFinalizeLocked(state *flowState, proto gondpi.NdpiProto) (Result, bool) {
	appKnown := proto.AppProtocolId != ndpitypes.NDPI_PROTOCOL_UNKNOWN
	enoughPackets := state.processed >= c.maxPacketsByProto(state.ipProto)

	if !appKnown {
		extraPossible := c.dm.IsExtraDissectionPossible(state.flow)
		if !enoughPackets && extraPossible {
			return Result{}, false
		}

		if c.cfg.EnableGuess {
			guessedProto, guessed := c.dm.DetectionGiveup(state.flow, true)
			c.stats.incGiveup()
			return flowResult(state.flow, guessedProto, guessed), true
		}

		finalProto, _ := c.dm.DetectionGiveup(state.flow, false)
		c.stats.incGiveup()
		return flowResult(state.flow, finalProto, false), true
	}

	return flowResult(state.flow, proto, false), true
}

func (c *classifier) maxPacketsByProto(ipProto uint8) int {
	if ipProto == uint8(layers.IPProtocolUDP) {
		return c.cfg.MaxUDPPackets
	}
	return c.cfg.MaxTCPPackets
}

func tupleProtocolToIPProto(proto string) uint8 {
	switch proto {
	case "udp":
		return uint8(layers.IPProtocolUDP)
	case "icmp":
		return uint8(layers.IPProtocolICMPv4)
	case "icmpv6":
		return uint8(layers.IPProtocolICMPv6)
	default:
		return uint8(layers.IPProtocolTCP)
	}
}

func (c *classifier) cleanupLocked(now time.Time) {
	if c.cfg.IdleTTL <= 0 || c.cfg.CleanupInterval <= 0 {
		return
	}
	if !c.lastCleanup.IsZero() && now.Sub(c.lastCleanup) < c.cfg.CleanupInterval {
		return
	}
	c.lastCleanup = now
	cutoff := now.Add(-c.cfg.IdleTTL)
	for key, state := range c.flows {
		if state == nil || state.lastSeen.After(cutoff) {
			continue
		}
		if state.flow != nil {
			state.flow.Close()
		}
		delete(c.flows, key)
	}
	c.stats.incCleanup()
}

func flowResult(flow *gondpi.NdpiFlow, proto gondpi.NdpiProto, guessed bool) Result {
	confidence := "Unknown"
	if flow != nil {
		confidence = normalizeName(flow.GetConfidence().ToName())
	}
	return Result{
		MasterProtocol: normalizeName(proto.MasterProtocolId.ToName()),
		AppProtocol:    normalizeName(proto.AppProtocolId.ToName()),
		Category:       normalizeName(proto.CategoryId.ToName()),
		Confidence:     confidence,
		Guessed:        guessed,
	}
}

func extractIPPacket(pkt gopacket.Packet) ([]byte, bool) {
	if ipv4Layer := pkt.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, ok := ipv4Layer.(*layers.IPv4)
		if !ok {
			return nil, false
		}
		return joinLayerBytes(ipv4.Contents, ipv4.Payload), true
	}

	if ipv6Layer := pkt.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, ok := ipv6Layer.(*layers.IPv6)
		if !ok {
			return nil, false
		}
		return joinLayerBytes(ipv6.Contents, ipv6.Payload), true
	}

	return nil, false
}

func joinLayerBytes(header []byte, payload []byte) []byte {
	total := len(header) + len(payload)
	if total == 0 {
		return nil
	}
	buf := make([]byte, 0, total)
	buf = append(buf, header...)
	buf = append(buf, payload...)
	return buf
}

var _ Classifier = (*classifier)(nil)
