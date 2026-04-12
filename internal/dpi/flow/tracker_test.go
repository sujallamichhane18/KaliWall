package flow

import (
	"testing"
	"time"

	"github.com/google/gopacket/layers"

	"kaliwall/internal/dpi/types"
)

func TestTrackerDNSLifecycleComplete(t *testing.T) {
	tracker := NewWithConfig(TrackerConfig{
		ShardCount:      1,
		MaxFlows:        16,
		MaxFlowsPerShard: 16,
		FlowTimeout:     time.Minute,
		ClosedFlowTTL:   10 * time.Second,
		CleanupInterval: time.Minute,
	})

	now := time.Now()
	query := types.DecodedPacket{
		Timestamp: now,
		Tuple: types.FiveTuple{
			SrcIP:    "10.1.1.10",
			DstIP:    "8.8.8.8",
			SrcPort:  53000,
			DstPort:  53,
			Protocol: "udp",
		},
		Payload:  []byte{0x01},
		DNSQuery: "example.com",
	}
	resp := types.DecodedPacket{
		Timestamp: now.Add(10 * time.Millisecond),
		Tuple: types.FiveTuple{
			SrcIP:    "8.8.8.8",
			DstIP:    "10.1.1.10",
			SrcPort:  53,
			DstPort:  53000,
			Protocol: "udp",
		},
		Payload: []byte{0x02},
	}

	tracker.ObserveDecoded(&query)
	tracker.ObserveDecoded(&resp)

	snapshot := tracker.Snapshot(4)
	if len(snapshot) != 1 {
		t.Fatalf("expected exactly one dns flow, got %d", len(snapshot))
	}
	rec := snapshot[0]
	if rec.Key.Protocol != FlowProtocolDNS {
		t.Fatalf("expected protocol dns, got %s", rec.Key.Protocol)
	}
	if rec.DNS.State != DNSStateComplete {
		t.Fatalf("expected dns state complete, got %s", rec.DNS.State)
	}
	if rec.Lifecycle != FlowLifecycleClosed {
		t.Fatalf("expected lifecycle closed, got %s", rec.Lifecycle)
	}
	if rec.DNS.QueryCount != 1 || rec.DNS.ResponseCount != 1 {
		t.Fatalf("expected dns query/response count 1/1, got %d/%d", rec.DNS.QueryCount, rec.DNS.ResponseCount)
	}
}

func TestTrackerTCPTLSLifecycleTransitions(t *testing.T) {
	tracker := NewWithConfig(TrackerConfig{
		ShardCount:      1,
		MaxFlows:        16,
		MaxFlowsPerShard: 16,
		FlowTimeout:     time.Minute,
		ClosedFlowTTL:   10 * time.Second,
		CleanupInterval: time.Minute,
	})

	now := time.Now()
	clientToServer := types.FiveTuple{SrcIP: "10.2.2.2", DstIP: "20.2.2.2", SrcPort: 50000, DstPort: 443, Protocol: "tcp"}
	serverToClient := types.FiveTuple{SrcIP: "20.2.2.2", DstIP: "10.2.2.2", SrcPort: 443, DstPort: 50000, Protocol: "tcp"}

	tracker.ObserveDecoded(&types.DecodedPacket{Timestamp: now, Tuple: clientToServer, TCPSegment: &layers.TCP{SYN: true}})
	tracker.ObserveDecoded(&types.DecodedPacket{Timestamp: now.Add(1 * time.Millisecond), Tuple: serverToClient, TCPSegment: &layers.TCP{SYN: true, ACK: true}})
	tracker.ObserveDecoded(&types.DecodedPacket{Timestamp: now.Add(2 * time.Millisecond), Tuple: clientToServer, TCPSegment: &layers.TCP{ACK: true}})

	tracker.ObserveInspection(types.InspectResult{Timestamp: now.Add(3 * time.Millisecond), Tuple: clientToServer, TLSSNI: "api.example.com"})
	tracker.ObserveInspection(types.InspectResult{Timestamp: now.Add(4 * time.Millisecond), Tuple: serverToClient})

	tracker.ObserveDecoded(&types.DecodedPacket{Timestamp: now.Add(5 * time.Millisecond), Tuple: clientToServer, TCPSegment: &layers.TCP{FIN: true}})
	tracker.ObserveDecoded(&types.DecodedPacket{Timestamp: now.Add(6 * time.Millisecond), Tuple: serverToClient, TCPSegment: &layers.TCP{FIN: true}})

	snapshot := tracker.Snapshot(4)
	if len(snapshot) != 1 {
		t.Fatalf("expected exactly one tls flow, got %d", len(snapshot))
	}
	rec := snapshot[0]
	if rec.Key.Protocol != FlowProtocolTLS {
		t.Fatalf("expected protocol tls, got %s", rec.Key.Protocol)
	}
	if rec.TCP.State != TCPStateClosed {
		t.Fatalf("expected tcp closed state, got %s", rec.TCP.State)
	}
	if rec.TLS.State != TLSStateEstablished {
		t.Fatalf("expected tls established state, got %s", rec.TLS.State)
	}
	if rec.Lifecycle != FlowLifecycleClosed {
		t.Fatalf("expected lifecycle closed, got %s", rec.Lifecycle)
	}
}

func TestTrackerEvictionKeepsBoundedMemory(t *testing.T) {
	tracker := NewWithConfig(TrackerConfig{
		ShardCount:      1,
		MaxFlows:        2,
		MaxFlowsPerShard: 2,
		FlowTimeout:     time.Minute,
		ClosedFlowTTL:   10 * time.Second,
		CleanupInterval: time.Minute,
	})

	now := time.Now()
	tracker.ObserveDecoded(&types.DecodedPacket{Timestamp: now, Tuple: types.FiveTuple{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1000, DstPort: 80, Protocol: "tcp"}})
	tracker.ObserveDecoded(&types.DecodedPacket{Timestamp: now.Add(1 * time.Millisecond), Tuple: types.FiveTuple{SrcIP: "3.3.3.3", DstIP: "4.4.4.4", SrcPort: 1001, DstPort: 80, Protocol: "tcp"}})
	tracker.ObserveDecoded(&types.DecodedPacket{Timestamp: now.Add(2 * time.Millisecond), Tuple: types.FiveTuple{SrcIP: "5.5.5.5", DstIP: "6.6.6.6", SrcPort: 1002, DstPort: 80, Protocol: "tcp"}})

	if got := tracker.SnapshotSize(); got > 2 {
		t.Fatalf("expected bounded flow table size <= 2, got %d", got)
	}
	stats := tracker.Stats()
	if stats.EvictedFlows == 0 {
		t.Fatalf("expected at least one eviction, got %d", stats.EvictedFlows)
	}
}

func TestTrackerExpirationRemovesIdleFlows(t *testing.T) {
	tracker := NewWithConfig(TrackerConfig{
		ShardCount:      1,
		MaxFlows:        16,
		MaxFlowsPerShard: 16,
		FlowTimeout:     25 * time.Millisecond,
		ClosedFlowTTL:   10 * time.Millisecond,
		CleanupInterval: 5 * time.Millisecond,
	})
	tracker.Start()
	defer tracker.Stop()

	tracker.ObserveDecoded(&types.DecodedPacket{
		Timestamp: time.Now(),
		Tuple:     types.FiveTuple{SrcIP: "9.9.9.9", DstIP: "8.8.8.8", SrcPort: 1111, DstPort: 2222, Protocol: "udp"},
	})

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if tracker.SnapshotSize() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected expired flow to be removed, active=%d", tracker.SnapshotSize())
}
