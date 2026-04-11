package api

import (
	"fmt"
	"path/filepath"
	"testing"

	"kaliwall/internal/firewall"
	"kaliwall/internal/logger"
)

func newAnomalyTestHandlers(t *testing.T) (*handlers, func()) {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "traffic.log")
	tl, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("create traffic logger: %v", err)
	}
	fw := firewall.New(tl, nil)

	h := &handlers{fw: fw, logger: tl}
	cleanup := func() {
		tl.Close()
	}
	return h, cleanup
}

func TestBuildTrafficAnomalySnapshotDetectsBlockedRatioSpike(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	for i := 0; i < 80; i++ {
		src := fmt.Sprintf("203.0.113.%d", (i%6)+10)
		h.logger.Log("BLOCK", src, "10.0.0.50", "tcp", "suspicious payload scan detected")
	}
	for i := 0; i < 20; i++ {
		src := fmt.Sprintf("198.51.100.%d", (i%4)+20)
		h.logger.Log("ALLOW", src, "10.0.0.10", "tcp", "normal traffic")
	}

	snapshot := h.buildTrafficAnomalySnapshot(500, 15)
	if snapshot.TotalAnomalies == 0 {
		t.Fatalf("expected anomalies, got none")
	}

	foundBlockedRatio := false
	for _, a := range snapshot.Anomalies {
		if a.Type == "blocked_ratio_spike" {
			foundBlockedRatio = true
			break
		}
	}
	if !foundBlockedRatio {
		t.Fatalf("expected blocked_ratio_spike anomaly, got %#v", snapshot.Anomalies)
	}

	if snapshot.RiskScore <= 0 {
		t.Fatalf("expected positive risk score, got %d", snapshot.RiskScore)
	}
}

func TestBuildTrafficAnomalySnapshotNoAnomalyForLowVolume(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	for i := 0; i < 12; i++ {
		h.logger.Log("ALLOW", "192.0.2.10", "10.0.0.1", "udp", "dns lookup")
	}

	snapshot := h.buildTrafficAnomalySnapshot(200, 15)
	if snapshot.TotalAnomalies != 0 {
		t.Fatalf("expected no anomalies for low-volume benign traffic, got %d", snapshot.TotalAnomalies)
	}
	if snapshot.Status != "normal" {
		t.Fatalf("expected normal status, got %q", snapshot.Status)
	}
}

func TestBuildTrafficAnomalySnapshotDetectsSourcePortScan(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	for i := 0; i < 78; i++ {
		dstPort := 1000 + (i % 26)
		h.logger.Log("BLOCK", "203.0.113.250", "10.0.0.80", "tcp", fmt.Sprintf("scan probe dst_port=%d suspicious payload", dstPort))
	}
	for i := 0; i < 24; i++ {
		h.logger.Log("ALLOW", fmt.Sprintf("198.51.100.%d", i+1), "10.0.0.20", "tcp", "normal web traffic")
	}

	snapshot := h.buildTrafficAnomalySnapshot(600, 15)
	if snapshot.TotalAnomalies == 0 {
		t.Fatalf("expected anomalies, got none")
	}

	found := false
	for _, a := range snapshot.Anomalies {
		if a.Type == "source_port_scan" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected source_port_scan anomaly, got %#v", snapshot.Anomalies)
	}
}

func TestBuildTrafficAnomalySnapshotDetectsSourceTargetSweep(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	for i := 0; i < 70; i++ {
		dst := fmt.Sprintf("10.0.1.%d", (i%35)+1)
		h.logger.Log("BLOCK", "203.0.113.77", dst, "tcp", "scanner sweep dst_port=443 suspicious payload")
	}
	for i := 0; i < 22; i++ {
		h.logger.Log("ALLOW", fmt.Sprintf("198.51.100.%d", i+1), "10.0.0.30", "udp", "dns lookup")
	}

	snapshot := h.buildTrafficAnomalySnapshot(700, 15)
	if snapshot.TotalAnomalies == 0 {
		t.Fatalf("expected anomalies, got none")
	}

	found := false
	for _, a := range snapshot.Anomalies {
		if a.Type == "source_target_sweep" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected source_target_sweep anomaly, got %#v", snapshot.Anomalies)
	}
}

func TestBuildTrafficAnomalySnapshotRiskScoreBoundedAndElevated(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	for i := 0; i < 220; i++ {
		dst := fmt.Sprintf("10.2.%d.%d", i%12, (i%40)+1)
		dstPort := 1000 + (i % 55)
		h.logger.Log("BLOCK", "203.0.113.240", dst, "tcp", fmt.Sprintf("aggressive scan probe dst_port=%d suspicious payload", dstPort))
	}
	for i := 0; i < 40; i++ {
		h.logger.Log("ALLOW", fmt.Sprintf("198.51.100.%d", i+1), "10.0.0.11", "udp", "normal dns lookup")
	}

	snapshot := h.buildTrafficAnomalySnapshot(1200, 15)
	if snapshot.RiskScore < 0 || snapshot.RiskScore > 100 {
		t.Fatalf("expected risk score to be clamped within 0..100, got %d", snapshot.RiskScore)
	}
	if snapshot.RiskScore < 55 {
		t.Fatalf("expected elevated/high risk score for sustained attack pattern, got %d", snapshot.RiskScore)
	}
	if snapshot.Status == "normal" {
		t.Fatalf("expected non-normal status under attack load, got %q", snapshot.Status)
	}
}
