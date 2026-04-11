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