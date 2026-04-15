package api

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

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

func TestBuildTrafficAnomalySnapshotLearningModeForLowVolume(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	for i := 0; i < 12; i++ {
		h.logger.Log("ALLOW", "192.0.2.10", "10.0.0.1", "udp", "dns lookup")
	}

	snapshot := h.buildTrafficAnomalySnapshot(200, 15)
	if snapshot.TotalAnomalies != 0 {
		t.Fatalf("expected no anomalies while history is insufficient, got %d", snapshot.TotalAnomalies)
	}
	if snapshot.Status != "learning" {
		t.Fatalf("expected learning status before history readiness, got %q", snapshot.Status)
	}
	if snapshot.HistoryReady {
		t.Fatalf("expected history_ready=false for low sample count")
	}
	if snapshot.HistorySamples != 12 {
		t.Fatalf("expected history sample count 12, got %d", snapshot.HistorySamples)
	}
	if snapshot.HistoryRequiredSamples <= snapshot.HistorySamples {
		t.Fatalf("expected required history to exceed current samples, got required=%d samples=%d", snapshot.HistoryRequiredSamples, snapshot.HistorySamples)
	}
	if snapshot.LearningMessage == "" {
		t.Fatalf("expected non-empty learning message when history is not ready")
	}
}

func TestBuildTrafficAnomalySnapshotRequiresTimeCoverageAtSampleThreshold(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	for i := 0; i < 80; i++ {
		action := "ALLOW"
		detail := "normal traffic"
		if i%10 == 0 {
			action = "BLOCK"
			detail = "suspicious payload"
		}
		src := fmt.Sprintf("203.0.113.%d", (i%6)+10)
		h.logger.Log(action, src, "10.0.0.10", "tcp", detail)
	}

	snapshot := h.buildTrafficAnomalySnapshot(400, 15)
	if snapshot.HistorySamples != 80 {
		t.Fatalf("expected history sample count 80, got %d", snapshot.HistorySamples)
	}
	if snapshot.HistoryReady {
		t.Fatalf("expected history_ready=false at pure sample threshold without enough time coverage")
	}
	if snapshot.Status != "learning" {
		t.Fatalf("expected learning status before time baseline is mature, got %q", snapshot.Status)
	}
	if snapshot.TotalAnomalies != 0 {
		t.Fatalf("expected no anomalies while baseline is still learning, got %d", snapshot.TotalAnomalies)
	}
	if snapshot.LearningMessage == "" {
		t.Fatalf("expected learning message to explain sample/time readiness")
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

func TestBuildTrafficAnomalySnapshotDetectsCoordinatedScanCampaign(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	attackers := []string{"203.0.113.200", "203.0.113.201", "203.0.113.202", "203.0.113.203"}
	for i, src := range attackers {
		for j := 0; j < 14; j++ {
			dst := fmt.Sprintf("10.8.%d.%d", i+1, (j%9)+1)
			dstPort := 2000 + j
			h.logger.Log("BLOCK", src, dst, "tcp", fmt.Sprintf("coordinated scan probe dst_port=%d suspicious payload", dstPort))
		}
	}

	for i := 0; i < 24; i++ {
		h.logger.Log("ALLOW", fmt.Sprintf("198.51.100.%d", i+1), "10.0.0.15", "udp", "normal dns lookup")
	}

	snapshot := h.buildTrafficAnomalySnapshot(1200, 15)
	if snapshot.TotalAnomalies == 0 {
		t.Fatalf("expected anomalies, got none")
	}

	found := false
	for _, a := range snapshot.Anomalies {
		if a.Type == "coordinated_scan_campaign" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected coordinated_scan_campaign anomaly, got %#v", snapshot.Anomalies)
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

func TestAnomalyTrendHistoryIncludesRiskAndDetectors(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	for i := 0; i < 90; i++ {
		src := fmt.Sprintf("203.0.113.%d", (i%8)+10)
		h.logger.Log("BLOCK", src, "10.0.0.50", "tcp", "suspicious payload scan detected")
	}
	for i := 0; i < 30; i++ {
		src := fmt.Sprintf("198.51.100.%d", (i%6)+20)
		h.logger.Log("ALLOW", src, "10.0.0.10", "tcp", "normal traffic")
	}

	first := h.buildTrafficAnomalySnapshot(800, 15)
	if !first.HistoryReady {
		t.Fatalf("expected history ready for high sample volume")
	}
	if first.TotalAnomalies == 0 {
		t.Fatalf("expected anomalies for trend-history test setup")
	}

	first.GeneratedAt = time.Now().UTC().Add(-2 * time.Minute)
	h.recordAnomalySnapshot(first)

	second := first
	second.GeneratedAt = first.GeneratedAt.Add(1 * time.Minute)
	second.RiskScore = 72
	second.Status = "high"
	h.recordAnomalySnapshot(second)

	withTrend := h.withAnomalyTrendHistory(second, 180)
	if len(withTrend.RiskTrend) < 2 {
		t.Fatalf("expected at least two risk trend points, got %d", len(withTrend.RiskTrend))
	}
	if len(withTrend.DetectorTrends) == 0 {
		t.Fatalf("expected detector trend series to be present")
	}

	hasPoints := false
	for _, series := range withTrend.DetectorTrends {
		if len(series.Points) > 0 {
			hasPoints = true
			break
		}
	}
	if !hasPoints {
		t.Fatalf("expected detector trend points in returned series")
	}
}

func TestBuildTrafficAnomalySnapshotDetectsProtocolRiskSkew(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	for i := 0; i < 72; i++ {
		src := fmt.Sprintf("203.0.113.%d", (i%9)+30)
		h.logger.Log("BLOCK", src, "10.9.0.5", "udp", "suspicious dns flood payload")
	}
	for i := 0; i < 24; i++ {
		src := fmt.Sprintf("198.51.100.%d", (i%10)+10)
		h.logger.Log("ALLOW", src, "10.9.0.6", "tcp", "normal web traffic")
	}

	snapshot := h.buildTrafficAnomalySnapshot(900, 15)
	if snapshot.TotalAnomalies == 0 {
		t.Fatalf("expected anomalies, got none")
	}

	found := false
	for _, a := range snapshot.Anomalies {
		if a.Type == "protocol_risk_skew" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected protocol_risk_skew anomaly, got %#v", snapshot.Anomalies)
	}
}

func TestBuildTrafficAnomalySnapshotDetectsMinuteVolatilitySpike(t *testing.T) {
	h, cleanup := newAnomalyTestHandlers(t)
	defer cleanup()

	protocols := []string{"tcp", "udp", "dns"}
	for i := 0; i < 96; i++ {
		src := fmt.Sprintf("203.0.113.%d", (i%32)+1)
		dst := fmt.Sprintf("10.5.0.%d", (i%28)+1)
		proto := protocols[i%len(protocols)]
		h.logger.Log("ALLOW", src, dst, proto, "normal traffic sample")
	}

	snapshot := h.buildTrafficAnomalySnapshot(1000, 15)
	if snapshot.TotalAnomalies == 0 {
		t.Fatalf("expected anomalies, got none")
	}

	found := false
	for _, a := range snapshot.Anomalies {
		if a.Type == "minute_volatility_spike" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected minute_volatility_spike anomaly, got %#v", snapshot.Anomalies)
	}
}

func TestComputeEWMABaselineAdaptsToRecentTraffic(t *testing.T) {
	values := []float64{10, 11, 10, 12, 11, 40}
	baseline := computeEWMABaseline(values, 0.30)

	if baseline.Samples != len(values) {
		t.Fatalf("expected %d samples, got %d", len(values), baseline.Samples)
	}
	if baseline.Mean <= 12 || baseline.Mean >= 40 {
		t.Fatalf("expected EWMA mean to adapt between baseline and spike, got %.2f", baseline.Mean)
	}
	if baseline.StdDev <= 0 {
		t.Fatalf("expected positive EWMA stddev, got %.4f", baseline.StdDev)
	}
	if baseline.Last != 40 {
		t.Fatalf("expected last value tracking to be 40, got %.2f", baseline.Last)
	}
}

func TestEvaluateIsolationForestWindowDetectsOutlierMinute(t *testing.T) {
	minuteAgg := make(map[int64]*trafficMinuteAggregate)
	makeAgg := func(total, blocked, suspicious, src, dst int, protoTCP, protoUDP int) *trafficMinuteAggregate {
		a := &trafficMinuteAggregate{
			Total:          total,
			Blocked:        blocked,
			Suspicious:     suspicious,
			SourceSet:      make(map[string]struct{}, src),
			DestinationSet: make(map[string]struct{}, dst),
			ProtocolCounts: map[string]int{"TCP": protoTCP, "UDP": protoUDP},
		}
		for i := 0; i < src; i++ {
			a.SourceSet[fmt.Sprintf("203.0.113.%d", i+1)] = struct{}{}
		}
		for i := 0; i < dst; i++ {
			a.DestinationSet[fmt.Sprintf("10.0.0.%d", i+1)] = struct{}{}
		}
		return a
	}

	for bucket := int64(1); bucket <= 55; bucket++ {
		minuteAgg[bucket] = makeAgg(12, 1, 1, 5, 4, 9, 3)
	}
	for bucket := int64(56); bucket <= 70; bucket++ {
		minuteAgg[bucket] = makeAgg(11, 1, 1, 5, 4, 8, 3)
	}

	minuteAgg[68] = makeAgg(120, 38, 26, 42, 31, 96, 24)

	result := evaluateIsolationForestWindow(minuteAgg, 56, 70)
	if !result.Ready {
		t.Fatalf("expected isolation forest result to be ready")
	}
	if result.AnomalyVectors == 0 {
		t.Fatalf("expected at least one anomaly minute, got 0")
	}
	if result.AnomalyRatio <= 0 {
		t.Fatalf("expected positive anomaly ratio, got %.4f", result.AnomalyRatio)
	}
	if result.WorstMinuteBucket != 68 {
		t.Fatalf("expected worst minute bucket 68, got %d", result.WorstMinuteBucket)
	}
}

func TestFormatHourBucket(t *testing.T) {
	cases := []struct {
		hour int
		want string
	}{
		{hour: 0, want: "00:00-00:59"},
		{hour: 9, want: "09:00-09:59"},
		{hour: 23, want: "23:00-23:59"},
		{hour: -1, want: "unknown"},
		{hour: 24, want: "unknown"},
	}

	for _, tc := range cases {
		got := formatHourBucket(tc.hour)
		if got != tc.want {
			t.Fatalf("formatHourBucket(%d) = %q, want %q", tc.hour, got, tc.want)
		}
	}
}

func TestComputeRobustSeriesStatsCapturesMedianAndSpread(t *testing.T) {
	values := []float64{10, 10, 11, 12, 12, 13, 40}
	stats := computeRobustSeriesStats(values)

	if stats.Samples != len(values) {
		t.Fatalf("expected %d samples, got %d", len(values), stats.Samples)
	}
	if stats.Median < 11.5 || stats.Median > 12.5 {
		t.Fatalf("expected median around 12, got %.3f", stats.Median)
	}
	if stats.MAD <= 0 {
		t.Fatalf("expected positive MAD, got %.6f", stats.MAD)
	}
	if stats.RobustStd <= 0 {
		t.Fatalf("expected positive robust stddev, got %.6f", stats.RobustStd)
	}
	if stats.P90 <= stats.Median {
		t.Fatalf("expected p90 to exceed median, got p90=%.3f median=%.3f", stats.P90, stats.Median)
	}
}
