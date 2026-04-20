package api

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"kaliwall/internal/models"
)

func TestLoadProjectMLOverrideRulesYAML(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get caller path")
	}

	rulesPath := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "configs", "ml-override-rules.yaml"))
	rules, err := loadMLDecisionOverrideRulesFromFile(rulesPath)
	if err != nil {
		t.Fatalf("failed to load ML override rules: %v", err)
	}
	if rules == nil {
		t.Fatal("expected non-nil ML override rules")
	}
	if !rules.Enabled() {
		t.Fatal("expected ML override rules to be enabled")
	}
	if rules.RuleCount() == 0 {
		t.Fatal("expected at least one active ML override rule")
	}
}

func TestEnforceMLScanDecisionOverrideAddsMetadata(t *testing.T) {
	prediction := &models.TrafficAnomalyMLPrediction{
		Enabled:        true,
		Available:      true,
		Decision:       "normal",
		Score:          0.28,
		Threshold:      0.55,
		IsAnomaly:      false,
		PredictedClass: 0,
	}

	anomalies := []models.TrafficAnomaly{
		{Type: "source_port_scan", Severity: "critical", Score: 78},
	}

	applied := enforceMLScanDecisionOverride(prediction, anomalies)
	if !applied {
		t.Fatal("expected scan override to be applied")
	}
	if prediction.Decision != "attack" || !prediction.IsAnomaly || prediction.PredictedClass != 1 {
		t.Fatalf("expected attack override, got decision=%q anomaly=%v class=%d", prediction.Decision, prediction.IsAnomaly, prediction.PredictedClass)
	}
	if !prediction.OverrideApplied {
		t.Fatal("expected override_applied=true")
	}
	if prediction.OverrideSource != "scan_signal" {
		t.Fatalf("expected override_source=scan_signal, got %q", prediction.OverrideSource)
	}
	if prediction.OverrideRuleID != "source_port_scan" {
		t.Fatalf("expected override_rule_id=source_port_scan, got %q", prediction.OverrideRuleID)
	}
	if !strings.Contains(strings.ToLower(prediction.Warning), "scan-signal override") {
		t.Fatalf("expected warning to include scan-signal override note, got %q", prediction.Warning)
	}
}

func TestApplyMLDecisionOverridesRuleCanSupersedeScanOverride(t *testing.T) {
	h := &handlers{
		mlDecisionOverrides: &mlDecisionOverrideSet{
			enabled: true,
			rules: []mlDecisionOverrideRule{
				{
					id:       "prefer-normal-source-scan",
					priority: 300,
					decision: "normal",
					reason:   "manual suppression for known scanner source profile",
					modelDecision: map[string]struct{}{
						"attack": {},
					},
					anomalyTypes: map[string]struct{}{
						"source_port_scan": {},
					},
				},
			},
		},
		mlScanOverrideEnabled:    true,
		mlScanOverrideConfigured: true,
	}

	prediction := &models.TrafficAnomalyMLPrediction{
		Enabled:        true,
		Available:      true,
		Decision:       "normal",
		Score:          0.34,
		Threshold:      0.55,
		IsAnomaly:      false,
		PredictedClass: 0,
	}

	anomalies := []models.TrafficAnomaly{
		{Type: "source_port_scan", Severity: "critical", Score: 82},
	}

	h.applyMLDecisionOverrides(prediction, anomalies)

	if prediction.Decision != "normal" || prediction.IsAnomaly || prediction.PredictedClass != 0 {
		t.Fatalf("expected rule override to end in normal decision, got decision=%q anomaly=%v class=%d", prediction.Decision, prediction.IsAnomaly, prediction.PredictedClass)
	}
	if !prediction.OverrideApplied {
		t.Fatal("expected override_applied=true")
	}
	if prediction.OverrideSource != "rule" {
		t.Fatalf("expected override_source=rule, got %q", prediction.OverrideSource)
	}
	if prediction.OverrideRuleID != "prefer-normal-source-scan" {
		t.Fatalf("expected override_rule_id to match rule, got %q", prediction.OverrideRuleID)
	}
	if !strings.Contains(strings.ToLower(prediction.Warning), "override rule prefer-normal-source-scan") {
		t.Fatalf("expected warning to include custom override note, got %q", prediction.Warning)
	}
}