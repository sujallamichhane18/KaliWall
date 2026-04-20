package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"kaliwall/internal/models"
)

const (
	defaultMLOverrideRulesPath = "configs/ml-override-rules.yaml"
	envMLOverrideRulesEnabled  = "KALIWALL_ML_OVERRIDE_RULES_ENABLED"
	envMLOverrideRulesPath     = "KALIWALL_ML_OVERRIDE_RULES_PATH"
	envMLScanOverrideEnabled   = "KALIWALL_ML_SCAN_OVERRIDE_ENABLED"
)

type mlDecisionOverrideFile struct {
	Enabled *bool                      `json:"enabled" yaml:"enabled"`
	Rules   []mlDecisionOverrideRuleFile `json:"rules" yaml:"rules"`
}

type mlDecisionOverrideRuleFile struct {
	ID       string                      `json:"id" yaml:"id"`
	Enabled  *bool                       `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Priority int                         `json:"priority,omitempty" yaml:"priority,omitempty"`
	Decision string                      `json:"decision" yaml:"decision"`
	Reason   string                      `json:"reason,omitempty" yaml:"reason,omitempty"`
	Warning  string                      `json:"warning,omitempty" yaml:"warning,omitempty"`
	Match    mlDecisionOverrideMatchFile `json:"match,omitempty" yaml:"match,omitempty"`
}

type mlDecisionOverrideMatchFile struct {
	ModelAvailable   *bool    `json:"model_available,omitempty" yaml:"model_available,omitempty"`
	ModelDecision    []string `json:"model_decision,omitempty" yaml:"model_decision,omitempty"`
	ModelIsAnomaly   *bool    `json:"model_is_anomaly,omitempty" yaml:"model_is_anomaly,omitempty"`
	MinModelScore    *float64 `json:"min_model_score,omitempty" yaml:"min_model_score,omitempty"`
	MaxModelScore    *float64 `json:"max_model_score,omitempty" yaml:"max_model_score,omitempty"`
	AnomalyTypes     []string `json:"anomaly_types,omitempty" yaml:"anomaly_types,omitempty"`
	AnomalySeverities []string `json:"anomaly_severities,omitempty" yaml:"anomaly_severities,omitempty"`
	MinAnomalyScore  *int     `json:"min_anomaly_score,omitempty" yaml:"min_anomaly_score,omitempty"`
	MaxAnomalyScore  *int     `json:"max_anomaly_score,omitempty" yaml:"max_anomaly_score,omitempty"`
	MinAnomalyCount  int      `json:"min_anomaly_count,omitempty" yaml:"min_anomaly_count,omitempty"`
}

type mlDecisionOverrideSet struct {
	path    string
	enabled bool
	rules   []mlDecisionOverrideRule
}

type mlDecisionOverrideRule struct {
	id       string
	order    int
	priority int

	decision string
	reason   string
	warning  string

	modelAvailable *bool
	modelDecision  map[string]struct{}
	modelIsAnomaly *bool
	minModelScore  *float64
	maxModelScore  *float64

	anomalyTypes      map[string]struct{}
	anomalySeverities map[string]struct{}
	minAnomalyScore   *int
	maxAnomalyScore   *int
	minAnomalyCount   int
}

func loadMLDecisionOverrideRulesFromEnv() (*mlDecisionOverrideSet, error) {
	if !envBoolDefault(envMLOverrideRulesEnabled, true) {
		return nil, nil
	}

	configPath := strings.TrimSpace(os.Getenv(envMLOverrideRulesPath))
	if configPath == "" {
		configPath = defaultMLOverrideRulesPath
	}

	resolvedPath := resolveOptionalConfigPath(configPath)
	if resolvedPath == "" {
		return nil, nil
	}

	return loadMLDecisionOverrideRulesFromFile(resolvedPath)
}

func loadMLDecisionOverrideRulesFromFile(configPath string) (*mlDecisionOverrideSet, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read ML override rules failed: %w", err)
	}

	parsed, err := decodeMLDecisionOverrideFile(configPath, data)
	if err != nil {
		return nil, err
	}

	absPath, absErr := filepath.Abs(configPath)
	if absErr == nil {
		configPath = absPath
	}
	return compileMLDecisionOverrideRules(configPath, parsed)
}

func decodeMLDecisionOverrideFile(configPath string, data []byte) (mlDecisionOverrideFile, error) {
	var parsed mlDecisionOverrideFile
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(configPath)))

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &parsed); err == nil {
			return parsed, nil
		}
		var rules []mlDecisionOverrideRuleFile
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return mlDecisionOverrideFile{}, fmt.Errorf("parse ML override rules yaml failed: %w", err)
		}
		parsed.Rules = rules
		return parsed, nil
	default:
		if err := json.Unmarshal(data, &parsed); err == nil {
			return parsed, nil
		}
		var rules []mlDecisionOverrideRuleFile
		if err := json.Unmarshal(data, &rules); err != nil {
			return mlDecisionOverrideFile{}, fmt.Errorf("parse ML override rules json failed: %w", err)
		}
		parsed.Rules = rules
		return parsed, nil
	}
}

func compileMLDecisionOverrideRules(configPath string, parsed mlDecisionOverrideFile) (*mlDecisionOverrideSet, error) {
	enabled := true
	if parsed.Enabled != nil {
		enabled = *parsed.Enabled
	}
	if !enabled {
		return &mlDecisionOverrideSet{path: configPath, enabled: false}, nil
	}

	compiled := make([]mlDecisionOverrideRule, 0, len(parsed.Rules))
	seenIDs := make(map[string]struct{}, len(parsed.Rules))

	for i, rawRule := range parsed.Rules {
		if rawRule.Enabled != nil && !*rawRule.Enabled {
			continue
		}

		ruleID := strings.TrimSpace(rawRule.ID)
		if ruleID == "" {
			ruleID = fmt.Sprintf("ml-override-%02d", i+1)
		}
		ruleKey := strings.ToLower(ruleID)
		if _, exists := seenIDs[ruleKey]; exists {
			return nil, fmt.Errorf("duplicate ML override rule id: %s", ruleID)
		}
		seenIDs[ruleKey] = struct{}{}

		decision, ok := normalizeMLOverrideDecision(rawRule.Decision)
		if !ok {
			return nil, fmt.Errorf("ML override rule %s has invalid decision %q", ruleID, rawRule.Decision)
		}

		priority := rawRule.Priority
		if priority == 0 {
			priority = 100
		}

		modelDecisionSet := make(map[string]struct{}, len(rawRule.Match.ModelDecision))
		for _, decisionMatch := range rawRule.Match.ModelDecision {
			normalized := normalizeMLDecisionKey(decisionMatch)
			if normalized == "" {
				continue
			}
			modelDecisionSet[normalized] = struct{}{}
		}

		anomalyTypeSet := make(map[string]struct{}, len(rawRule.Match.AnomalyTypes))
		for _, anomalyType := range rawRule.Match.AnomalyTypes {
			normalized := strings.ToLower(strings.TrimSpace(anomalyType))
			if normalized == "" {
				continue
			}
			anomalyTypeSet[normalized] = struct{}{}
		}

		anomalySeveritySet := make(map[string]struct{}, len(rawRule.Match.AnomalySeverities))
		for _, severity := range rawRule.Match.AnomalySeverities {
			normalized := strings.ToLower(strings.TrimSpace(severity))
			if normalized == "" {
				continue
			}
			anomalySeveritySet[normalized] = struct{}{}
		}

		minModelScore := clampFloatPointer(rawRule.Match.MinModelScore, 0, 1)
		maxModelScore := clampFloatPointer(rawRule.Match.MaxModelScore, 0, 1)
		if minModelScore != nil && maxModelScore != nil && *minModelScore > *maxModelScore {
			return nil, fmt.Errorf("ML override rule %s has min_model_score greater than max_model_score", ruleID)
		}

		minAnomalyScore := clampIntPointer(rawRule.Match.MinAnomalyScore, 0, 100)
		maxAnomalyScore := clampIntPointer(rawRule.Match.MaxAnomalyScore, 0, 100)
		if minAnomalyScore != nil && maxAnomalyScore != nil && *minAnomalyScore > *maxAnomalyScore {
			return nil, fmt.Errorf("ML override rule %s has min_anomaly_score greater than max_anomaly_score", ruleID)
		}

		compiled = append(compiled, mlDecisionOverrideRule{
			id:                ruleID,
			order:             i,
			priority:          priority,
			decision:          decision,
			reason:            strings.TrimSpace(rawRule.Reason),
			warning:           strings.TrimSpace(rawRule.Warning),
			modelAvailable:    rawRule.Match.ModelAvailable,
			modelDecision:     modelDecisionSet,
			modelIsAnomaly:    rawRule.Match.ModelIsAnomaly,
			minModelScore:     minModelScore,
			maxModelScore:     maxModelScore,
			anomalyTypes:      anomalyTypeSet,
			anomalySeverities: anomalySeveritySet,
			minAnomalyScore:   minAnomalyScore,
			maxAnomalyScore:   maxAnomalyScore,
			minAnomalyCount:   maxInt(rawRule.Match.MinAnomalyCount, 0),
		})
	}

	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].priority == compiled[j].priority {
			return compiled[i].order < compiled[j].order
		}
		return compiled[i].priority > compiled[j].priority
	})

	return &mlDecisionOverrideSet{path: configPath, enabled: true, rules: compiled}, nil
}

func (s *mlDecisionOverrideSet) Enabled() bool {
	return s != nil && s.enabled
}

func (s *mlDecisionOverrideSet) RuleCount() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

func (s *mlDecisionOverrideSet) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *mlDecisionOverrideSet) Apply(mlPrediction *models.TrafficAnomalyMLPrediction, anomalies []models.TrafficAnomaly) bool {
	if s == nil || !s.enabled || len(s.rules) == 0 || mlPrediction == nil || !mlPrediction.Enabled {
		return false
	}

	for _, rule := range s.rules {
		if !rule.matches(mlPrediction, anomalies) {
			continue
		}

		rule.apply(mlPrediction)

		reason := strings.TrimSpace(rule.reason)
		if reason == "" {
			reason = fmt.Sprintf("matched override rule %s", rule.id)
		}
		setMLOverrideMetadata(mlPrediction, "rule", rule.id, reason)
		appendMLWarning(mlPrediction, fmt.Sprintf("override rule %s: %s", rule.id, reason))
		if rule.warning != "" {
			appendMLWarning(mlPrediction, rule.warning)
		}
		return true
	}

	return false
}

func (r *mlDecisionOverrideRule) matches(mlPrediction *models.TrafficAnomalyMLPrediction, anomalies []models.TrafficAnomaly) bool {
	if mlPrediction == nil {
		return false
	}

	if r.modelAvailable != nil && mlPrediction.Available != *r.modelAvailable {
		return false
	}

	if len(r.modelDecision) > 0 {
		decision := normalizeMLDecisionKey(mlPrediction.Decision)
		if decision == "" {
			decision = "unknown"
		}
		if _, ok := r.modelDecision[decision]; !ok {
			return false
		}
	}

	if r.modelIsAnomaly != nil && mlPrediction.IsAnomaly != *r.modelIsAnomaly {
		return false
	}
	if r.minModelScore != nil && mlPrediction.Score < *r.minModelScore {
		return false
	}
	if r.maxModelScore != nil && mlPrediction.Score > *r.maxModelScore {
		return false
	}

	if r.minAnomalyCount > 0 && len(anomalies) < r.minAnomalyCount {
		return false
	}

	requiresAnomalyMatch := len(r.anomalyTypes) > 0 || len(r.anomalySeverities) > 0 || r.minAnomalyScore != nil || r.maxAnomalyScore != nil
	if !requiresAnomalyMatch {
		return true
	}

	for _, anomaly := range anomalies {
		if r.matchesAnomaly(anomaly) {
			return true
		}
	}

	return false
}

func (r *mlDecisionOverrideRule) matchesAnomaly(anomaly models.TrafficAnomaly) bool {
	if len(r.anomalyTypes) > 0 {
		kind := strings.ToLower(strings.TrimSpace(anomaly.Type))
		if _, ok := r.anomalyTypes[kind]; !ok {
			return false
		}
	}

	if len(r.anomalySeverities) > 0 {
		severity := strings.ToLower(strings.TrimSpace(anomaly.Severity))
		if _, ok := r.anomalySeverities[severity]; !ok {
			return false
		}
	}

	score := clampIntRange(anomaly.Score, 0, 100)
	if r.minAnomalyScore != nil && score < *r.minAnomalyScore {
		return false
	}
	if r.maxAnomalyScore != nil && score > *r.maxAnomalyScore {
		return false
	}

	return true
}

func (r *mlDecisionOverrideRule) apply(mlPrediction *models.TrafficAnomalyMLPrediction) {
	if mlPrediction == nil {
		return
	}

	switch r.decision {
	case "attack":
		mlPrediction.Decision = "attack"
		mlPrediction.IsAnomaly = true
		mlPrediction.PredictedClass = 1
		if mlPrediction.Available {
			if mlPrediction.Threshold <= 0 {
				mlPrediction.Threshold = 0.5
			}
			minScore := clampFloatRange(mlPrediction.Threshold+0.01, 0, 0.99)
			if mlPrediction.Score < minScore {
				mlPrediction.Score = minScore
			}
		}
	default:
		mlPrediction.Decision = "normal"
		mlPrediction.IsAnomaly = false
		mlPrediction.PredictedClass = 0
		if mlPrediction.Available {
			if mlPrediction.Threshold <= 0 {
				mlPrediction.Threshold = 0.5
			}
			if mlPrediction.Score >= mlPrediction.Threshold {
				mlPrediction.Score = clampFloatRange(mlPrediction.Threshold-0.01, 0, 1)
			}
		}
	}
}

func setMLOverrideMetadata(mlPrediction *models.TrafficAnomalyMLPrediction, source string, ruleID string, reason string) {
	if mlPrediction == nil {
		return
	}
	mlPrediction.OverrideApplied = true
	mlPrediction.OverrideSource = strings.TrimSpace(source)
	mlPrediction.OverrideRuleID = strings.TrimSpace(ruleID)
	mlPrediction.OverrideReason = strings.TrimSpace(reason)
}

func appendMLWarning(mlPrediction *models.TrafficAnomalyMLPrediction, note string) {
	if mlPrediction == nil {
		return
	}
	note = strings.TrimSpace(note)
	if note == "" {
		return
	}
	if strings.TrimSpace(mlPrediction.Warning) == "" {
		mlPrediction.Warning = note
		return
	}
	if strings.Contains(strings.ToLower(mlPrediction.Warning), strings.ToLower(note)) {
		return
	}
	mlPrediction.Warning += "; " + note
}

func resolveOptionalConfigPath(configPath string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return ""
	}

	candidates := make([]string, 0, 4)
	if filepath.IsAbs(configPath) {
		candidates = append(candidates, configPath)
	} else {
		candidates = append(candidates, configPath)
		if cwd, err := os.Getwd(); err == nil {
			candidates = append(candidates, filepath.Join(cwd, configPath))
		}
		if exePath, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exePath)
			candidates = append(candidates,
				filepath.Join(exeDir, configPath),
				filepath.Join(exeDir, "..", configPath),
			)
		}
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		abs := candidate
		if resolved, err := filepath.Abs(candidate); err == nil {
			abs = resolved
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}

		if info, err := os.Stat(abs); err == nil && !info.IsDir() {
			return abs
		}
	}

	return ""
}

func envBoolDefault(key string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch raw {
	case "1", "true", "yes", "on", "enabled", "enable":
		return true
	case "0", "false", "no", "off", "disabled", "disable":
		return false
	default:
		return fallback
	}
}

func normalizeMLOverrideDecision(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "attack", "anomaly", "block", "deny", "malicious":
		return "attack", true
	case "normal", "allow", "benign", "safe":
		return "normal", true
	default:
		return "", false
	}
}

func normalizeMLDecisionKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if normalized, ok := normalizeMLOverrideDecision(value); ok {
		return normalized
	}
	return value
}

func clampFloatPointer(value *float64, min float64, max float64) *float64 {
	if value == nil {
		return nil
	}
	clamped := clampFloatRange(*value, min, max)
	return &clamped
}

func clampIntPointer(value *int, min int, max int) *int {
	if value == nil {
		return nil
	}
	clamped := clampIntRange(*value, min, max)
	return &clamped
}

func clampFloatRange(value float64, min float64, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func clampIntRange(value int, min int, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func maxInt(value int, floor int) int {
	if value < floor {
		return floor
	}
	return value
}