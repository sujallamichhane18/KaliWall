// Package ml provides optional machine-learning anomaly scoring integrations.
package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	defaultScriptPath   = "machinelearning/infer_xgboost.py"
	defaultModelPath    = "machinelearning/xgboost_anomaly_model.joblib"
	defaultMetadataPath = "machinelearning/training_metadata.json"
	defaultTimeout      = 1500 * time.Millisecond
)

var errPredictorDisabled = errors.New("ml anomaly predictor disabled")

// AnomalyPredictor bridges Go anomaly features to a Python XGBoost joblib model.
type AnomalyPredictor struct {
	enabled      bool
	pythonCmd    string
	scriptPath   string
	modelPath    string
	metadataPath string
	timeout      time.Duration
	threshold    *float64
}

// Prediction is the normalized ML output consumed by the anomaly API.
type Prediction struct {
	Available      bool
	Score          float64
	Threshold      float64
	IsAnomaly      bool
	PredictedClass int
	FeatureCount   int
	Warning        string
}

type predictRequest struct {
	ModelPath    string             `json:"model_path"`
	MetadataPath string             `json:"metadata_path,omitempty"`
	Features     map[string]float64 `json:"features"`
	Threshold    *float64           `json:"threshold,omitempty"`
}

type predictResponse struct {
	OK             bool    `json:"ok"`
	Error          string  `json:"error,omitempty"`
	Warning        string  `json:"warning,omitempty"`
	Score          float64 `json:"score"`
	Threshold      float64 `json:"threshold"`
	IsAnomaly      bool    `json:"is_anomaly"`
	PredictedClass int     `json:"predicted_class"`
	FeatureCount   int     `json:"feature_count"`
}

// NewAnomalyPredictorFromEnv builds an optional predictor from environment settings.
func NewAnomalyPredictorFromEnv() *AnomalyPredictor {
	predictor := &AnomalyPredictor{enabled: false, timeout: defaultTimeout}
	if !envBool("KALIWALL_ML_ANOMALY_ENABLED", true) {
		return predictor
	}

	pythonCmd := strings.TrimSpace(os.Getenv("KALIWALL_ML_PYTHON_CMD"))
	if pythonCmd == "" {
		pythonCmd = defaultPythonCommand()
	}
	if _, err := exec.LookPath(pythonCmd); err != nil {
		return predictor
	}

	scriptPath := resolveExistingPath(strings.TrimSpace(os.Getenv("KALIWALL_ML_SCRIPT_PATH")), defaultScriptPath)
	modelPath := resolveExistingPath(strings.TrimSpace(os.Getenv("KALIWALL_ML_MODEL_PATH")), defaultModelPath)
	metadataPath := resolveExistingPath(strings.TrimSpace(os.Getenv("KALIWALL_ML_METADATA_PATH")), defaultMetadataPath)
	if scriptPath == "" || modelPath == "" {
		return predictor
	}

	predictor.enabled = true
	predictor.pythonCmd = pythonCmd
	predictor.scriptPath = scriptPath
	predictor.modelPath = modelPath
	predictor.metadataPath = metadataPath
	predictor.timeout = envDurationMs("KALIWALL_ML_TIMEOUT_MS", defaultTimeout)
	if threshold, ok := envFloat("KALIWALL_ML_THRESHOLD"); ok {
		t := clampFloat(threshold, 0, 1)
		predictor.threshold = &t
	}
	return predictor
}

// Enabled reports whether ML inference is currently active.
func (p *AnomalyPredictor) Enabled() bool {
	return p != nil && p.enabled
}

// ModelPath exposes the resolved model file path.
func (p *AnomalyPredictor) ModelPath() string {
	if p == nil {
		return ""
	}
	return p.modelPath
}

// Predict runs Python inference against the configured XGBoost joblib model.
func (p *AnomalyPredictor) Predict(features map[string]float64) (Prediction, error) {
	if p == nil || !p.enabled {
		return Prediction{}, errPredictorDisabled
	}
	if features == nil {
		features = map[string]float64{}
	}

	request := predictRequest{
		ModelPath:    p.modelPath,
		MetadataPath: p.metadataPath,
		Features:     features,
		Threshold:    p.threshold,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return Prediction{}, fmt.Errorf("marshal ml request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, p.pythonCmd, p.scriptPath)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Prediction{}, fmt.Errorf("ml inference timeout after %s", p.timeout.String())
	}
	if runErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail != "" {
			return Prediction{}, fmt.Errorf("ml inference failed: %v (%s)", runErr, detail)
		}
		return Prediction{}, fmt.Errorf("ml inference failed: %w", runErr)
	}

	raw := bytes.TrimSpace(stdout.Bytes())
	if len(raw) == 0 {
		return Prediction{}, errors.New("ml inference produced empty output")
	}

	var response predictResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return Prediction{}, fmt.Errorf("parse ml response: %w", err)
	}
	if !response.OK {
		msg := strings.TrimSpace(response.Error)
		if msg == "" {
			msg = "ml bridge returned an unsuccessful response"
		}
		return Prediction{}, errors.New(msg)
	}

	score := clampFloat(response.Score, 0, 1)
	threshold := clampFloat(response.Threshold, 0, 1)
	if threshold <= 0 {
		threshold = 0.5
	}
	prediction := Prediction{
		Available:      true,
		Score:          score,
		Threshold:      threshold,
		IsAnomaly:      response.IsAnomaly,
		PredictedClass: response.PredictedClass,
		FeatureCount:   response.FeatureCount,
		Warning:        strings.TrimSpace(response.Warning),
	}
	if prediction.PredictedClass != 0 && prediction.PredictedClass != 1 {
		if prediction.IsAnomaly {
			prediction.PredictedClass = 1
		} else {
			prediction.PredictedClass = 0
		}
	}
	return prediction, nil
}

func defaultPythonCommand() string {
	if runtime.GOOS == "windows" {
		return "python"
	}
	return "python3"
}

func envBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

func envFloat(key string) (float64, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func envDurationMs(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms < 200 {
		return fallback
	}
	if ms > 15000 {
		ms = 15000
	}
	return time.Duration(ms) * time.Millisecond
}

func resolveExistingPath(preferred string, fallback string) string {
	if preferred != "" {
		if resolved := firstExistingFile(preferred); resolved != "" {
			return resolved
		}
		return ""
	}
	return firstExistingFile(fallback)
}

func firstExistingFile(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}

	candidates := make([]string, 0, 6)
	add := func(p string) {
		if strings.TrimSpace(p) == "" {
			return
		}
		for _, existing := range candidates {
			if existing == p {
				return
			}
		}
		candidates = append(candidates, p)
	}

	add(candidate)
	if !filepath.IsAbs(candidate) {
		if cwd, err := os.Getwd(); err == nil {
			add(filepath.Join(cwd, candidate))
		}
		if exePath, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exePath)
			add(filepath.Join(exeDir, candidate))
			add(filepath.Join(exeDir, "..", candidate))
			add(filepath.Join(exeDir, "..", "..", candidate))
		}
	}

	for _, p := range candidates {
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return p
	}
	return ""
}

func clampFloat(v float64, lo float64, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
