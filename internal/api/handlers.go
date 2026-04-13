// Package api provides the HTTP router and REST API handlers for KaliWall.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kaliwall/internal/analytics"
	"kaliwall/internal/dpi/pipeline"
	"kaliwall/internal/firewall"
	"kaliwall/internal/geoip"
	"kaliwall/internal/logger"
	"kaliwall/internal/models"
	"kaliwall/internal/proxy"
	"kaliwall/internal/sysinfo"
	"kaliwall/internal/threatintel"
	"kaliwall/internal/ai"
)

type dpiStatusProvider interface {
	Status() pipeline.Status
}

type dpiControlProvider interface {
	SetEnabled(enabled bool) error
}

type dpiDetailedStatsProvider interface {
	DetailedStats() interface{}
}

type dpiWorkersProvider interface {
	SetWorkers(workers int) error
}

type maliciousDomainProxy interface {
	DomainStats() proxy.DomainBlocklistStats
	DomainList() []string
	ReloadDomains() (int, error)
	AddDomain(domain string) (bool, string, error)
	RemoveDomain(domain string) (bool, string, error)
	IsDomainBlocked(domain string) bool
	RecentBlockedEvents(limit int) []proxy.BlockedEvent
}

// DPIProvider provides synchronized access to an optional DPI pipeline.
type DPIProvider struct {
	mu       sync.RWMutex
	provider dpiStatusProvider
}

// NewDPIProvider constructs a thread-safe holder for the DPI dependency.
func NewDPIProvider(provider dpiStatusProvider) *DPIProvider {
	p := &DPIProvider{}
	p.Set(provider)
	return p
}

// Set updates the active DPI provider (safe for async initialization paths).
func (p *DPIProvider) Set(provider dpiStatusProvider) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.provider = provider
}

// Status returns DPI status and whether a provider is available.
func (p *DPIProvider) Status() (pipeline.Status, bool) {
	if p == nil {
		return pipeline.Status{Enabled: false, Running: false}, false
	}
	p.mu.RLock()
	provider := p.provider
	p.mu.RUnlock()
	if provider == nil {
		return pipeline.Status{Enabled: false, Running: false}, false
	}
	return provider.Status(), true
}

// SetEnabled toggles DPI on/off if the provider supports lifecycle control.
func (p *DPIProvider) SetEnabled(enabled bool) error {
	if p == nil {
		return errors.New("DPI provider unavailable")
	}
	if !enabled {
		return errors.New("DPI disable removed: always-on mode")
	}
	p.mu.RLock()
	provider := p.provider
	p.mu.RUnlock()
	if provider == nil {
		return errors.New("DPI provider unavailable")
	}
	ctrl, ok := provider.(dpiControlProvider)
	if !ok {
		return errors.New("DPI control not supported")
	}
	return ctrl.SetEnabled(true)
}

// DetailedStats returns provider-specific rich stats when available.
func (p *DPIProvider) DetailedStats() (interface{}, bool) {
	if p == nil {
		return nil, false
	}
	p.mu.RLock()
	provider := p.provider
	p.mu.RUnlock()
	if provider == nil {
		return nil, false
	}
	if detailed, ok := provider.(dpiDetailedStatsProvider); ok {
		return detailed.DetailedStats(), true
	}
	return nil, false
}

// SetWorkers updates DPI worker concurrency when provider supports it.
func (p *DPIProvider) SetWorkers(workers int) error {
	if p == nil {
		return errors.New("DPI provider unavailable")
	}
	p.mu.RLock()
	provider := p.provider
	p.mu.RUnlock()
	if provider == nil {
		return errors.New("DPI provider unavailable")
	}
	ctrl, ok := provider.(dpiWorkersProvider)
	if !ok {
		return errors.New("DPI worker control not supported")
	}
	return ctrl.SetWorkers(workers)
}

// NewRouter creates the HTTP mux with all API routes and static file serving.
func NewRouter(fw *firewall.Engine, tl *logger.TrafficLogger, ti *threatintel.Service, an *analytics.Service, dpi *DPIProvider, geo *geoip.Service, proxy maliciousDomainProxy, aiService *ai.OpenRouterService) http.Handler {
	mux := http.NewServeMux()

	h := &handlers{fw: fw, logger: tl, threat: ti, analytics: an, dpi: dpi, geo: geo, proxy: proxy, aiService: aiService}
	h.anomalyRiskHistory = make([]models.TrafficAnomalyRiskPoint, 0, 256)
	h.anomalyDetectorHistory = make(map[string][]models.TrafficAnomalyDetectorPoint)

	// REST API v1 endpoints
	mux.HandleFunc("/api/v1/rules", h.handleRules)
	mux.HandleFunc("/api/v1/rules/analyze", h.handleRulesAnalyze)
	mux.HandleFunc("/api/v1/rules/validate", h.handleRuleValidate)
	mux.HandleFunc("/api/v1/rules/", h.handleRuleByID)  // /api/v1/rules/{id}
	mux.HandleFunc("/api/v1/stats", h.handleStats)
	mux.HandleFunc("/api/v1/sysinfo", h.handleSysInfo)
	mux.HandleFunc("/api/v1/connections", h.handleConnections)
	mux.HandleFunc("/api/v1/logs", h.handleLogs)
	mux.HandleFunc("/api/v1/logs/stream", h.handleLogStream)
	mux.HandleFunc("/api/v1/events", h.handleEvents)
	mux.HandleFunc("/api/v1/events/stream", h.handleEventStream)
	mux.HandleFunc("/api/v1/threat/apikey", h.handleAPIKey)
	mux.HandleFunc("/api/v1/threat/check/", h.handleThreatCheck)
	mux.HandleFunc("/api/v1/threat/cache", h.handleThreatCache)
	mux.HandleFunc("/api/v1/analytics", h.handleAnalytics)
	mux.HandleFunc("/api/v1/analytics/stream", h.handleAnalyticsStream)
	mux.HandleFunc("/api/v1/blocked", h.handleBlockedIPs)
	mux.HandleFunc("/api/v1/blocked/", h.handleBlockedIPByAddr)
	mux.HandleFunc("/api/v1/websites", h.handleWebsiteBlocks)
	mux.HandleFunc("/api/v1/websites/", h.handleWebsiteBlockByDomain)
	mux.HandleFunc("/api/v1/firewall/engine", h.handleFirewallEngine)
	mux.HandleFunc("/api/v1/firewall/logs", h.handleFirewallLogs)
	mux.HandleFunc("/api/v1/traffic/visibility", h.handleTrafficVisibility)
	mux.HandleFunc("/api/v1/traffic/anomalies", h.handleTrafficAnomalies)
	mux.HandleFunc("/api/v1/dns/stats", h.handleDNSStats)
	mux.HandleFunc("/api/v1/dns/cache", h.handleDNSCache)
	mux.HandleFunc("/api/v1/dns/refresh", h.handleDNSRefresh)
	mux.HandleFunc("/api/v1/dpi/status", h.handleDPIStatus)
	mux.HandleFunc("/api/v1/dpi/stats", h.handleDPIStats)
	mux.HandleFunc("/api/v1/dpi/control", h.handleDPIControl)
	mux.HandleFunc("/api/v1/dpi/workers", h.handleDPIWorkers)
	mux.HandleFunc("/api/v1/geo/attacks", h.handleGeoAttacks)
	mux.HandleFunc("/api/v1/geo/me", h.handleGeoMe)
	mux.HandleFunc("/api/v1/geo/stream", h.handleGeoStream)
	mux.HandleFunc("/api/v1/proxy/malicious-domains", h.handleProxyMaliciousDomains)
	mux.HandleFunc("/api/v1/proxy/malicious-domains/reload", h.handleProxyMaliciousDomainsReload)
	mux.HandleFunc("/api/v1/proxy/blocked-events", h.handleProxyBlockedEvents)
	mux.HandleFunc("/api/v1/ai/apikey", h.handleAIApiKey)
	mux.HandleFunc("/api/v1/ai/status", h.handleAIStatus)
	mux.HandleFunc("/api/v1/ai/explain", h.handleAIExplain)
	mux.HandleFunc("/api/v1/ai/suggest-rule", h.handleAISuggestRule)
	mux.HandleFunc("/web", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/web/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})

	// Serve web UI with a resilient resolver so the daemon can run from any working directory.
	webDir := resolveWebDir()
	if webDir == "" {
		log.Printf("Web UI assets not found. Set KALIWALL_WEB_DIR or place a 'web' folder near the executable")
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("KaliWall web assets not found. Set KALIWALL_WEB_DIR to the web directory."))
		})
		return withRecovery(mux)
	}

	log.Printf("Web UI assets: %s", webDir)
	fileServer := http.FileServer(http.Dir(webDir))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(webDir, "index.html"))
			return
		}

		cleanedURLPath := path.Clean("/" + r.URL.Path)
		requested := strings.TrimPrefix(cleanedURLPath, "/")
		if requested == "" {
			http.ServeFile(w, r, filepath.Join(webDir, "index.html"))
			return
		}

		if stat, err := os.Stat(filepath.Join(webDir, filepath.FromSlash(requested))); err == nil {
			if stat.IsDir() {
				index := filepath.Join(webDir, filepath.FromSlash(requested), "index.html")
				if _, err := os.Stat(index); err == nil {
					fileServer.ServeHTTP(w, r)
					return
				}
			} else {
				fileServer.ServeHTTP(w, r)
				return
			}
		}

		// Fallback to index.html for client-side routes without a file extension.
		if !strings.Contains(path.Base(cleanedURLPath), ".") {
			http.ServeFile(w, r, filepath.Join(webDir, "index.html"))
			return
		}

		fileServer.ServeHTTP(w, r)
	})

	return withRecovery(mux)
}

func resolveWebDir() string {
	candidates := make([]string, 0, 8)

	if envPath := strings.TrimSpace(os.Getenv("KALIWALL_WEB_DIR")); envPath != "" {
		candidates = append(candidates, envPath)
	}

	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "web"))
	}

	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates,
			filepath.Join(exeDir, "web"),
			filepath.Join(exeDir, "..", "web"),
			filepath.Join(exeDir, "..", "share", "kaliwall", "web"),
		)
	}

	candidates = append(candidates,
		"/usr/local/share/kaliwall/web",
		"/usr/share/kaliwall/web",
	)

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		abs, err := filepath.Abs(candidate)
		if err != nil {
			abs = candidate
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}

		indexPath := filepath.Join(abs, "index.html")
		if info, err := os.Stat(indexPath); err == nil && !info.IsDir() {
			return abs
		}
	}

	return ""
}

func (h *handlers) handleDPIControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if h.dpi == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "DPI pipeline unavailable"})
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "enabled is required"})
		return
	}
	if !*body.Enabled {
		if err := h.dpi.SetEnabled(true); err != nil {
			respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: err.Error()})
			return
		}
		status, _ := h.dpi.Status()
		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "DPI always-on mode active", Data: status})
		return
	}
	if err := h.dpi.SetEnabled(true); err != nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: err.Error()})
		return
	}
	status, _ := h.dpi.Status()
	respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "DPI enabled", Data: status})
}

func (h *handlers) handleDPIStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	status, ok := h.dpi.Status()
	if !ok {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{
			Success: false,
			Message: "DPI pipeline unavailable",
			Data:    pipeline.Status{Enabled: false, Running: false},
		})
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: status})
}

func (h *handlers) handleDPIStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if h.dpi == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "DPI pipeline unavailable"})
		return
	}
	if stats, ok := h.dpi.DetailedStats(); ok {
		respond(w, http.StatusOK, models.APIResponse{Success: true, Data: stats})
		return
	}
	status, ok := h.dpi.Status()
	if !ok {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "DPI pipeline unavailable"})
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: status})
}

func (h *handlers) handleDPIWorkers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if h.dpi == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "DPI pipeline unavailable"})
		return
	}
	var body struct {
		Workers int `json:"workers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "workers is required"})
		return
	}
	if body.Workers < 1 || body.Workers > 256 {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "workers must be between 1 and 256"})
		return
	}
	if err := h.dpi.SetWorkers(body.Workers); err != nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: err.Error()})
		return
	}
	status, _ := h.dpi.Status()
	respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "DPI workers updated", Data: status})
}

// ---------- Firewall Engine & Visibility ----------

func (h *handlers) handleFirewallEngine(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		respond(w, http.StatusOK, models.APIResponse{Success: true, Data: h.fw.EngineInfo()})
	case http.MethodPost:
		var body struct {
			Engine string `json:"engine"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "invalid JSON"})
			return
		}
		if err := h.fw.SwitchEngine(body.Engine); err != nil {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: err.Error()})
			return
		}
		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "Firewall engine switched", Data: h.fw.EngineInfo()})
	default:
		methodNotAllowed(w)
	}
}

func (h *handlers) handleFirewallLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
			limit = v
		}
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: h.fw.FirewallLogs(limit)})
}

func (h *handlers) handleTrafficVisibility(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := 1000
	if q := r.URL.Query().Get("limit"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
			limit = v
		}
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: h.fw.TrafficVisibility(limit)})
}

func (h *handlers) handleTrafficAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	limit := 5000
	if q := r.URL.Query().Get("limit"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 10000 {
			limit = v
		}
	}

	trendLimit := 180
	if q := r.URL.Query().Get("trend_limit"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v >= 10 && v <= 1440 {
			trendLimit = v
		}
	}

	windowMinutes := 15
	if q := r.URL.Query().Get("window_minutes"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v >= 1 && v <= 120 {
			windowMinutes = v
		}
	}
	if q := r.URL.Query().Get("window_min"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v >= 1 && v <= 120 {
			windowMinutes = v
		}
	}

	snapshot := h.buildTrafficAnomalySnapshot(limit, windowMinutes)
	h.enforceAnomalyBlocking(snapshot)
	h.recordAnomalySnapshot(snapshot)
	snapshot = h.withAnomalyTrendHistory(snapshot, trendLimit)

	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: snapshot})
}

func (h *handlers) buildTrafficAnomalySnapshot(limit int, windowMinutes int) models.TrafficAnomalySnapshot {
	if limit <= 0 || limit > 10000 {
		limit = 5000
	}
	if windowMinutes <= 0 || windowMinutes > 120 {
		windowMinutes = 15
	}

	minHistorySamples := 60
	minHistoryDurationMinutes := windowMinutes * 2
	if minHistoryDurationMinutes < 15 {
		minHistoryDurationMinutes = 15
	}
	minHistoryFastTrackSamples := minHistorySamples + 6

	now := time.Now().UTC()
	snapshot := models.TrafficAnomalySnapshot{
		GeneratedAt:    now,
		WindowMinutes:  windowMinutes,
		SampleSize:     0,
		HistoryReady:   false,
		HistorySamples: 0,
		HistoryRequiredSamples: minHistorySamples,
		RiskScore:      0,
		Status:         "normal",
		TotalAnomalies: 0,
		Anomalies:      []models.TrafficAnomaly{},
	}

	if h == nil || h.logger == nil || h.fw == nil {
		return snapshot
	}

	windowDuration := time.Duration(windowMinutes) * time.Minute
	windowStart := now.Add(-windowDuration)
	prevWindowStart := windowStart.Add(-windowDuration)

	entries := h.logger.RecentEntries(limit)
	conns := h.fw.ActiveConnections()
	if len(entries) == 0 {
		snapshot.SampleSize = 0
		snapshot.HistorySamples = 0
		snapshot.Status = "learning"
		snapshot.LearningMessage = fmt.Sprintf("UEBA baseline learning: 0/%d samples, 0/%d min coverage", minHistorySamples, minHistoryDurationMinutes)
		return snapshot
	}

	firstSeen := entries[0].Timestamp
	lastSeen := entries[0].Timestamp
	historyMinuteBuckets := make(map[int64]struct{}, len(entries))
	for _, entry := range entries {
		ts := entry.Timestamp
		if ts.Before(firstSeen) {
			firstSeen = ts
		}
		if ts.After(lastSeen) {
			lastSeen = ts
		}
		historyMinuteBuckets[ts.Unix()/60] = struct{}{}
	}

	historyCoverageMinutes := int(math.Ceil(lastSeen.Sub(firstSeen).Minutes()))
	if historyCoverageMinutes < len(historyMinuteBuckets) {
		historyCoverageMinutes = len(historyMinuteBuckets)
	}
	if historyCoverageMinutes < 1 {
		historyCoverageMinutes = 1
	}

	snapshot.SampleSize = len(entries)
	snapshot.HistorySamples = len(entries)
	historyReadyBySamples := len(entries) >= minHistorySamples
	historyReadyByTime := historyCoverageMinutes >= minHistoryDurationMinutes
	historyReadyFastTrack := len(entries) >= minHistoryFastTrackSamples
	snapshot.HistoryReady = historyReadyBySamples && (historyReadyByTime || historyReadyFastTrack)
	if !snapshot.HistoryReady {
		snapshot.Status = "learning"
		snapshot.LearningMessage = fmt.Sprintf(
			"UEBA baseline learning: %d/%d samples, %d/%d min coverage before anomaly marking",
			len(entries), minHistorySamples, historyCoverageMinutes, minHistoryDurationMinutes,
		)
	}
	if !snapshot.HistoryReady {
		return snapshot
	}

	minuteTotals := make(map[int64]int)
	windowMinuteCounts := make(map[int64]int)
	windowTotal := 0
	windowBlocked := 0
	windowSuspicious := 0
	prevTotal := 0
	prevBlocked := 0
	prevSuspicious := 0
	sourceWindow := make(map[string]int)
	prevSourceWindow := make(map[string]int)
	windowProtocolCounts := make(map[string]int)
	windowProtocolRiskCounts := make(map[string]int)
	prevProtocolCounts := make(map[string]int)
	sourcePorts := make(map[string]map[string]struct{})
	sourceTargets := make(map[string]map[string]struct{})
	sourceTotal := make(map[string]int)
	sourceBlocked := make(map[string]int)
	sourceSuspicious := make(map[string]int)
	destinationWindow := make(map[string]int)
	destinationRiskWindow := make(map[string]int)

	historicalSourceTotals := make(map[string]int)
	historicalSourceRisk := make(map[string]int)
	historicalProtocolCounts := make(map[string]int)
	historicalHourTotals := make(map[int]int)
	historicalTotal := 0
	windowHourCounts := make(map[int]int)

	for _, entry := range entries {
		ts := entry.Timestamp
		minuteTotals[ts.Unix()/60]++

		isBlocked := isBlockingAction(entry.Action)
		isSuspicious := isSuspiciousDetail(entry.Detail)
		proto := normalizeTrafficProtocol(entry.Protocol)
		src := normalizeTrafficIP(entry.SrcIP)
		dst := normalizeTrafficIP(entry.DstIP)

		if ts.Before(windowStart) {
			historicalTotal++
			historicalHourTotals[ts.UTC().Hour()]++
			if proto != "" {
				historicalProtocolCounts[proto]++
			}
			if src != "" {
				historicalSourceTotals[src]++
				if isBlocked || isSuspicious {
					historicalSourceRisk[src]++
				}
			}
		}

		if ts.Before(prevWindowStart) {
			continue
		}

		if ts.Before(windowStart) {
			prevTotal++
			if isBlocked {
				prevBlocked++
			}
			if isSuspicious {
				prevSuspicious++
			}
			if proto != "" {
				prevProtocolCounts[proto]++
			}
			if src != "" {
				prevSourceWindow[src]++
			}
			continue
		}

		windowTotal++
		windowMinuteCounts[ts.Unix()/60]++
		windowHourCounts[ts.UTC().Hour()]++
		if isBlocked {
			windowBlocked++
		}
		if isSuspicious {
			windowSuspicious++
		}
		if proto != "" {
			windowProtocolCounts[proto]++
			if isBlocked || isSuspicious {
				windowProtocolRiskCounts[proto]++
			}
		}

		if src != "" {
			sourceWindow[src]++
			sourceTotal[src]++
			if isBlocked {
				sourceBlocked[src]++
			}
			if isSuspicious {
				sourceSuspicious[src]++
			}
			if dst != "" {
				if _, ok := sourceTargets[src]; !ok {
					sourceTargets[src] = make(map[string]struct{})
				}
				sourceTargets[src][dst] = struct{}{}
			}
			if dstPort := parseDestinationPortFromDetail(entry.Detail); dstPort != "" {
				if _, ok := sourcePorts[src]; !ok {
					sourcePorts[src] = make(map[string]struct{})
				}
				sourcePorts[src][dstPort] = struct{}{}
			}
		}

		if dst != "" {
			destinationWindow[dst]++
			if isBlocked || isSuspicious {
				destinationRiskWindow[dst]++
			}
		}
	}

	type fanoutStat struct {
		IP    string
		Ports int
	}
	fanout := make(map[string]map[string]struct{})
	for _, c := range conns {
		remote := strings.TrimSpace(c.RemoteIP)
		localPort := strings.TrimSpace(c.LocalPort)
		if remote == "" || remote == "-" || remote == "0.0.0.0" || remote == "::" || remote == "127.0.0.1" || remote == "::1" || localPort == "" {
			continue
		}
		if _, ok := fanout[remote]; !ok {
			fanout[remote] = make(map[string]struct{})
		}
		fanout[remote][localPort] = struct{}{}
	}

	maxFanout := fanoutStat{}
	for ip, ports := range fanout {
		if len(ports) > maxFanout.Ports {
			maxFanout = fanoutStat{IP: ip, Ports: len(ports)}
		}
	}

	currentBucket := now.Unix() / 60
	currentMinuteCount := minuteTotals[currentBucket]
	historyCounts := make([]int, 0, len(minuteTotals))
	for bucket, count := range minuteTotals {
		if bucket == currentBucket || count <= 0 {
			continue
		}
		historyCounts = append(historyCounts, count)
	}
	meanPerMin, stdPerMin := intSeriesStats(historyCounts)
	zScore := 0.0
	if meanPerMin > 0 {
		if stdPerMin > 0 {
			zScore = (float64(currentMinuteCount) - meanPerMin) / stdPerMin
		} else {
			zScore = (float64(currentMinuteCount) - meanPerMin) / math.Max(1, meanPerMin*0.4)
		}
		if zScore < 0 {
			zScore = 0
		}
	}
	burstRatio := 0.0
	if meanPerMin > 0 {
		burstRatio = float64(currentMinuteCount) / (meanPerMin + 1)
	} else if currentMinuteCount > 0 {
		burstRatio = float64(currentMinuteCount)
	}

	anomalies := make([]models.TrafficAnomaly, 0, 14)
	idx := 1
	appendAnomaly := func(kind string, severity string, score int, title string, summary string, sampleCount int, baseline float64, current float64, evidence map[string]interface{}) {
		sev := strings.ToLower(strings.TrimSpace(severity))
		if sev != "critical" && sev != "warning" {
			sev = "warning"
		}
		anomalies = append(anomalies, models.TrafficAnomaly{
			ID:            fmt.Sprintf("%s-%d", kind, idx),
			Type:          kind,
			Severity:      sev,
			Score:         clampInt(score, 1, 100),
			Title:         title,
			Summary:       summary,
			SampleCount:   sampleCount,
			BaselineValue: baseline,
			CurrentValue:  current,
			FirstSeen:     firstSeen,
			LastSeen:      lastSeen,
			Evidence:      evidence,
		})
		idx++
	}

	if currentMinuteCount >= 12 {
		if (meanPerMin > 0 && zScore >= 1.9) || (burstRatio >= 1.8 && currentMinuteCount >= 18) {
			severity := "warning"
			if zScore >= 3.2 || burstRatio >= 2.8 {
				severity = "critical"
			}
			score := int(40 + zScore*14 + math.Max(0, burstRatio-1.0)*12)
			appendAnomaly(
				"traffic_spike",
				severity,
				score,
				"Traffic Spike Detected",
				fmt.Sprintf("Current minute traffic (%d events) exceeds baseline (%.1f/min, z=%.2f).", currentMinuteCount, meanPerMin, zScore),
				currentMinuteCount,
				meanPerMin,
				float64(currentMinuteCount),
				map[string]interface{}{
					"current_minute_events": currentMinuteCount,
					"baseline_avg_per_min": meanPerMin,
					"baseline_stddev":      stdPerMin,
					"z_score":              zScore,
					"burst_ratio":          burstRatio,
					"window_minutes":       windowMinutes,
				},
			)
		}
	}

	if prevTotal >= 16 && windowTotal >= 28 {
		growth := float64(windowTotal) / float64(prevTotal)
		if growth >= 1.35 && (windowTotal-prevTotal) >= 12 {
			severity := "warning"
			if growth >= 1.9 {
				severity = "critical"
			}
			appendAnomaly(
				"window_growth",
				severity,
				int(30+(growth-1.0)*30),
				"Traffic Window Growth",
				fmt.Sprintf("Recent %d-minute traffic volume increased %.1fx versus the previous window (%d -> %d events).", windowMinutes, growth, prevTotal, windowTotal),
				windowTotal,
				float64(prevTotal),
				float64(windowTotal),
				map[string]interface{}{
					"window_total":        windowTotal,
					"previous_window_total": prevTotal,
					"growth_factor":       growth,
					"window_minutes":      windowMinutes,
				},
			)
		}
	}

	if windowTotal >= 20 {
		blockedRatio := float64(windowBlocked) / float64(windowTotal)
		if blockedRatio >= 0.34 && windowBlocked >= 8 {
			severity := "warning"
			if blockedRatio >= 0.52 {
				severity = "critical"
			}
			appendAnomaly(
				"blocked_ratio_spike",
				severity,
				int(32 + blockedRatio*95 + float64(windowBlocked)/4),
				"Blocked Ratio Surge",
				fmt.Sprintf("%d of %d recent events were blocked/rejected (%.1f%%).", windowBlocked, windowTotal, blockedRatio*100),
				windowTotal,
				0.35,
				blockedRatio,
				map[string]interface{}{
					"window_blocked": windowBlocked,
					"window_total":   windowTotal,
					"window_minutes": windowMinutes,
				},
			)
		}
	}

	if prevTotal >= 16 && windowTotal >= 20 {
		prevBlockedRatio := float64(prevBlocked) / float64(prevTotal)
		blockedRatio := float64(windowBlocked) / float64(windowTotal)
		delta := blockedRatio - prevBlockedRatio
		if blockedRatio >= 0.30 && delta >= 0.10 && windowBlocked >= 7 {
			severity := "warning"
			if blockedRatio >= 0.45 || delta >= 0.18 {
				severity = "critical"
			}
			appendAnomaly(
				"blocked_ratio_escalation",
				severity,
				int(34 + blockedRatio*72 + delta*120),
				"Blocked Ratio Escalation",
				fmt.Sprintf("Blocked ratio rose from %.1f%% to %.1f%% across consecutive %d-minute windows.", prevBlockedRatio*100, blockedRatio*100, windowMinutes),
				windowTotal,
				prevBlockedRatio,
				blockedRatio,
				map[string]interface{}{
					"previous_blocked_ratio": prevBlockedRatio,
					"current_blocked_ratio":  blockedRatio,
					"ratio_delta":            delta,
					"window_minutes":         windowMinutes,
				},
			)
		}
	}

	if windowTotal >= 26 && len(sourceWindow) > 0 {
		topSource := ""
		topHits := 0
		for src, hits := range sourceWindow {
			if hits > topHits {
				topSource = src
				topHits = hits
			}
		}
		if topHits >= 10 {
			share := float64(topHits) / float64(windowTotal)
			prevShare := 0.0
			if prevTotal > 0 {
				prevShare = float64(prevSourceWindow[topSource]) / float64(prevTotal)
			}
			if share >= 0.30 && (prevTotal < 20 || (share-prevShare) >= 0.12 || share >= 0.42) {
				severity := "warning"
				if share >= 0.52 {
					severity = "critical"
				}
				appendAnomaly(
					"source_concentration",
					severity,
					int(30+share*96+float64(topHits)/1.8),
					"Single Source Concentration",
					fmt.Sprintf("Source %s accounts for %.1f%% of recent traffic (%d/%d events).", topSource, share*100, topHits, windowTotal),
					topHits,
					prevShare,
					share,
					map[string]interface{}{
						"source_ip":      topSource,
						"source_hits":    topHits,
						"window_total":   windowTotal,
						"previous_share": prevShare,
						"window_minutes": windowMinutes,
					},
				)
			}
		}
	}

	if windowTotal >= 18 && windowSuspicious >= 5 {
		suspiciousRatio := float64(windowSuspicious) / float64(windowTotal)
		if suspiciousRatio >= 0.16 {
			severity := "warning"
			if suspiciousRatio >= 0.26 {
				severity = "critical"
			}
			appendAnomaly(
				"suspicious_payload_burst",
				severity,
				int(34 + suspiciousRatio*92),
				"Suspicious Payload Burst",
				fmt.Sprintf("%d events in the analysis window include suspicious markers (%.1f%%).", windowSuspicious, suspiciousRatio*100),
				windowSuspicious,
				0.15,
				suspiciousRatio,
				map[string]interface{}{
					"suspicious_events": windowSuspicious,
					"window_total":      windowTotal,
					"window_minutes":    windowMinutes,
				},
			)
		}
	}

	if windowTotal >= 20 {
		startBucket := windowStart.Unix() / 60
		endBucket := currentBucket
		if endBucket < startBucket {
			endBucket = startBucket
		}
		windowSeries := make([]int, 0, int(endBucket-startBucket)+1)
		peakMinute := 0
		zeroMinutes := 0
		for bucket := startBucket; bucket <= endBucket; bucket++ {
			count := windowMinuteCounts[bucket]
			windowSeries = append(windowSeries, count)
			if count == 0 {
				zeroMinutes++
			}
			if count > peakMinute {
				peakMinute = count
			}
		}

		if len(windowSeries) >= 4 {
			seriesMean, seriesStd := intSeriesStats(windowSeries)
			if seriesMean > 0 {
				cv := seriesStd / seriesMean
				medianMinute := math.Max(1, medianInt(windowSeries))
				peakToMedian := float64(peakMinute) / medianMinute
				quietRatio := safeRatio(float64(zeroMinutes), float64(len(windowSeries)))
				if cv >= 1.05 && peakToMedian >= 2.5 && quietRatio >= 0.30 {
					severity := "warning"
					if cv >= 1.8 || peakToMedian >= 4.5 || quietRatio >= 0.65 {
						severity = "critical"
					}
					appendAnomaly(
						"minute_volatility_spike",
						severity,
						int(28+cv*24+peakToMedian*7+quietRatio*28),
						"Burst Volatility Spike",
						fmt.Sprintf("Per-minute traffic volatility spiked (CV %.2f) with peak minute %d events and %.0f%% quiet minutes.", cv, peakMinute, quietRatio*100),
						windowTotal,
						seriesMean,
						float64(peakMinute),
						map[string]interface{}{
							"window_minutes":    windowMinutes,
							"peak_minute_events": peakMinute,
							"mean_per_minute":   seriesMean,
							"stddev_per_minute": seriesStd,
							"coefficient_variation": cv,
							"peak_to_median":    peakToMedian,
							"quiet_minute_ratio": quietRatio,
						},
					)
				}
			}
		}
	}

	if windowTotal >= 24 && len(windowProtocolCounts) > 0 {
		globalRiskHits := windowBlocked
		if windowSuspicious > globalRiskHits {
			globalRiskHits = windowSuspicious
		}
		globalRiskRatio := safeRatio(float64(globalRiskHits), float64(windowTotal))
		type protocolRiskCandidate struct {
			Protocol      string
			Events        int
			RiskHits      int
			Share         float64
			RiskRatio     float64
			GlobalRisk    float64
		}
		best := protocolRiskCandidate{}
		bestWeight := 0.0
		for proto, count := range windowProtocolCounts {
			if count < 8 {
				continue
			}
			riskHits := windowProtocolRiskCounts[proto]
			if riskHits < 5 {
				continue
			}
			share := safeRatio(float64(count), float64(windowTotal))
			riskRatio := safeRatio(float64(riskHits), float64(count))
			if share < 0.18 || riskRatio < 0.55 {
				continue
			}
			if globalRiskRatio > 0 && riskRatio < globalRiskRatio+0.20 {
				continue
			}
			weight := riskRatio*share*100 + float64(riskHits)
			if weight > bestWeight {
				bestWeight = weight
				best = protocolRiskCandidate{
					Protocol:   proto,
					Events:     count,
					RiskHits:   riskHits,
					Share:      share,
					RiskRatio:  riskRatio,
					GlobalRisk: globalRiskRatio,
				}
			}
		}
		if best.Protocol != "" {
			severity := "warning"
			if best.RiskRatio >= 0.80 || best.Share >= 0.45 {
				severity = "critical"
			}
			appendAnomaly(
				"protocol_risk_skew",
				severity,
				int(32+best.RiskRatio*78+best.Share*34+safeRatio(float64(best.RiskHits), 3)),
				"Protocol Risk Skew",
				fmt.Sprintf("%s accounts for %.1f%% of traffic but %.1f%% of its events are blocked/suspicious (%d/%d).", best.Protocol, best.Share*100, best.RiskRatio*100, best.RiskHits, best.Events),
				best.Events,
				best.GlobalRisk,
				best.RiskRatio,
				map[string]interface{}{
					"protocol":              best.Protocol,
					"protocol_events":       best.Events,
					"protocol_share":        best.Share,
					"protocol_risk_hits":    best.RiskHits,
					"protocol_risk_ratio":   best.RiskRatio,
					"global_risk_ratio":     best.GlobalRisk,
					"window_minutes":        windowMinutes,
				},
			)
		}
	}

	if windowTotal >= 40 && len(windowProtocolCounts) >= 2 {
		baselineProtocolCounts := historicalProtocolCounts
		baselineProtocolTotal := sumIntMap(baselineProtocolCounts)
		if baselineProtocolTotal < 24 && prevTotal >= 20 {
			baselineProtocolCounts = prevProtocolCounts
			baselineProtocolTotal = sumIntMap(baselineProtocolCounts)
		}
		if baselineProtocolTotal >= 20 {
			jsd, shiftedProto, currentShare, baselineShare := protocolDistributionDrift(windowProtocolCounts, baselineProtocolCounts)
			delta := currentShare - baselineShare
			if shiftedProto != "" && jsd >= 0.14 && currentShare >= 0.24 && delta >= 0.08 {
				severity := "warning"
				if jsd >= 0.24 || currentShare >= 0.42 || delta >= 0.18 {
					severity = "critical"
				}
				appendAnomaly(
					"protocol_distribution_drift",
					severity,
					int(30+jsd*190+delta*120+currentShare*38),
					"Protocol Distribution Drift",
					fmt.Sprintf("Protocol distribution diverged from baseline (JSD %.2f); %s rose from %.1f%% to %.1f%% share.", jsd, shiftedProto, baselineShare*100, currentShare*100),
					windowTotal,
					baselineShare,
					currentShare,
					map[string]interface{}{
						"protocol":                shiftedProto,
						"jsd":                     jsd,
						"current_share":           currentShare,
						"baseline_share":          baselineShare,
						"share_delta":             delta,
						"window_minutes":          windowMinutes,
						"baseline_protocol_events": baselineProtocolTotal,
					},
				)
			}

			type rareProtocolCandidate struct {
				Protocol      string
				CurrentShare  float64
				BaselineShare float64
				Events        int
			}
			bestRare := rareProtocolCandidate{}
			bestRareWeight := 0.0
			for proto, count := range windowProtocolCounts {
				if count < 8 {
					continue
				}
				currentShare := safeRatio(float64(count), float64(windowTotal))
				baselineShare := safeRatio(float64(baselineProtocolCounts[proto]), float64(baselineProtocolTotal))
				if currentShare < 0.12 || baselineShare > 0.10 {
					continue
				}
				if baselineShare > 0 && currentShare < baselineShare*3.5+0.05 {
					continue
				}
				weight := (currentShare - baselineShare) * 100
				if weight > bestRareWeight {
					bestRareWeight = weight
					bestRare = rareProtocolCandidate{
						Protocol:      proto,
						CurrentShare:  currentShare,
						BaselineShare: baselineShare,
						Events:        count,
					}
				}
			}
			if bestRare.Protocol != "" {
				severity := "warning"
				if bestRare.CurrentShare >= 0.30 || bestRare.BaselineShare <= 0.01 {
					severity = "critical"
				}
				appendAnomaly(
					"rare_protocol_emergence",
					severity,
					int(28+bestRare.CurrentShare*96+(bestRare.CurrentShare-bestRare.BaselineShare)*92),
					"Rare Protocol Emergence",
					fmt.Sprintf("Protocol %s surged to %.1f%% share (%d events) from baseline %.1f%%.", bestRare.Protocol, bestRare.CurrentShare*100, bestRare.Events, bestRare.BaselineShare*100),
					bestRare.Events,
					bestRare.BaselineShare,
					bestRare.CurrentShare,
					map[string]interface{}{
						"protocol":              bestRare.Protocol,
						"protocol_events":       bestRare.Events,
						"current_share":         bestRare.CurrentShare,
						"baseline_share":        bestRare.BaselineShare,
						"window_minutes":        windowMinutes,
						"baseline_protocol_total": baselineProtocolTotal,
					},
				)
			}
		}
	}

	if windowTotal >= 50 && len(windowProtocolCounts) > 0 {
		topProto := ""
		topCount := 0
		for proto, count := range windowProtocolCounts {
			if count > topCount {
				topProto = proto
				topCount = count
			}
		}
		if topProto != "" {
			share := float64(topCount) / float64(windowTotal)
			prevShare := 0.0
			if prevTotal > 0 {
				prevShare = float64(prevProtocolCounts[topProto]) / float64(prevTotal)
			}
			entropy, normalizedEntropy := protocolEntropy(windowProtocolCounts)
			if share >= 0.66 && (prevTotal < 30 || prevShare <= 0.48 || (share-prevShare) >= 0.14 || normalizedEntropy <= 0.54) {
				severity := "warning"
				if share >= 0.82 || (share-prevShare) >= 0.30 {
					severity = "critical"
				}
				appendAnomaly(
					"protocol_dominance",
					severity,
					int(34 + share*70 + (share-prevShare)*48 + (1-normalizedEntropy)*20),
					"Protocol Dominance Shift",
					fmt.Sprintf("%s now represents %.1f%% of recent traffic (%d/%d), indicating a potential flood or focused abuse pattern.", topProto, share*100, topCount, windowTotal),
					topCount,
					prevShare,
					share,
					map[string]interface{}{
						"protocol":         topProto,
						"current_share":    share,
						"previous_share":   prevShare,
						"current_events":   topCount,
						"entropy":          entropy,
						"normalized_entropy": normalizedEntropy,
						"window_minutes":   windowMinutes,
					},
				)
			}

			if len(windowProtocolCounts) >= 2 && normalizedEntropy <= 0.50 && share >= 0.68 {
				severity := "warning"
				if normalizedEntropy <= 0.34 || share >= 0.82 {
					severity = "critical"
				}
				appendAnomaly(
					"protocol_entropy_collapse",
					severity,
					int(30 + (1-normalizedEntropy)*88 + share*24),
					"Protocol Entropy Collapse",
					fmt.Sprintf("Protocol mix diversity collapsed (entropy %.2f, normalized %.2f) with %s at %.1f%% share.", entropy, normalizedEntropy, topProto, share*100),
					topCount,
					1,
					normalizedEntropy,
					map[string]interface{}{
						"protocol":            topProto,
						"dominant_share":      share,
						"entropy":             entropy,
						"normalized_entropy":  normalizedEntropy,
						"window_minutes":      windowMinutes,
					},
				)
			}
		}
	}

	type scanCandidate struct {
		SourceIP      string
		UniquePorts   int
		UniqueTargets int
		Events        int
	}
	bestScan := scanCandidate{}
	bestScanWeight := 0
	for src, portsSet := range sourcePorts {
		portCount := len(portsSet)
		targetCount := len(sourceTargets[src])
		events := sourceTotal[src]
		if events < 10 || portCount < 6 {
			continue
		}
		if targetCount < 4 && portCount < 9 {
			continue
		}
		weight := portCount*3 + targetCount*2 + events/2 + sourceBlocked[src]
		if weight > bestScanWeight {
			bestScanWeight = weight
			bestScan = scanCandidate{SourceIP: src, UniquePorts: portCount, UniqueTargets: targetCount, Events: events}
		}
	}
	if bestScan.SourceIP != "" {
		severity := "warning"
		if bestScan.UniquePorts >= 18 || bestScan.UniqueTargets >= 12 {
			severity = "critical"
		}
		appendAnomaly(
			"source_port_scan",
			severity,
			int(34 + float64(bestScan.UniquePorts)*2.4 + float64(bestScan.UniqueTargets)*1.8),
			"Distributed Port Scan Behavior",
			fmt.Sprintf("Source %s touched %d destination ports across %d targets within %d observed events.", bestScan.SourceIP, bestScan.UniquePorts, bestScan.UniqueTargets, bestScan.Events),
			bestScan.Events,
			8,
			float64(bestScan.UniquePorts),
			map[string]interface{}{
				"source_ip":            bestScan.SourceIP,
				"unique_dst_ports":     bestScan.UniquePorts,
				"unique_dst_targets":   bestScan.UniqueTargets,
				"source_event_count":   bestScan.Events,
				"window_minutes":       windowMinutes,
			},
		)
	}

	type sweepCandidate struct {
		SourceIP       string
		UniqueTargets  int
		Events         int
		RiskHits       int
		TargetPerEvent float64
	}
	bestSweep := sweepCandidate{}
	bestSweepWeight := 0
	for src, targetsSet := range sourceTargets {
		targetCount := len(targetsSet)
		events := sourceTotal[src]
		riskHits := sourceBlocked[src] + sourceSuspicious[src]
		if events < 12 || targetCount < 8 {
			continue
		}
		targetRatio := safeRatio(float64(targetCount), float64(events))
		if targetRatio < 0.26 && targetCount < 10 {
			continue
		}
		weight := targetCount*3 + riskHits*2 + events/2
		if weight > bestSweepWeight {
			bestSweepWeight = weight
			bestSweep = sweepCandidate{SourceIP: src, UniqueTargets: targetCount, Events: events, RiskHits: riskHits, TargetPerEvent: targetRatio}
		}
	}
	if bestSweep.SourceIP != "" {
		severity := "warning"
		if bestSweep.UniqueTargets >= 22 || bestSweep.TargetPerEvent >= 0.75 {
			severity = "critical"
		}
		appendAnomaly(
			"source_target_sweep",
			severity,
			int(32 + float64(bestSweep.UniqueTargets)*2.1 + float64(bestSweep.RiskHits)*1.4),
			"Source Target Sweep",
			fmt.Sprintf("Source %s contacted %d unique destinations across %d events (risk hits: %d).", bestSweep.SourceIP, bestSweep.UniqueTargets, bestSweep.Events, bestSweep.RiskHits),
			bestSweep.Events,
			0.25,
			bestSweep.TargetPerEvent,
			map[string]interface{}{
				"source_ip":            bestSweep.SourceIP,
				"unique_destinations":  bestSweep.UniqueTargets,
				"source_event_count":   bestSweep.Events,
				"risk_hits":            bestSweep.RiskHits,
				"target_per_event":     bestSweep.TargetPerEvent,
				"window_minutes":       windowMinutes,
			},
		)
	}

	type offenderCandidate struct {
		SourceIP    string
		Total       int
		Blocked     int
		Suspicious  int
	}
	bestOffender := offenderCandidate{}
	bestOffenderWeight := 0
	for src, total := range sourceTotal {
		if total < 10 {
			continue
		}
		blockedHits := sourceBlocked[src]
		suspiciousHits := sourceSuspicious[src]
		if blockedHits < 6 {
			continue
		}
		riskHits := blockedHits + suspiciousHits
		ratio := float64(riskHits) / float64(total)
		if ratio < 0.50 {
			continue
		}
		weight := blockedHits*3 + suspiciousHits*2 + total/2
		if weight > bestOffenderWeight {
			bestOffenderWeight = weight
			bestOffender = offenderCandidate{SourceIP: src, Total: total, Blocked: blockedHits, Suspicious: suspiciousHits}
		}
	}
	if bestOffender.SourceIP != "" {
		riskRatio := float64(bestOffender.Blocked+bestOffender.Suspicious) / float64(bestOffender.Total)
		severity := "warning"
		if riskRatio >= 0.84 || bestOffender.Blocked >= 18 {
			severity = "critical"
		}
		appendAnomaly(
			"repeat_offender",
			severity,
			int(34 + riskRatio*86 + float64(bestOffender.Blocked)*1.5),
			"Repeat Offender Source",
			fmt.Sprintf("Source %s generated %d high-risk events (%d blocked, %d suspicious) out of %d total events.", bestOffender.SourceIP, bestOffender.Blocked+bestOffender.Suspicious, bestOffender.Blocked, bestOffender.Suspicious, bestOffender.Total),
			bestOffender.Total,
			0.5,
			riskRatio,
			map[string]interface{}{
				"source_ip":          bestOffender.SourceIP,
				"total_events":       bestOffender.Total,
				"blocked_events":     bestOffender.Blocked,
				"suspicious_events":  bestOffender.Suspicious,
				"risk_ratio":         riskRatio,
				"window_minutes":     windowMinutes,
			},
		)
	}

	if windowTotal >= 16 && historicalTotal >= 40 && len(sourceWindow) > 0 {
		type entityShiftCandidate struct {
			SourceIP       string
			CurrentHits    int
			HistoricalHits int
			CurrentShare   float64
			BaselineShare  float64
			RiskHits       int
		}

		bestShift := entityShiftCandidate{}
		bestShiftWeight := 0
		bestNew := entityShiftCandidate{}
		bestNewWeight := 0

		for src, currentHits := range sourceWindow {
			historicalHits := historicalSourceTotals[src]
			currentShare := safeRatio(float64(currentHits), float64(windowTotal))
			riskHits := sourceBlocked[src] + sourceSuspicious[src]

			if historicalHits >= 5 {
				baselineShare := safeRatio(float64(historicalHits), float64(historicalTotal))
				shareDelta := currentShare - baselineShare
				if currentHits >= 5 && shareDelta >= 0.04 && currentShare >= baselineShare*2.2+0.03 {
					weight := int(shareDelta*1000) + riskHits*4 + currentHits
					if weight > bestShiftWeight {
						bestShiftWeight = weight
						bestShift = entityShiftCandidate{
							SourceIP:       src,
							CurrentHits:    currentHits,
							HistoricalHits: historicalHits,
							CurrentShare:   currentShare,
							BaselineShare:  baselineShare,
							RiskHits:       riskHits,
						}
					}
				}
				continue
			}

			if historicalHits == 0 && currentHits >= 8 && riskHits >= 4 {
				weight := currentHits*2 + riskHits*5
				if weight > bestNewWeight {
					bestNewWeight = weight
					bestNew = entityShiftCandidate{
						SourceIP:       src,
						CurrentHits:    currentHits,
						HistoricalHits: 0,
						CurrentShare:   currentShare,
						BaselineShare:  0,
						RiskHits:       riskHits,
					}
				}
			}
		}

		if bestShift.SourceIP != "" {
			severity := "warning"
			if bestShift.CurrentShare >= bestShift.BaselineShare*4.5 || bestShift.RiskHits >= 10 {
				severity = "critical"
			}
			appendAnomaly(
				"entity_behavior_shift",
				severity,
				int(32 + (bestShift.CurrentShare-bestShift.BaselineShare)*180 + float64(bestShift.RiskHits)*2.2),
				"UEBA Entity Behavior Shift",
				fmt.Sprintf("Entity %s shifted from %.1f%% historical share to %.1f%% in the current window (%d events).", bestShift.SourceIP, bestShift.BaselineShare*100, bestShift.CurrentShare*100, bestShift.CurrentHits),
				bestShift.CurrentHits,
				bestShift.BaselineShare,
				bestShift.CurrentShare,
				map[string]interface{}{
					"entity_ip":             bestShift.SourceIP,
					"current_events":        bestShift.CurrentHits,
					"historical_events":     bestShift.HistoricalHits,
					"current_share":         bestShift.CurrentShare,
					"historical_share":      bestShift.BaselineShare,
					"risk_hits":             bestShift.RiskHits,
					"historical_total_events": historicalTotal,
					"window_minutes":        windowMinutes,
				},
			)
		}

		if bestNew.SourceIP != "" {
			severity := "warning"
			if bestNew.RiskHits >= 10 || bestNew.CurrentHits >= 20 {
				severity = "critical"
			}
			appendAnomaly(
				"new_entity_risk_surge",
				severity,
				int(30 + bestNew.CurrentShare*120 + float64(bestNew.RiskHits)*2.4),
				"UEBA New Entity Risk Surge",
				fmt.Sprintf("Previously unseen entity %s generated %d events (%d risk hits) in the current window.", bestNew.SourceIP, bestNew.CurrentHits, bestNew.RiskHits),
				bestNew.CurrentHits,
				0,
				bestNew.CurrentShare,
				map[string]interface{}{
					"entity_ip":             bestNew.SourceIP,
					"current_events":        bestNew.CurrentHits,
					"risk_hits":             bestNew.RiskHits,
					"current_share":         bestNew.CurrentShare,
					"historical_total_events": historicalTotal,
					"window_minutes":        windowMinutes,
				},
			)
		}
	}

	if windowTotal >= 16 && historicalTotal >= 48 && len(windowHourCounts) > 0 {
		dominantHour := -1
		dominantHourHits := 0
		for hour, hits := range windowHourCounts {
			if hits > dominantHourHits {
				dominantHour = hour
				dominantHourHits = hits
			}
		}

		if dominantHour >= 0 && dominantHourHits >= 6 {
			baselineShare := safeRatio(float64(historicalHourTotals[dominantHour]), float64(historicalTotal))
			currentShare := safeRatio(float64(dominantHourHits), float64(windowTotal))
			if (baselineShare <= 0.10 && currentShare >= 0.24) || (baselineShare > 0 && currentShare >= baselineShare*2.1 && (currentShare-baselineShare) >= 0.09) {
				severity := "warning"
				if currentShare >= 0.40 || baselineShare <= 0.02 {
					severity = "critical"
				}
				appendAnomaly(
					"off_hours_entity_activity",
					severity,
					int(30 + currentShare*96 + (currentShare-baselineShare)*62),
					"UEBA Temporal Activity Drift",
					fmt.Sprintf("Activity in hour bucket %s rose to %.1f%% (baseline %.1f%%), indicating unusual temporal behavior.", formatHourBucket(dominantHour), currentShare*100, baselineShare*100),
					dominantHourHits,
					baselineShare,
					currentShare,
					map[string]interface{}{
						"hour_bucket":           formatHourBucket(dominantHour),
						"hour_events":           dominantHourHits,
						"current_share":         currentShare,
						"historical_share":      baselineShare,
						"historical_total_events": historicalTotal,
						"window_minutes":        windowMinutes,
					},
				)
			}
		}
	}

	windowRiskHits := windowBlocked + windowSuspicious
	if windowTotal >= 22 && len(destinationWindow) > 0 {
		topDst := ""
		topHits := 0
		for dst, hits := range destinationWindow {
			if hits > topHits {
				topDst = dst
				topHits = hits
			}
		}
		if topDst != "" && topHits >= 9 {
			riskHits := destinationRiskWindow[topDst]
			share := safeRatio(float64(topHits), float64(windowTotal))
			riskShare := 0.0
			if windowRiskHits > 0 {
				riskShare = safeRatio(float64(riskHits), float64(windowRiskHits))
			}
			if share >= 0.28 || (riskHits >= 6 && riskShare >= 0.34) {
				severity := "warning"
				if share >= 0.42 || riskShare >= 0.56 {
					severity = "critical"
				}
				appendAnomaly(
					"destination_hotspot",
					severity,
					int(30 + share*86 + riskShare*44),
					"Destination Hotspot Pressure",
					fmt.Sprintf("Destination %s accounted for %d/%d events (%.1f%%), with %d high-risk hits.", topDst, topHits, windowTotal, share*100, riskHits),
					topHits,
					0.2,
					share,
					map[string]interface{}{
						"destination_ip":      topDst,
						"destination_hits":    topHits,
						"destination_share":   share,
						"risk_hits":           riskHits,
						"risk_share":          riskShare,
						"window_minutes":      windowMinutes,
					},
				)
			}
		}
	}

	halfOpen := 0
	for _, c := range conns {
		state := strings.ToUpper(strings.TrimSpace(c.State))
		if state == "SYN_SENT" || state == "SYN_RECV" {
			halfOpen++
		}
	}
	if len(conns) >= 20 && halfOpen >= 7 {
		halfOpenRatio := float64(halfOpen) / float64(len(conns))
		if halfOpenRatio >= 0.22 {
			severity := "warning"
			if halfOpenRatio >= 0.34 {
				severity = "critical"
			}
			appendAnomaly(
				"half_open_connection_pressure",
				severity,
				int(30 + halfOpenRatio*100),
				"Half-open Connection Pressure",
				fmt.Sprintf("%d of %d active connections are in SYN handshake states, consistent with connection-flood behavior.", halfOpen, len(conns)),
				halfOpen,
				0.2,
				halfOpenRatio,
				map[string]interface{}{
					"half_open_connections": halfOpen,
					"active_connections":    len(conns),
					"half_open_ratio":       halfOpenRatio,
				},
			)
		}
	}

	if maxFanout.Ports >= 8 {
		severity := "warning"
		if maxFanout.Ports >= 14 {
			severity = "critical"
		}
		appendAnomaly(
			"port_fanout",
			severity,
			int(34 + float64(maxFanout.Ports)*2.6),
			"Port Fanout Pattern",
			fmt.Sprintf("Remote %s is connected across %d local ports, suggesting broad probing behavior.", maxFanout.IP, maxFanout.Ports),
			maxFanout.Ports,
			6,
			float64(maxFanout.Ports),
			map[string]interface{}{
				"remote_ip":          maxFanout.IP,
				"local_ports_touched": maxFanout.Ports,
				"active_connections": len(conns),
			},
		)
	}

	sort.SliceStable(anomalies, func(i, j int) bool {
		return anomalies[i].Score > anomalies[j].Score
	})
	if len(anomalies) > 14 {
		anomalies = anomalies[:14]
	}

	riskScore := calculateAnomalyRiskScore(anomalies, windowTotal, windowBlocked, windowSuspicious, currentMinuteCount, meanPerMin, stdPerMin)

	status := "normal"
	switch {
	case riskScore >= 72:
		status = "critical"
	case riskScore >= 50:
		status = "high"
	case riskScore >= 28:
		status = "elevated"
	}

	snapshot.RiskScore = riskScore
	snapshot.Status = status
	snapshot.TotalAnomalies = len(anomalies)
	snapshot.Anomalies = anomalies
	return snapshot
}

func calculateAnomalyRiskScore(anomalies []models.TrafficAnomaly, windowTotal int, windowBlocked int, windowSuspicious int, currentMinuteCount int, meanPerMin float64, stdPerMin float64) int {
	if len(anomalies) == 0 {
		base := 0.0
		if windowTotal > 0 {
			blockedRatio := safeRatio(float64(windowBlocked), float64(windowTotal))
			suspiciousRatio := safeRatio(float64(windowSuspicious), float64(windowTotal))
			base += blockedRatio*24 + suspiciousRatio*18
		}
		if meanPerMin > 0 {
			threshold := meanPerMin + math.Max(stdPerMin*1.4, 2.0)
			if float64(currentMinuteCount) > threshold {
				base += math.Min(18, (float64(currentMinuteCount)-threshold)*1.1)
			}
		}
		return clampInt(int(math.Round(base)), 0, 100)
	}

	criticalCount := 0
	warningCount := 0
	weightedTotal := 0.0
	maxScore := 0
	for _, a := range anomalies {
		w := 1.0
		if a.Severity == "critical" {
			criticalCount++
			w = 1.35
		} else if a.Severity == "warning" {
			warningCount++
			w = 1.12
		}
		weightedTotal += float64(a.Score) * w
		if a.Score > maxScore {
			maxScore = a.Score
		}
	}
	weightedAvg := weightedTotal / float64(len(anomalies))
	topMean := meanTopAnomalyScores(anomalies, 3)

	severityPressure := float64(criticalCount*15 + warningCount*8 + len(anomalies)*3)
	behaviorPressure := 0.0
	if windowTotal > 0 {
		blockedRatio := safeRatio(float64(windowBlocked), float64(windowTotal))
		suspiciousRatio := safeRatio(float64(windowSuspicious), float64(windowTotal))
		behaviorPressure = blockedRatio*28 + suspiciousRatio*20
	}
	volatilityPressure := 0.0
	if meanPerMin > 0 {
		threshold := meanPerMin + math.Max(stdPerMin*1.8, 2.5)
		if float64(currentMinuteCount) > threshold {
			volatilityPressure = math.Min(14, (float64(currentMinuteCount)-threshold)*0.9)
		}
	}

	composite := weightedAvg*0.36 + float64(maxScore)*0.30 + topMean*0.18 + severityPressure*0.22 + behaviorPressure + volatilityPressure
	if len(anomalies) >= 5 {
		composite += 6
	}
	if criticalCount >= 2 {
		composite += 7
	}

	return clampInt(int(math.Round(composite)), 0, 100)
}

func meanTopAnomalyScores(anomalies []models.TrafficAnomaly, topN int) float64 {
	if len(anomalies) == 0 || topN <= 0 {
		return 0
	}
	if topN > len(anomalies) {
		topN = len(anomalies)
	}
	total := 0
	for i := 0; i < topN; i++ {
		total += anomalies[i].Score
	}
	return float64(total) / float64(topN)
}

func protocolEntropy(protocolCounts map[string]int) (float64, float64) {
	if len(protocolCounts) == 0 {
		return 0, 0
	}
	total := 0
	for _, c := range protocolCounts {
		total += c
	}
	if total <= 0 {
		return 0, 0
	}
	entropy := 0.0
	for _, c := range protocolCounts {
		if c <= 0 {
			continue
		}
		p := float64(c) / float64(total)
		entropy -= p * math.Log2(p)
	}
	maxEntropy := math.Log2(float64(len(protocolCounts)))
	if maxEntropy <= 0 {
		return entropy, 1
	}
	normalized := entropy / maxEntropy
	if normalized < 0 {
		normalized = 0
	}
	if normalized > 1 {
		normalized = 1
	}
	return entropy, normalized
}

func formatHourBucket(hour int) string {
	if hour < 0 || hour > 23 {
		return "unknown"
	}
	return fmt.Sprintf("%02d:00-%02d:59", hour, hour)
}

func safeRatio(numerator float64, denominator float64) float64 {
	if denominator <= 0 {
		return 0
	}
	return numerator / denominator
}

func medianInt(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	cp := append([]int(nil), values...)
	sort.Ints(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 1 {
		return float64(cp[mid])
	}
	return float64(cp[mid-1]+cp[mid]) / 2
}

func sumIntMap(values map[string]int) int {
	total := 0
	for _, v := range values {
		total += v
	}
	return total
}

func protocolDistributionDrift(currentCounts map[string]int, baselineCounts map[string]int) (jsd float64, shiftedProto string, shiftedCurrentShare float64, shiftedBaselineShare float64) {
	totalCurrent := sumIntMap(currentCounts)
	totalBaseline := sumIntMap(baselineCounts)
	if totalCurrent <= 0 || totalBaseline <= 0 {
		return 0, "", 0, 0
	}

	keys := make(map[string]struct{}, len(currentCounts)+len(baselineCounts))
	for proto := range currentCounts {
		keys[proto] = struct{}{}
	}
	for proto := range baselineCounts {
		keys[proto] = struct{}{}
	}

	maxDelta := 0.0
	for proto := range keys {
		p := safeRatio(float64(currentCounts[proto]), float64(totalCurrent))
		q := safeRatio(float64(baselineCounts[proto]), float64(totalBaseline))
		m := (p + q) / 2
		if p > 0 && m > 0 {
			jsd += 0.5 * p * math.Log2(p/m)
		}
		if q > 0 && m > 0 {
			jsd += 0.5 * q * math.Log2(q/m)
		}

		delta := p - q
		if delta > maxDelta {
			maxDelta = delta
			shiftedProto = proto
			shiftedCurrentShare = p
			shiftedBaselineShare = q
		}
	}

	if jsd < 0 {
		jsd = 0
	}
	if jsd > 1 {
		jsd = 1
	}
	return jsd, shiftedProto, shiftedCurrentShare, shiftedBaselineShare
}

func (h *handlers) recordAnomalySnapshot(snapshot models.TrafficAnomalySnapshot) {
	if h == nil {
		return
	}

	const anomalyTrendHistoryCap = 1440
	bucket := snapshot.GeneratedAt.UTC().Truncate(time.Minute)
	if bucket.IsZero() {
		return
	}

	riskPoint := models.TrafficAnomalyRiskPoint{
		Timestamp:      bucket,
		RiskScore:      clampInt(snapshot.RiskScore, 0, 100),
		Status:         strings.TrimSpace(snapshot.Status),
		TotalAnomalies: snapshot.TotalAnomalies,
		SampleSize:     snapshot.SampleSize,
	}

	h.anomalyTrendMu.Lock()
	defer h.anomalyTrendMu.Unlock()

	if h.anomalyRiskHistory == nil {
		h.anomalyRiskHistory = make([]models.TrafficAnomalyRiskPoint, 0, 256)
	}
	if len(h.anomalyRiskHistory) > 0 && h.anomalyRiskHistory[len(h.anomalyRiskHistory)-1].Timestamp.Equal(bucket) {
		h.anomalyRiskHistory[len(h.anomalyRiskHistory)-1] = riskPoint
	} else {
		h.anomalyRiskHistory = append(h.anomalyRiskHistory, riskPoint)
	}
	if len(h.anomalyRiskHistory) > anomalyTrendHistoryCap {
		h.anomalyRiskHistory = h.anomalyRiskHistory[len(h.anomalyRiskHistory)-anomalyTrendHistoryCap:]
	}

	if h.anomalyDetectorHistory == nil {
		h.anomalyDetectorHistory = make(map[string][]models.TrafficAnomalyDetectorPoint)
	}

	present := make(map[string]models.TrafficAnomalyDetectorPoint, len(snapshot.Anomalies))
	for _, a := range snapshot.Anomalies {
		kind := strings.TrimSpace(a.Type)
		if kind == "" {
			continue
		}
		present[kind] = models.TrafficAnomalyDetectorPoint{
			Timestamp: bucket,
			Score:     clampInt(a.Score, 0, 100),
			Severity:  strings.TrimSpace(strings.ToLower(a.Severity)),
		}
	}

	for kind, point := range present {
		series := h.anomalyDetectorHistory[kind]
		if len(series) > 0 && series[len(series)-1].Timestamp.Equal(bucket) {
			series[len(series)-1] = point
		} else {
			series = append(series, point)
		}
		if len(series) > anomalyTrendHistoryCap {
			series = series[len(series)-anomalyTrendHistoryCap:]
		}
		h.anomalyDetectorHistory[kind] = series
	}

	for kind, series := range h.anomalyDetectorHistory {
		if _, ok := present[kind]; ok {
			continue
		}
		zeroPoint := models.TrafficAnomalyDetectorPoint{
			Timestamp: bucket,
			Score:     0,
			Severity:  "info",
		}
		if len(series) > 0 && series[len(series)-1].Timestamp.Equal(bucket) {
			series[len(series)-1] = zeroPoint
		} else {
			series = append(series, zeroPoint)
		}
		if len(series) > anomalyTrendHistoryCap {
			series = series[len(series)-anomalyTrendHistoryCap:]
		}
		h.anomalyDetectorHistory[kind] = series
	}
}

func (h *handlers) withAnomalyTrendHistory(snapshot models.TrafficAnomalySnapshot, trendLimit int) models.TrafficAnomalySnapshot {
	if h == nil {
		return snapshot
	}
	if trendLimit < 10 {
		trendLimit = 10
	}
	if trendLimit > 1440 {
		trendLimit = 1440
	}

	h.anomalyTrendMu.RLock()
	defer h.anomalyTrendMu.RUnlock()

	riskSeries := h.anomalyRiskHistory
	if len(riskSeries) > trendLimit {
		riskSeries = riskSeries[len(riskSeries)-trendLimit:]
	}
	if len(riskSeries) > 0 {
		snapshot.RiskTrend = make([]models.TrafficAnomalyRiskPoint, len(riskSeries))
		copy(snapshot.RiskTrend, riskSeries)
	}

	type detectorCandidate struct {
		kind     string
		latest   models.TrafficAnomalyDetectorPoint
		points   []models.TrafficAnomalyDetectorPoint
		hasSignal bool
	}
	candidates := make([]detectorCandidate, 0, len(h.anomalyDetectorHistory))
	for kind, all := range h.anomalyDetectorHistory {
		if len(all) == 0 {
			continue
		}
		points := all
		if len(points) > trendLimit {
			points = points[len(points)-trendLimit:]
		}
		hasSignal := false
		for _, p := range points {
			if p.Score > 0 {
				hasSignal = true
				break
			}
		}
		if !hasSignal {
			continue
		}
		latest := points[len(points)-1]
		candidates = append(candidates, detectorCandidate{kind: kind, latest: latest, points: points, hasSignal: true})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].latest.Score == candidates[j].latest.Score {
			return candidates[i].latest.Timestamp.After(candidates[j].latest.Timestamp)
		}
		return candidates[i].latest.Score > candidates[j].latest.Score
	})

	maxSeries := 8
	if len(candidates) < maxSeries {
		maxSeries = len(candidates)
	}

	detectorTrends := make([]models.TrafficAnomalyDetectorTrend, 0, maxSeries)
	for i := 0; i < maxSeries; i++ {
		item := candidates[i]
		cp := make([]models.TrafficAnomalyDetectorPoint, len(item.points))
		copy(cp, item.points)
		detectorTrends = append(detectorTrends, models.TrafficAnomalyDetectorTrend{
			Type:           item.kind,
			Label:          detectorDisplayLabel(item.kind),
			LatestScore:    clampInt(item.latest.Score, 0, 100),
			LatestSeverity: item.latest.Severity,
			Points:         cp,
		})
	}

	if len(detectorTrends) == 0 {
		for _, a := range snapshot.Anomalies {
			detectorTrends = append(detectorTrends, models.TrafficAnomalyDetectorTrend{
				Type:           a.Type,
				Label:          detectorDisplayLabel(a.Type),
				LatestScore:    clampInt(a.Score, 0, 100),
				LatestSeverity: a.Severity,
				Points: []models.TrafficAnomalyDetectorPoint{
					{Timestamp: snapshot.GeneratedAt, Score: clampInt(a.Score, 0, 100), Severity: a.Severity},
				},
			})
			if len(detectorTrends) >= 8 {
				break
			}
		}
	}

	snapshot.DetectorTrends = detectorTrends
	return snapshot
}

func detectorDisplayLabel(kind string) string {
	kind = strings.TrimSpace(strings.ToLower(kind))
	if kind == "" {
		return "Detector"
	}
	parts := strings.Split(kind, "_")
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, " ")
}

func normalizeTrafficIP(ip string) string {
	clean := strings.TrimSpace(ip)
	if clean == "" || clean == "-" || clean == "0.0.0.0" || clean == "::" || clean == "::1" || clean == "127.0.0.1" {
		return ""
	}
	return clean
}

func normalizeTrafficProtocol(proto string) string {
	p := strings.ToUpper(strings.TrimSpace(proto))
	if p == "" || p == "-" {
		return ""
	}
	return p
}

func parseDestinationPortFromDetail(detail string) string {
	if detail == "" {
		return ""
	}
	lower := strings.ToLower(detail)
	markers := []string{"dst_port=", "dpt=", "dstport=", "destination_port=", "port="}

	for _, marker := range markers {
		idx := strings.Index(lower, marker)
		if idx < 0 {
			continue
		}
		start := idx + len(marker)
		end := start
		for end < len(lower) {
			ch := lower[end]
			if ch < '0' || ch > '9' {
				break
			}
			end++
		}
		if end <= start {
			continue
		}
		candidate := lower[start:end]
		if v, err := strconv.Atoi(candidate); err == nil && v >= 1 && v <= 65535 {
			return strconv.Itoa(v)
		}
	}

	// Support netmon connection details: "... -> 203.0.113.10:443 (...)" or with unicode arrow.
	arrowMarkers := []string{"->", "→"}
	for _, marker := range arrowMarkers {
		idx := strings.LastIndex(detail, marker)
		if idx < 0 {
			continue
		}
		tail := strings.TrimSpace(detail[idx+len(marker):])
		if tail == "" {
			continue
		}
		token := tail
		if cut := strings.IndexAny(token, " \t("); cut >= 0 {
			token = token[:cut]
		}
		if token == "" {
			continue
		}
		colon := strings.LastIndex(token, ":")
		if colon < 0 || colon+1 >= len(token) {
			continue
		}
		candidate := strings.TrimSpace(token[colon+1:])
		if v, err := strconv.Atoi(candidate); err == nil && v >= 1 && v <= 65535 {
			return strconv.Itoa(v)
		}
	}

	return ""
}

func isBlockingAction(action string) bool {
	a := strings.ToUpper(strings.TrimSpace(action))
	return a == "BLOCK" || a == "DROP" || a == "REJECT"
}

func isSuspiciousDetail(detail string) bool {
	d := strings.ToLower(detail)
	if d == "" {
		return false
	}
	keywords := []string{
		"suspicious", "malicious", "malware", "exploit", "attack", "bruteforce", "scan", "dns tunneling", "c2", "command-and-control", "exfil", "payload",
		"sql injection", "sqli", "xss", "rce", "botnet", "beacon", "flood", "port sweep", "malicious ip feed match",
	}
	for _, kw := range keywords {
		if strings.Contains(d, kw) {
			return true
		}
	}
	return false
}

func intSeriesStats(values []int) (mean float64, stddev float64) {
	if len(values) == 0 {
		return 0, 0
	}
	total := 0
	for _, v := range values {
		total += v
	}
	mean = float64(total) / float64(len(values))

	if len(values) == 1 {
		return mean, 0
	}
	variance := 0.0
	for _, v := range values {
		delta := float64(v) - mean
		variance += delta * delta
	}
	variance /= float64(len(values))
	stddev = math.Sqrt(variance)
	return mean, stddev
}

func clampInt(v int, minV int, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func (h *handlers) handleDNSStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: h.fw.DNSStats()})
}

func (h *handlers) handleDNSCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	h.fw.ClearDNSCache()
	respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "DNS cache cleared"})
}

func (h *handlers) handleDNSRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "invalid JSON"})
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: h.fw.RefreshDNS(body.IPs)})
}

func (h *handlers) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 2000 {
			limit = v
		}
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: h.logger.RecentFirewallEvents(limit)})
}

func (h *handlers) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	subID, ch := h.logger.SubscribeFirewallEvents()
	defer h.logger.UnsubscribeFirewallEvents(subID)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: firewall-event\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (h *handlers) handleRulesAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: h.fw.AnalyzeCurrentRules()})
}

func (h *handlers) handleRuleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req models.RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "Invalid JSON"})
		return
	}
	if err := firewall.ValidateRuleRequest(req); err != nil {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: err.Error()})
		return
	}
	warnings := h.fw.ValidateCandidateRule(req)
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: warnings})
}

// handlers holds dependencies for HTTP handler methods.
type handlers struct {
	fw        *firewall.Engine
	logger    *logger.TrafficLogger
	threat    *threatintel.Service
	analytics *analytics.Service
	dpi       *DPIProvider
	geo       *geoip.Service
	proxy     maliciousDomainProxy
	aiService *ai.OpenRouterService

	anomalyTrendMu       sync.RWMutex
	anomalyRiskHistory   []models.TrafficAnomalyRiskPoint
	anomalyDetectorHistory map[string][]models.TrafficAnomalyDetectorPoint

	myGeoMu      sync.RWMutex
	myGeoCache   models.GeoLocation
	myGeoExpiry  time.Time
}

func (h *handlers) handleProxyMaliciousDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if h.proxy == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "HTTP proxy is disabled"})
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: map[string]interface{}{
		"stats":   h.proxy.DomainStats(),
		"domains": h.proxy.DomainList(),
	}})
}

func (h *handlers) handleProxyMaliciousDomainsReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if h.proxy == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "HTTP proxy is disabled"})
		return
	}
	count, err := h.proxy.ReloadDomains()
	if err != nil {
		respond(w, http.StatusInternalServerError, models.APIResponse{Success: false, Message: err.Error()})
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "Malicious domain list reloaded", Data: map[string]interface{}{
		"domain_count": count,
		"stats":        h.proxy.DomainStats(),
	}})
}

func (h *handlers) handleProxyBlockedEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if h.proxy == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "HTTP proxy is disabled"})
		return
	}
	limit := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
			limit = v
		}
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: h.proxy.RecentBlockedEvents(limit)})
}

func (h *handlers) handleGeoAttacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if h.geo == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "GeoIP unavailable"})
		return
	}
	limit := 300
	if q := r.URL.Query().Get("limit"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 2000 {
			limit = v
		}
	}
	points := make([]models.GeoAttackPoint, 0, limit)

	// Prioritize active connection arcs so map consistently shows current remote flow to home.
	connPoints := h.geoConnectionPoints(limit)
	points = append(points, connPoints...)

	remaining := limit - len(points)
	if remaining < 0 {
		remaining = 0
	}
	for _, ev := range h.logger.RecentFirewallEvents(remaining) {
		if p, ok := h.toGeoAttackPoint(ev); ok {
			points = append(points, p)
		}
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: points})
}

func (h *handlers) handleGeoMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if h.geo == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "GeoIP unavailable"})
		return
	}
	loc, ok := h.resolveMyGeoLocation()
	if !ok {
		respond(w, http.StatusNotFound, models.APIResponse{Success: false, Message: "Unable to determine public location"})
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: loc})
}

func (h *handlers) handleGeoStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if h.geo == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "GeoIP unavailable"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	subID, ch := h.logger.SubscribeFirewallEvents()
	defer h.logger.UnsubscribeFirewallEvents(subID)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			point, ok := h.toGeoAttackPoint(ev)
			if !ok {
				continue
			}
			data, _ := json.Marshal(point)
			fmt.Fprintf(w, "event: geo-attack\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (h *handlers) toGeoAttackPoint(ev models.FirewallEvent) (models.GeoAttackPoint, bool) {
	if h.geo == nil {
		return models.GeoAttackPoint{}, false
	}
	src, srcOK := h.geo.Lookup(ev.SrcIP)
	if !srcOK {
		return models.GeoAttackPoint{}, false
	}
	if src.IP == "" {
		src.IP = ev.SrcIP
	}

	target, targetOK := h.resolveMyGeoLocation()
	if !targetOK {
		dst, dstOK := h.geo.Lookup(ev.DstIP)
		if dstOK {
			if dst.IP == "" {
				dst.IP = ev.DstIP
			}
			target = dst
			targetOK = true
		}
	}
	if !targetOK {
		target = models.GeoLocation{}
	}

	return models.GeoAttackPoint{
		Timestamp: ev.Timestamp,
		EventType: ev.EventType,
		Action:    ev.Action,
		Severity:  ev.Severity,
		RuleID:    ev.RuleID,
		Detail:    ev.Detail,
		Source:    src,
		Target:    target,
	}, true
}

func (h *handlers) geoConnectionPoints(limit int) []models.GeoAttackPoint {
	if h == nil || h.geo == nil || h.fw == nil || limit <= 0 {
		return nil
	}

	target, targetOK := h.resolveMyGeoLocation()
	now := time.Now()
	conns := h.fw.ActiveConnections()
	points := make([]models.GeoAttackPoint, 0, len(conns))
	seen := make(map[string]struct{}, len(conns))

	for _, c := range conns {
		remoteIP := strings.TrimSpace(c.RemoteIP)
		if remoteIP == "" || remoteIP == "0.0.0.0" || remoteIP == "::" || remoteIP == "127.0.0.1" || remoteIP == "::1" {
			continue
		}

		key := strings.Join([]string{c.Protocol, c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, c.State}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		src, ok := h.geo.Lookup(remoteIP)
		if !ok {
			continue
		}
		if src.IP == "" {
			src.IP = remoteIP
		}

		dst := target
		if !targetOK {
			if loc, found := h.geo.Lookup(strings.TrimSpace(c.LocalIP)); found {
				if loc.IP == "" {
					loc.IP = strings.TrimSpace(c.LocalIP)
				}
				dst = loc
			}
		}

		points = append(points, models.GeoAttackPoint{
			Timestamp: now,
			EventType: "connection",
			Action:    "ALLOW",
			Severity:  "low",
			Detail:    fmt.Sprintf("Connection %s %s:%s -> %s:%s (%s)", strings.ToUpper(c.Protocol), c.RemoteIP, c.RemotePort, c.LocalIP, c.LocalPort, c.State),
			Source:    src,
			Target:    dst,
		})

		if len(points) >= limit {
			break
		}
	}

	return points
}

func (h *handlers) resolveMyGeoLocation() (models.GeoLocation, bool) {
	if h == nil || h.geo == nil {
		return models.GeoLocation{}, false
	}

	now := time.Now()
	h.myGeoMu.RLock()
	if now.Before(h.myGeoExpiry) && h.myGeoCache.IP != "" {
		loc := h.myGeoCache
		h.myGeoMu.RUnlock()
		return loc, true
	}
	h.myGeoMu.RUnlock()

	if ip, ok := h.detectLikelyPublicIPFromEvents(); ok {
		if loc, found := h.geo.Lookup(ip); found {
			h.myGeoMu.Lock()
			h.myGeoCache = loc
			h.myGeoExpiry = now.Add(10 * time.Minute)
			h.myGeoMu.Unlock()
			return loc, true
		}
	}

	if ip, ok := fetchPublicIP(); ok {
		if loc, found := h.geo.Lookup(ip); found {
			h.myGeoMu.Lock()
			h.myGeoCache = loc
			h.myGeoExpiry = now.Add(10 * time.Minute)
			h.myGeoMu.Unlock()
			return loc, true
		}
	}

	return models.GeoLocation{}, false
}

func (h *handlers) detectLikelyPublicIPFromEvents() (string, bool) {
	events := h.logger.RecentFirewallEvents(600)
	if len(events) == 0 {
		return "", false
	}

	counts := make(map[string]int)
	for _, ev := range events {
		if ev.DstIP == "" {
			continue
		}
		if _, ok := h.geo.Lookup(ev.DstIP); ok {
			counts[ev.DstIP]++
		}
	}

	bestIP := ""
	bestCount := 0
	for ip, c := range counts {
		if c > bestCount {
			bestIP = ip
			bestCount = c
		}
	}
	if bestIP == "" {
		return "", false
	}
	return bestIP, true
}

func fetchPublicIP() (string, bool) {
	urls := []string{"https://api.ipify.org", "https://ifconfig.me/ip"}
	client := &http.Client{Timeout: 3 * time.Second}
	for _, u := range urls {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip, true
		}
	}
	return "", false
}

// ---------- Rules ----------

// handleRules dispatches GET (list) and POST (create) for /api/v1/rules
func (h *handlers) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listRules(w, r)
	case http.MethodPost:
		h.addRule(w, r)
	default:
		methodNotAllowed(w)
	}
}

// listRules returns all firewall rules as JSON.
func (h *handlers) listRules(w http.ResponseWriter, r *http.Request) {
	rules := h.fw.ListRules()
	respond(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    rules,
	})
}

// addRule creates a new firewall rule from the request body.
func (h *handlers) addRule(w http.ResponseWriter, r *http.Request) {
	var req models.RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid JSON: " + err.Error(),
		})
		return
	}

	rule, err := h.fw.AddRule(req)
	if err != nil {
		respond(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	respond(w, http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "Rule created",
		Data:    rule,
	})
}

// handleRuleByID dispatches GET, DELETE, PATCH for /api/v1/rules/{id}
func (h *handlers) handleRuleByID(w http.ResponseWriter, r *http.Request) {
	// Extract rule ID from the URL path
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/")
	if id == "" {
		respond(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Missing rule ID",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		rule, err := h.fw.GetRule(id)
		if err != nil {
			respond(w, http.StatusNotFound, models.APIResponse{Success: false, Message: err.Error()})
			return
		}
		respond(w, http.StatusOK, models.APIResponse{Success: true, Data: rule})

	case http.MethodDelete:
		if err := h.fw.RemoveRule(id); err != nil {
			respond(w, http.StatusNotFound, models.APIResponse{Success: false, Message: err.Error()})
			return
		}
		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "Rule deleted"})

	case http.MethodPatch:
		// Toggle rule enabled/disabled
		rule, err := h.fw.ToggleRule(id)
		if err != nil {
			respond(w, http.StatusNotFound, models.APIResponse{Success: false, Message: err.Error()})
			return
		}
		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "Rule toggled", Data: rule})

	case http.MethodPut:
		// Update rule
		var req models.RuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "Invalid JSON"})
			return
		}
		rule, err := h.fw.UpdateRule(id, req)
		if err != nil {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: err.Error()})
			return
		}
		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "Rule updated", Data: rule})

	default:
		methodNotAllowed(w)
	}
}

// ---------- Dashboard ----------

// handleStats returns firewall statistics for the dashboard.
func (h *handlers) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	stats := h.fw.Stats()
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: stats})
}

// handleSysInfo returns detailed real-time system information.
func (h *handlers) handleSysInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	si := sysinfo.Gather()
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: si})
}

// handleConnections returns active network connections.
func (h *handlers) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	conns := h.fw.ActiveConnections()
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: conns})
}

// handleLogs returns recent traffic log entries.
func (h *handlers) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	n := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 1000 {
			n = v
		}
	}
	entries := h.logger.RecentEntries(n)
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: entries})
}

// handleLogStream provides a Server-Sent Events (SSE) stream of real-time log entries.
func (h *handlers) handleLogStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	subID, ch := h.logger.Subscribe()
	defer h.logger.Unsubscribe(subID)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// ---------- Threat Intelligence ----------

// handleAPIKey handles GET (check status) and POST (set key) for the VT API key.
func (h *handlers) handleAPIKey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		respond(w, http.StatusOK, models.APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"configured":   h.threat.HasAPIKey(),
				"cache_entries": h.threat.CacheStats(),
			},
		})
	case http.MethodPost:
		var body struct {
			APIKey string `json:"api_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.APIKey == "" {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "api_key is required"})
			return
		}
		h.threat.SetAPIKey(body.APIKey)
		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "API key saved"})
	case http.MethodDelete:
		h.threat.SetAPIKey("")
		h.threat.ClearCache()
		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "API key removed"})
	default:
		methodNotAllowed(w)
	}
}

// handleThreatCheck looks up an IP against VirusTotal: /api/v1/threat/check/{ip}
func (h *handlers) handleThreatCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	ip := strings.TrimPrefix(r.URL.Path, "/api/v1/threat/check/")
	if ip == "" {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "IP address required"})
		return
	}

	verdict, err := h.threat.CheckIP(ip)
	autoBlocked, autoBlockMsg := h.enforceThreatAutoBlock(verdict)

	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no api key configured") {
			if autoBlockMsg != "" {
				respond(w, http.StatusOK, models.APIResponse{Success: true, Message: autoBlockMsg, Data: verdict})
				return
			}
			respond(w, http.StatusOK, models.APIResponse{Success: true, Data: verdict})
			return
		}
		msg := err.Error()
		if autoBlockMsg != "" {
			msg = msg + " | " + autoBlockMsg
		}
		respond(w, http.StatusOK, models.APIResponse{
			Success: true,
			Message: msg,
			Data:    verdict,
		})
		return
	}

	if autoBlocked {
		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: autoBlockMsg, Data: verdict})
		return
	}
	if autoBlockMsg != "" {
		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: autoBlockMsg, Data: verdict})
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: verdict})
}

func (h *handlers) enforceThreatAutoBlock(verdict threatintel.Verdict) (bool, string) {
	if h == nil || h.fw == nil {
		return false, ""
	}
	ip := strings.TrimSpace(verdict.IP)
	if ip == "" {
		return false, ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsUnspecified() {
		return false, ""
	}
	if !shouldAggressivelyBlockThreat(verdict) {
		return false, ""
	}
	if !h.fw.EngineInfo().LiveMode {
		msg := fmt.Sprintf("Threat detected for %s, but firewall backend is not in live mode; block not enforced", ip)
		if h.logger != nil {
			h.logger.Log("LOG", ip, "-", "THREAT", "dpi:threat_block_unenforced:firewall_not_live")
		}
		return false, msg
	}
	if h.fw.IsIPBlocked(ip) {
		return false, ""
	}
	reason := fmt.Sprintf("Auto threat block: level=%s malicious=%d suspicious=%d reputation=%d", verdict.ThreatLevel, verdict.Malicious, verdict.Suspicious, verdict.Reputation)
	if _, err := h.fw.BlockIP(ip, reason); err != nil {
		if h.logger != nil {
			h.logger.Log("ERROR", ip, "-", "THREAT", fmt.Sprintf("threat auto-block failed: %v", err))
		}
		return false, ""
	}
	msg := fmt.Sprintf("Threat auto-block enforced for %s", ip)
	if h.logger != nil {
		h.logger.Log("BLOCK", ip, "-", "THREAT", msg)
	}
	return true, msg
}

func shouldAggressivelyBlockThreat(verdict threatintel.Verdict) bool {
	level := strings.ToLower(strings.TrimSpace(verdict.ThreatLevel))
	if level == "malicious" {
		return verdict.Malicious >= 1 || verdict.Suspicious >= 2
	}
	if level == "suspicious" {
		return verdict.Malicious >= 1 || verdict.Suspicious >= 4
	}
	return verdict.Malicious >= 2
}

func (h *handlers) enforceAnomalyBlocking(snapshot models.TrafficAnomalySnapshot) {
	if h == nil || h.fw == nil {
		return
	}
	if !h.fw.EngineInfo().LiveMode {
		return
	}
	if strings.ToLower(strings.TrimSpace(snapshot.Status)) != "critical" && snapshot.RiskScore < 68 {
		return
	}

	for _, anomaly := range snapshot.Anomalies {
		severity := strings.ToLower(strings.TrimSpace(anomaly.Severity))
		if severity != "critical" && anomaly.Score < 80 {
			continue
		}
		if !isAnomalyAutoBlockType(anomaly.Type) {
			continue
		}
		ip := anomalyEvidenceSourceIP(anomaly.Evidence)
		if ip == "" || !isBlockableInternetIP(ip) {
			continue
		}
		if h.fw.IsIPBlocked(ip) {
			continue
		}

		reason := fmt.Sprintf("Auto anomaly block: type=%s score=%d risk=%d", anomaly.Type, anomaly.Score, snapshot.RiskScore)
		if _, err := h.fw.BlockIP(ip, reason); err != nil {
			if h.logger != nil {
				h.logger.Log("ERROR", ip, "-", "ANOMALY", fmt.Sprintf("anomaly auto-block failed: %v", err))
			}
			continue
		}
		if h.logger != nil {
			h.logger.Log("BLOCK", ip, "-", "ANOMALY", fmt.Sprintf("Anomaly auto-block applied (%s)", anomaly.Type))
		}
		return
	}
}

func isAnomalyAutoBlockType(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "source_port_scan", "source_target_sweep", "repeat_offender", "entity_behavior_shift", "new_entity_risk_surge", "half_open_connection_pressure":
		return true
	default:
		return false
	}
}

func anomalyEvidenceSourceIP(evidence map[string]interface{}) string {
	if len(evidence) == 0 {
		return ""
	}
	for _, key := range []string{"source_ip", "entity_ip"} {
		if raw, ok := evidence[key]; ok {
			if s, ok := raw.(string); ok {
				s = strings.TrimSpace(s)
				if net.ParseIP(s) != nil {
					return s
				}
			}
		}
	}
	return ""
}

func isBlockableInternetIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	return true
}

// handleThreatCache returns all cached VT verdicts with connection/block status.
func (h *handlers) handleThreatCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	// Get active connections to check if cached IPs are connected
	conns := h.fw.ActiveConnections()
	connectedIPs := make(map[string]bool)
	for _, c := range conns {
		connectedIPs[c.RemoteIP] = true
		connectedIPs[c.LocalIP] = true
	}

	verdicts := h.threat.CacheEntries()
	entries := make([]models.ThreatCacheEntry, 0, len(verdicts))
	for _, v := range verdicts {
		entries = append(entries, models.ThreatCacheEntry{
			IP:            v.IP,
			ThreatLevel:   v.ThreatLevel,
			Malicious:     v.Malicious,
			Suspicious:    v.Suspicious,
			Harmless:      v.Harmless,
			Reputation:    v.Reputation,
			Country:       v.Country,
			Owner:         v.Owner,
			CheckedAt:     v.CheckedAt.Format("2006-01-02 15:04:05"),
			HasConnection: connectedIPs[v.IP],
			IsBlocked:     h.fw.IsIPBlocked(v.IP),
		})
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: entries})
}

// ---------- Blocked IPs ----------

func (h *handlers) handleBlockedIPs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		respond(w, http.StatusOK, models.APIResponse{Success: true, Data: h.fw.ListBlockedIPs()})
	case http.MethodPost:
		var body struct {
			IP     string `json:"ip"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "ip is required"})
			return
		}
		entry, err := h.fw.BlockIP(body.IP, body.Reason)
		if err != nil {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: err.Error()})
			return
		}
		respond(w, http.StatusCreated, models.APIResponse{Success: true, Message: "IP blocked", Data: entry})
	default:
		methodNotAllowed(w)
	}
}

func (h *handlers) handleBlockedIPByAddr(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/v1/blocked/")
	if ip == "" {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "IP required"})
		return
	}
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	if err := h.fw.UnblockIP(ip); err != nil {
		respond(w, http.StatusNotFound, models.APIResponse{Success: false, Message: err.Error()})
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "IP unblocked"})
}

// ---------- Website Blocking ----------

func (h *handlers) handleWebsiteBlocks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		websites := h.fw.ListWebsiteBlocks()
		respond(w, http.StatusOK, models.APIResponse{Success: true, Data: websites})
	case http.MethodPost:
		var body struct {
			Domain string `json:"domain"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Domain == "" {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "domain is required"})
			return
		}
		entry, err := h.fw.BlockWebsite(body.Domain, body.Reason)
		if err != nil {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: err.Error()})
			return
		}
		proxySynced := true
		proxyMessage := ""
		if h.proxy != nil {
			if added, normalized, perr := h.proxy.AddDomain(body.Domain); perr != nil {
				proxySynced = false
				proxyMessage = perr.Error()
			} else if !added {
				proxyMessage = fmt.Sprintf("already present in proxy list as %s", normalized)
			} else {
				proxyMessage = fmt.Sprintf("added to proxy list as %s", normalized)
			}
		}
		msg := "Website blocked"
		if proxyMessage != "" {
			msg = msg + " (" + proxyMessage + ")"
		}
		status := http.StatusCreated
		if !proxySynced {
			status = http.StatusAccepted
		}
		respond(w, status, models.APIResponse{Success: true, Message: msg, Data: map[string]interface{}{
			"website":      entry,
			"proxy_synced": proxySynced,
		}})
		return
	default:
		methodNotAllowed(w)
	}
}

func (h *handlers) handleWebsiteBlockByDomain(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/api/v1/websites/")
	if domain == "" {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "domain required"})
		return
	}
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	if err := h.fw.UnblockWebsite(domain); err != nil {
		respond(w, http.StatusNotFound, models.APIResponse{Success: false, Message: err.Error()})
		return
	}
	proxySynced := true
	proxyMessage := ""
	if h.proxy != nil {
		if removed, normalized, perr := h.proxy.RemoveDomain(domain); perr != nil {
			proxySynced = false
			proxyMessage = perr.Error()
		} else if !removed {
			proxyMessage = fmt.Sprintf("not found in proxy list (normalized %s)", normalized)
		} else {
			proxyMessage = fmt.Sprintf("removed from proxy list (%s)", normalized)
		}
	}
	msg := "Website unblocked"
	if proxyMessage != "" {
		msg = msg + " (" + proxyMessage + ")"
	}
	status := http.StatusOK
	if !proxySynced {
		status = http.StatusAccepted
	}
	respond(w, status, models.APIResponse{Success: true, Message: msg, Data: map[string]interface{}{"proxy_synced": proxySynced}})
}

// ---------- Analytics ----------

// handleAnalytics returns the full analytics snapshot (bandwidth history, top talkers, protocols, blocked/allowed).
func (h *handlers) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	snap := h.analytics.GetSnapshot()
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: snap})
}

// handleAnalyticsStream provides SSE for live bandwidth samples.
func (h *handlers) handleAnalyticsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	subID, ch := h.analytics.Subscribe()
	defer h.analytics.Unsubscribe(subID)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case sample, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(sample)
			fmt.Fprintf(w, "event: bandwidth\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// ---------- AI Explainability  ----------

func (h *handlers) handleAIApiKey(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "AI service unavailable"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		provider := h.aiService.Provider()
		configuredMap := map[string]bool{}
		for _, p := range h.aiService.SupportedProviders() {
			configuredMap[p] = h.aiService.HasAPIKeyForProvider(p)
		}
		respond(w, http.StatusOK, models.APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"provider":             provider,
				"providers":            h.aiService.SupportedProviders(),
				"configured":           h.aiService.HasAPIKeyForProvider(provider),
				"configured_providers": h.aiService.ConfiguredProviders(),
				"configured_map":       configuredMap,
			},
		})
	case http.MethodPost:
		var body struct {
			APIKey   string `json:"api_key"`
			Provider string `json:"provider"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "invalid JSON payload"})
			return
		}
		if strings.TrimSpace(body.Provider) == "" && strings.TrimSpace(body.APIKey) == "" {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "provider or api_key is required"})
			return
		}

		provider := h.aiService.Provider()
		if strings.TrimSpace(body.Provider) != "" {
			if err := h.aiService.SetProvider(body.Provider); err != nil {
				respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: err.Error()})
				return
			}
			provider = h.aiService.Provider()
		}

		if strings.TrimSpace(body.APIKey) != "" {
			if err := h.aiService.SetAPIKeyForProvider(provider, body.APIKey); err != nil {
				respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: err.Error()})
				return
			}
			respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "AI provider updated and API key saved", Data: map[string]interface{}{"provider": provider}})
			return
		}

		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "AI provider updated", Data: map[string]interface{}{"provider": provider}})
	case http.MethodDelete:
		provider := strings.TrimSpace(r.URL.Query().Get("provider"))
		if provider == "" {
			provider = h.aiService.Provider()
		}
		if err := h.aiService.RemoveAPIKeyForProvider(provider); err != nil {
			respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: err.Error()})
			return
		}
		respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "AI API key removed", Data: map[string]interface{}{"provider": strings.ToLower(strings.TrimSpace(provider))}})
	default:
		methodNotAllowed(w)
	}
}

func (h *handlers) handleAIExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if h.aiService == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "AI service unavailable"})
		return
	}
	var packetMeta map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&packetMeta); err != nil {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "Invalid JSON packet metadata"})
		return
	}
	explanation, err := h.aiService.ExplainBlock(packetMeta)
	if err != nil {
		respond(w, http.StatusInternalServerError, models.APIResponse{Success: false, Message: err.Error()})
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: explanation})
}

func (h *handlers) handleAIStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if h.aiService == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "AI service unavailable"})
		return
	}

	status := h.aiService.ConnectionStatus()
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: status})
}

func (h *handlers) handleAISuggestRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if h.aiService == nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: "AI service unavailable"})
		return
	}

	var packetMeta map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&packetMeta); err != nil {
		respond(w, http.StatusBadRequest, models.APIResponse{Success: false, Message: "Invalid JSON packet metadata"})
		return
	}

	decision, err := h.aiService.SuggestRuleDecision(packetMeta)
	if err != nil {
		respond(w, http.StatusInternalServerError, models.APIResponse{Success: false, Message: err.Error()})
		return
	}

	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: decision})
}

// ---------- Helpers ----------

// respond writes a JSON response with the given status code.
func respond(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func methodNotAllowed(w http.ResponseWriter) {
	respond(w, http.StatusMethodNotAllowed, models.APIResponse{
		Success: false,
		Message: "Method not allowed",
	})
}

func withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered method=%s path=%s err=%v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				respond(w, http.StatusInternalServerError, models.APIResponse{
					Success: false,
					Message: "internal server error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
