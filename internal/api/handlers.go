// Package api provides the HTTP router and REST API handlers for KaliWall.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime/debug"
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
	return ctrl.SetEnabled(enabled)
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

	// Serve web UI from the "web" directory
	fs := http.FileServer(http.Dir("web"))
	mux.Handle("/", fs)

	return withRecovery(mux)
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
	if err := h.dpi.SetEnabled(*body.Enabled); err != nil {
		respond(w, http.StatusServiceUnavailable, models.APIResponse{Success: false, Message: err.Error()})
		return
	}
	status, _ := h.dpi.Status()
	msg := "DPI disabled"
	if *body.Enabled {
		msg = "DPI enabled"
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Message: msg, Data: status})
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
	for _, ev := range h.logger.RecentFirewallEvents(limit) {
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

	target, targetOK := h.resolveMyGeoLocation()
	if !targetOK {
		dst, dstOK := h.geo.Lookup(ev.DstIP)
		if dstOK {
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
	if err != nil {
		respond(w, http.StatusOK, models.APIResponse{
			Success: true,
			Message: err.Error(),
			Data:    verdict,
		})
		return
	}
	respond(w, http.StatusOK, models.APIResponse{Success: true, Data: verdict})
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
