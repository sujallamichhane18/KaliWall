// Package api provides the HTTP router and REST API handlers for KaliWall.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"kaliwall/internal/analytics"
	"kaliwall/internal/firewall"
	"kaliwall/internal/logger"
	"kaliwall/internal/models"
	"kaliwall/internal/sysinfo"
	"kaliwall/internal/threatintel"
)

// NewRouter creates the HTTP mux with all API routes and static file serving.
func NewRouter(fw *firewall.Engine, tl *logger.TrafficLogger, ti *threatintel.Service, an *analytics.Service) http.Handler {
	mux := http.NewServeMux()

	h := &handlers{fw: fw, logger: tl, threat: ti, analytics: an}

	// REST API v1 endpoints
	mux.HandleFunc("/api/v1/rules", h.handleRules)
	mux.HandleFunc("/api/v1/rules/", h.handleRuleByID)  // /api/v1/rules/{id}
	mux.HandleFunc("/api/v1/stats", h.handleStats)
	mux.HandleFunc("/api/v1/sysinfo", h.handleSysInfo)
	mux.HandleFunc("/api/v1/connections", h.handleConnections)
	mux.HandleFunc("/api/v1/logs", h.handleLogs)
	mux.HandleFunc("/api/v1/logs/stream", h.handleLogStream)
	mux.HandleFunc("/api/v1/threat/apikey", h.handleAPIKey)
	mux.HandleFunc("/api/v1/threat/check/", h.handleThreatCheck)
	mux.HandleFunc("/api/v1/threat/cache", h.handleThreatCache)
	mux.HandleFunc("/api/v1/analytics", h.handleAnalytics)
	mux.HandleFunc("/api/v1/analytics/stream", h.handleAnalyticsStream)
	mux.HandleFunc("/api/v1/blocked", h.handleBlockedIPs)
	mux.HandleFunc("/api/v1/blocked/", h.handleBlockedIPByAddr)
	mux.HandleFunc("/api/v1/websites", h.handleWebsiteBlocks)
	mux.HandleFunc("/api/v1/websites/", h.handleWebsiteBlockByDomain)

	// Serve web UI from the "web" directory
	fs := http.FileServer(http.Dir("web"))
	mux.Handle("/", fs)

	return mux
}

// handlers holds dependencies for HTTP handler methods.
type handlers struct {
	fw        *firewall.Engine
	logger    *logger.TrafficLogger
	threat    *threatintel.Service
	analytics *analytics.Service
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
		respond(w, http.StatusOK, models.APIResponse{Success: true, Data: h.fw.ListWebsiteBlocks()})
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
		respond(w, http.StatusCreated, models.APIResponse{Success: true, Message: "Website blocked", Data: entry})
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
	respond(w, http.StatusOK, models.APIResponse{Success: true, Message: "Website unblocked"})
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
