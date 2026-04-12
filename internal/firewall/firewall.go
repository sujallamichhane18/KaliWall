// Package firewall manages iptables/nftables rule application and in-memory rule storage.
// On Linux with root privileges it executes real iptables commands.
// Otherwise it operates in demo mode with in-memory rules only.
package firewall

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"kaliwall/internal/database"
	"kaliwall/internal/logger"
	"kaliwall/internal/models"
	"kaliwall/internal/sysinfo"
)

const (
	engineMemory   = "memory"
	engineIPTables = "iptables"
	engineUFW      = "ufw"
	engineNFTables = "nftables"
)

// Engine is the core firewall management component.
type Engine struct {
	mu        sync.RWMutex
	rules     []models.Rule
	logger    *logger.TrafficLogger
	db        *database.Store
	liveMode  bool
	backend   string
	available []string
	root      bool
	lastError string
	dnsMu      sync.RWMutex
	dnsCache   map[string]dnsCacheEntry
	nslookup   string
	lookupsTotal int
	cacheHits int
	cacheMisses int
	verifiedPTR int
	unresolved int
}

type dnsCacheEntry struct {
	host     string
	verified bool
	expires  time.Time
}

// New creates a new firewall engine and detects whether live iptables mode is available.
func New(l *logger.TrafficLogger, db *database.Store) *Engine {
	e := &Engine{rules: make([]models.Rule, 0), logger: l, db: db, backend: engineMemory, dnsCache: make(map[string]dnsCacheEntry)}
	if path, err := exec.LookPath("nslookup"); err == nil {
		e.nslookup = path
	}
	l.SetBackendProvider(func() string {
		e.mu.RLock()
		defer e.mu.RUnlock()
		return e.backend
	})
	e.detectMode()

	// Load persisted rules from database
	if db != nil {
		saved := db.LoadRules()
		if len(saved) > 0 {
			e.rules = saved
			fmt.Printf("[+] Restored %d rules from database\n", len(saved))
		}
	}

	e.ensureDefaultRules()

	if db != nil {
		if savedEngine, ok := db.GetSetting("firewall_engine"); ok {
			savedEngine = strings.TrimSpace(strings.ToLower(savedEngine))
			if savedEngine != "" && savedEngine != e.backend {
				if err := e.SwitchEngine(savedEngine); err != nil {
					e.lastError = err.Error()
					fmt.Printf("[!] Saved firewall backend %q could not be restored: %v\n", savedEngine, err)
				}
			}
		}
	}

	if e.liveMode {
		e.syncLiveConfig()
	}

	return e
}

// detectMode checks available firewall backends and whether live mode is possible.
func (e *Engine) detectMode() {
	e.root = isRootUser()
	e.available = detectAvailableBackends()

	if !e.root {
		e.backend = engineMemory
		e.liveMode = false
		fmt.Println("[!] Not running as root — firewall backends in memory mode")
		return
	}

	if len(e.available) == 0 {
		e.backend = engineMemory
		e.liveMode = false
		fmt.Println("[!] No firewall backend detected — rules stored in-memory only")
		return
	}

	e.backend = e.available[0]
	e.liveMode = true
	fmt.Printf("[+] Firewall backend: %s (available: %s)\n", e.backend, strings.Join(e.available, ", "))
}

func isRootUser() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	u, err := user.Current()
	if err != nil {
		return false
	}
	return u.Uid == "0"
}

func detectAvailableBackends() []string {
	available := make([]string, 0, 3)
	if _, err := exec.LookPath("nft"); err == nil {
		available = append(available, engineNFTables)
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		available = append(available, engineIPTables)
	}
	if _, err := exec.LookPath("ufw"); err == nil {
		available = append(available, engineUFW)
	}
	return available
}

// ensureDefaultRules seeds a safe starter policy only on first-run.
func (e *Engine) ensureDefaultRules() {
	e.mu.Lock()
	if len(e.rules) > 0 {
		e.mu.Unlock()
		return
	}
	now := time.Now()
	e.rules = []models.Rule{
		{
			ID:        uuid.New().String(),
			Chain:     "INPUT",
			Protocol:  "all",
			SrcIP:     "127.0.0.1",
			DstIP:     "127.0.0.1",
			SrcPort:   "any",
			DstPort:   "any",
			Action:    "ACCEPT",
			Comment:   "Default: allow loopback inbound",
			Enabled:   true,
			CreatedAt: now,
		},
		{
			ID:        uuid.New().String(),
			Chain:     "OUTPUT",
			Protocol:  "all",
			SrcIP:     "127.0.0.1",
			DstIP:     "127.0.0.1",
			SrcPort:   "any",
			DstPort:   "any",
			Action:    "ACCEPT",
			Comment:   "Default: allow loopback outbound",
			Enabled:   true,
			CreatedAt: now,
		},
		{
			ID:        uuid.New().String(),
			Chain:     "OUTPUT",
			Protocol:  "udp",
			SrcIP:     "any",
			DstIP:     "any",
			SrcPort:   "any",
			DstPort:   "53",
			Action:    "ACCEPT",
			Comment:   "Default: allow DNS over UDP",
			Enabled:   true,
			CreatedAt: now,
		},
		{
			ID:        uuid.New().String(),
			Chain:     "OUTPUT",
			Protocol:  "tcp",
			SrcIP:     "any",
			DstIP:     "any",
			SrcPort:   "any",
			DstPort:   "53",
			Action:    "ACCEPT",
			Comment:   "Default: allow DNS over TCP",
			Enabled:   true,
			CreatedAt: now,
		},
		{
			ID:        uuid.New().String(),
			Chain:     "OUTPUT",
			Protocol:  "tcp",
			SrcIP:     "any",
			DstIP:     "any",
			SrcPort:   "any",
			DstPort:   "80",
			Action:    "ACCEPT",
			Comment:   "Default: allow HTTP outbound",
			Enabled:   true,
			CreatedAt: now,
		},
		{
			ID:        uuid.New().String(),
			Chain:     "OUTPUT",
			Protocol:  "tcp",
			SrcIP:     "any",
			DstIP:     "any",
			SrcPort:   "any",
			DstPort:   "443",
			Action:    "ACCEPT",
			Comment:   "Default: allow HTTPS outbound",
			Enabled:   true,
			CreatedAt: now,
		},
		{
			ID:        uuid.New().String(),
			Chain:     "INPUT",
			Protocol:  "tcp",
			SrcIP:     "any",
			DstIP:     "any",
			SrcPort:   "any",
			DstPort:   "22",
			Action:    "ACCEPT",
			Comment:   "Default (optional): allow SSH inbound",
			Enabled:   false,
			CreatedAt: now,
		},
	}
	rulesCount := len(e.rules)
	e.mu.Unlock()

	if e.db != nil {
		e.db.SaveRules(e.ListRules())
	}
	e.logger.Log("CONFIG", "-", "-", "-", fmt.Sprintf("Seeded %d default firewall rules", rulesCount))
}

// EngineInfo returns current firewall backend status for API/UI visibility.
func (e *Engine) EngineInfo() models.FirewallEngineInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	avail := make([]string, len(e.available))
	copy(avail, e.available)
	return models.FirewallEngineInfo{
		CurrentEngine: e.backend,
		Available:     avail,
		LiveMode:      e.liveMode,
		Root:          e.root,
		LastError:     e.lastError,
	}
}

// SwitchEngine changes the active backend and re-syncs rules/blocks.
func (e *Engine) SwitchEngine(name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = engineMemory
	}

	e.mu.Lock()
	if name == engineMemory {
		e.backend = engineMemory
		e.liveMode = false
		e.lastError = ""
		e.mu.Unlock()
		if e.db != nil {
			e.db.SetSetting("firewall_engine", engineMemory)
		}
		e.logger.Log("CONFIG", "-", "-", "-", "Firewall backend switched to memory")
		return nil
	}

	if !e.root {
		e.mu.Unlock()
		return fmt.Errorf("switching backend requires root")
	}

	ok := false
	for _, a := range e.available {
		if a == name {
			ok = true
			break
		}
	}
	if !ok {
		e.mu.Unlock()
		return fmt.Errorf("backend %s is not available", name)
	}

	e.backend = name
	e.liveMode = true
	e.lastError = ""
	e.mu.Unlock()

	if e.db != nil {
		e.db.SetSetting("firewall_engine", name)
	}
	go e.syncLiveConfig()
	e.logger.Log("CONFIG", "-", "-", "-", fmt.Sprintf("Firewall backend switched to %s", name))
	return nil
}

// ---------- Rule CRUD ----------

// AddRule validates, stores, and optionally applies a firewall rule.
func (e *Engine) AddRule(req models.RuleRequest) (models.Rule, error) {
	if err := validateRuleRequest(req); err != nil {
		return models.Rule{}, err
	}

	rule := models.Rule{
		ID:        uuid.New().String(),
		Chain:     strings.ToUpper(req.Chain),
		Protocol:  strings.ToLower(req.Protocol),
		ConnectionState: normalizeConnectionState(req.ConnectionState),
		SrcIP:     normalise(req.SrcIP),
		DstIP:     normalise(req.DstIP),
		SrcPort:   normalise(req.SrcPort),
		DstPort:   normalise(req.DstPort),
		Action:    strings.ToUpper(req.Action),
		Comment:   req.Comment,
		Enabled:   req.Enabled,
		CreatedAt: time.Now(),
	}

	e.mu.Lock()
	e.rules = append(e.rules, rule)
	e.mu.Unlock()

	// Persist to database
	if e.db != nil {
		e.db.SaveRules(e.ListRules())
	}

	// Apply to active firewall backend if live
	if e.liveMode && rule.Enabled {
		if err := e.syncLiveConfig(); err != nil {
			e.logger.Log("ERROR", "-", "-", "-", fmt.Sprintf("%s apply failed: %v", e.backend, err))
		}
	}

	e.logger.Log("CONFIG", "-", "-", "-",
		fmt.Sprintf("Rule added: %s %s %s src=%s dst=%s dport=%s [%s]",
			rule.Action, rule.Chain, rule.Protocol, rule.SrcIP, rule.DstIP, rule.DstPort, rule.Comment))
	e.emitPolicyEvent("policy_apply", rule, "Rule added", "info")

	return rule, nil
}

// RemoveRule deletes a rule by ID and removes it from iptables if live.
func (e *Engine) RemoveRule(id string) error {
	e.mu.Lock()
	idx := -1
	for i, r := range e.rules {
		if r.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		e.mu.Unlock()
		return fmt.Errorf("rule %s not found", id)
	}
	removed := e.rules[idx]
	needsSync := e.liveMode && removed.Enabled

	e.rules = append(e.rules[:idx], e.rules[idx+1:]...)
	e.logger.Log("CONFIG", "-", "-", "-", fmt.Sprintf("Rule removed: %s", id))

	// Persist
	if e.db != nil {
		rulesCopy := make([]models.Rule, len(e.rules))
		copy(rulesCopy, e.rules)
		go e.db.SaveRules(rulesCopy)
	}
	e.mu.Unlock()

	if needsSync {
		if err := e.syncLiveConfig(); err != nil {
			e.logger.Log("ERROR", "-", "-", "-", fmt.Sprintf("%s sync failed: %v", e.backend, err))
		}
	}
	e.emitPolicyEvent("policy_apply", removed, "Rule removed", "warning")

	return nil
}

// ToggleRule enables or disables a rule by ID.
func (e *Engine) ToggleRule(id string) (models.Rule, error) {
	e.mu.Lock()
	needsSync := false
	for i, r := range e.rules {
		if r.ID == id {
			e.rules[i].Enabled = !e.rules[i].Enabled
			needsSync = e.liveMode
			// Persist
			if e.db != nil {
				rulesCopy := make([]models.Rule, len(e.rules))
				copy(rulesCopy, e.rules)
				go e.db.SaveRules(rulesCopy)
			}
			result := e.rules[i]
			e.mu.Unlock()
			if needsSync {
				if err := e.syncLiveConfig(); err != nil {
					e.logger.Log("ERROR", "-", "-", "-", fmt.Sprintf("%s sync failed: %v", e.backend, err))
				}
			}
			e.emitPolicyEvent("rule_match", result, "Rule toggled", "info")
			return result, nil
		}
	}
	e.mu.Unlock()
	return models.Rule{}, fmt.Errorf("rule %s not found", id)
}

// ListRules returns a copy of all rules.
func (e *Engine) ListRules() []models.Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]models.Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// GetRule returns a single rule by ID.
func (e *Engine) GetRule(id string) (models.Rule, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, r := range e.rules {
		if r.ID == id {
			return r, nil
		}
	}
	return models.Rule{}, fmt.Errorf("rule %s not found", id)
}

// UpdateRule modifies an existing rule.
func (e *Engine) UpdateRule(id string, req models.RuleRequest) (models.Rule, error) {
	if err := validateRuleRequest(req); err != nil {
		return models.Rule{}, err
	}

	e.mu.Lock()
	for i, r := range e.rules {
		if r.ID == id {
			// Update fields
			e.rules[i].Chain = strings.ToUpper(req.Chain)
			e.rules[i].Protocol = strings.ToLower(req.Protocol)
			e.rules[i].ConnectionState = normalizeConnectionState(req.ConnectionState)
			e.rules[i].SrcIP = normalise(req.SrcIP)
			e.rules[i].DstIP = normalise(req.DstIP)
			e.rules[i].SrcPort = normalise(req.SrcPort)
			e.rules[i].DstPort = normalise(req.DstPort)
			e.rules[i].Action = strings.ToUpper(req.Action)
			e.rules[i].Comment = req.Comment
			e.rules[i].Enabled = req.Enabled

			needsSync := e.liveMode

			// Persist
			if e.db != nil {
				rulesCopy := make([]models.Rule, len(e.rules))
				copy(rulesCopy, e.rules)
				go e.db.SaveRules(rulesCopy)
			}

			e.logger.Log("CONFIG", "-", "-", "-",
				fmt.Sprintf("Rule updated: %s %s %s [%s]",
					e.rules[i].Action, e.rules[i].Chain, e.rules[i].Protocol, e.rules[i].Comment))
			result := e.rules[i]
			e.mu.Unlock()
			if needsSync {
				if err := e.syncLiveConfig(); err != nil {
					e.logger.Log("ERROR", "-", "-", "-", fmt.Sprintf("%s sync failed: %v", e.backend, err))
				}
			}
			e.emitPolicyEvent("policy_apply", result, "Rule updated", "info")
			return result, nil
		}
	}
	e.mu.Unlock()
	return models.Rule{}, fmt.Errorf("rule %s not found", id)
}

// AnalyzeRules detects duplicate, shadowed, and unreachable rules.
func (e *Engine) AnalyzeRules(rules []models.Rule) []models.RuleWarning {
	warnings := make([]models.RuleWarning, 0)
	seen := make(map[string]int)

	for i, r := range rules {
		sig := ruleSignature(r)
		if prev, ok := seen[sig]; ok {
			warnings = append(warnings, models.RuleWarning{
				Index: i, RuleID: r.ID, Level: "warning", Code: "duplicate_rule",
				Message: fmt.Sprintf("Duplicate of earlier rule at index %d", prev),
			})
		} else {
			seen[sig] = i
		}

		for j := 0; j < i; j++ {
			prev := rules[j]
			if !prev.Enabled || !r.Enabled {
				continue
			}
			if strings.EqualFold(prev.Chain, r.Chain) && strings.EqualFold(prev.Action, "ACCEPT") && strings.EqualFold(r.Action, "DROP") && ruleCovers(prev, r) {
				warnings = append(warnings, models.RuleWarning{
					Index: i, RuleID: r.ID, Level: "warning", Code: "shadowed_rule",
					Message: fmt.Sprintf("Broad ACCEPT at index %d can shadow this DROP", j),
				})
				warnings = append(warnings, models.RuleWarning{
					Index: i, RuleID: r.ID, Level: "error", Code: "unreachable_rule",
					Message: fmt.Sprintf("Rule may never match due to earlier ACCEPT at index %d", j),
				})
				break
			}
		}
	}
	return warnings
}

// AnalyzeCurrentRules analyzes currently configured rules.
func (e *Engine) AnalyzeCurrentRules() []models.RuleWarning {
	return e.AnalyzeRules(e.ListRules())
}

// ValidateCandidateRule analyzes current rules with a pending candidate appended.
func (e *Engine) ValidateCandidateRule(req models.RuleRequest) []models.RuleWarning {
	base := e.ListRules()
	candidate := models.Rule{
		ID:       "candidate",
		Chain:    strings.ToUpper(req.Chain),
		Protocol: strings.ToLower(req.Protocol),
		ConnectionState: normalizeConnectionState(req.ConnectionState),
		SrcIP:    normalise(req.SrcIP),
		DstIP:    normalise(req.DstIP),
		SrcPort:  normalise(req.SrcPort),
		DstPort:  normalise(req.DstPort),
		Action:   strings.ToUpper(req.Action),
		Comment:  req.Comment,
		Enabled:  req.Enabled,
	}
	base = append(base, candidate)
	return e.AnalyzeRules(base)
}

func ruleSignature(r models.Rule) string {
	return strings.Join([]string{
		strings.ToUpper(r.Chain),
		strings.ToLower(r.Protocol),
		normalizeConnectionState(r.ConnectionState),
		normalise(r.SrcIP),
		normalise(r.DstIP),
		normalise(r.SrcPort),
		normalise(r.DstPort),
		strings.ToUpper(r.Action),
		fmt.Sprintf("%t", r.Enabled),
	}, "|")
}

func ruleCovers(broad, specific models.Rule) bool {
	if !sameOrAny(broad.Protocol, specific.Protocol) {
		return false
	}
	if !sameOrAny(normalizeConnectionState(broad.ConnectionState), normalizeConnectionState(specific.ConnectionState)) {
		return false
	}
	if !sameOrAny(broad.SrcIP, specific.SrcIP) || !sameOrAny(broad.DstIP, specific.DstIP) {
		return false
	}
	if !sameOrAny(broad.SrcPort, specific.SrcPort) || !sameOrAny(broad.DstPort, specific.DstPort) {
		return false
	}
	return true
}

func sameOrAny(broad, specific string) bool {
	b := strings.TrimSpace(strings.ToLower(normalise(broad)))
	s := strings.TrimSpace(strings.ToLower(normalise(specific)))
	return b == "any" || b == "all" || b == s
}

func (e *Engine) emitPolicyEvent(eventType string, rule models.Rule, detail, severity string) {
	e.mu.RLock()
	backend := e.backend
	e.mu.RUnlock()
	e.logger.EmitFirewallEvent(models.FirewallEvent{
		EventType:   eventType,
		Backend:     backend,
		Action:      rule.Action,
		SrcIP:       rule.SrcIP,
		DstIP:       rule.DstIP,
		Protocol:    rule.Protocol,
		SrcPort:     rule.SrcPort,
		DstPort:     rule.DstPort,
		Chain:       rule.Chain,
		RuleID:      rule.ID,
		RuleComment: rule.Comment,
		Detail:      detail,
		Severity:    severity,
	})
}

// ---------- IP Blocking ----------

// BlockIP blocks an IP address via iptables and persists it.
func (e *Engine) BlockIP(ip, reason string) (models.BlockedIP, error) {
	if net.ParseIP(ip) == nil {
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			return models.BlockedIP{}, fmt.Errorf("invalid IP: %s", ip)
		}
	}
	if e.db == nil {
		return models.BlockedIP{}, fmt.Errorf("database unavailable")
	}

	entry, added := e.db.AddBlockedIP(ip, reason)
	if !added {
		return entry, nil
	}

	if e.liveMode {
		e.mu.RLock()
		backend := e.backend
		e.mu.RUnlock()

		if err := e.applyIPBlockBackend(backend, ip); err != nil {
			// Fallback to full sync when incremental apply fails due backend drift.
			if syncErr := e.syncLiveConfig(); syncErr != nil {
				e.logger.Log("ERROR", ip, "-", "-", fmt.Sprintf("%s IP block apply failed: %v", backend, syncErr))
			}
		}
	}

	e.logger.Log("BLOCK", ip, "-", "-", fmt.Sprintf("IP blocked: %s (%s)", ip, reason))
	e.mu.RLock()
	backend := e.backend
	e.mu.RUnlock()
	e.logger.EmitFirewallEvent(models.FirewallEvent{
		EventType: "blocked_packet",
		Backend:   backend,
		Action:    "BLOCK",
		SrcIP:     ip,
		Detail:    fmt.Sprintf("IP blocked: %s (%s)", ip, reason),
		Severity:  "critical",
	})
	return entry, nil
}

// UnblockIP removes an IP block.
func (e *Engine) UnblockIP(ip string) error {
	if !e.db.RemoveBlockedIP(ip) {
		return fmt.Errorf("IP %s not in blocklist", ip)
	}

	if e.liveMode {
		if err := e.syncLiveConfig(); err != nil {
			e.logger.Log("ERROR", ip, "-", "-", fmt.Sprintf("%s IP unblock apply failed: %v", e.backend, err))
		}
	}

	e.logger.Log("UNBLOCK", ip, "-", "-", fmt.Sprintf("IP unblocked: %s", ip))
	e.logger.EmitFirewallEvent(models.FirewallEvent{
		EventType: "policy_apply",
		Backend:   e.backend,
		Action:    "UNBLOCK",
		SrcIP:     ip,
		Detail:    fmt.Sprintf("IP unblocked: %s", ip),
		Severity:  "info",
	})
	return nil
}

// ListBlockedIPs returns all blocked IPs.
func (e *Engine) ListBlockedIPs() []models.BlockedIP {
	return e.db.ListBlockedIPs()
}

// IsIPBlocked checks if an IP is in the blocklist.
func (e *Engine) IsIPBlocked(ip string) bool {
	if e.db == nil {
		return false
	}
	return e.db.IsBlocked(ip)
}

// ---------- Website Blocking ----------

// BlockWebsite blocks a domain via iptables string matching.
func (e *Engine) BlockWebsite(domain, reason string) (models.WebsiteBlock, error) {
	if domain == "" {
		return models.WebsiteBlock{}, fmt.Errorf("domain cannot be empty")
	}
	// Sanitize domain
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimRight(domain, "/")

	entry := e.db.AddWebsiteBlock(domain, reason)

	if e.liveMode {
		if err := e.syncLiveConfig(); err != nil {
			e.logger.Log("ERROR", "-", "-", "-", fmt.Sprintf("%s website block apply failed: %v", e.backend, err))
		}
	}

	e.logger.Log("BLOCK", "-", "-", "-", fmt.Sprintf("Website blocked: %s (%s)", domain, reason))
	e.logger.EmitFirewallEvent(models.FirewallEvent{
		EventType: "policy_apply",
		Backend:   e.backend,
		Action:    "BLOCK",
		Detail:    fmt.Sprintf("Website blocked: %s (%s)", domain, reason),
		Severity:  "warning",
	})
	return entry, nil
}

// UnblockWebsite removes a website block.
func (e *Engine) UnblockWebsite(domain string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if !e.db.RemoveWebsiteBlock(domain) {
		return fmt.Errorf("website %s not in blocklist", domain)
	}

	if e.liveMode {
		if err := e.syncLiveConfig(); err != nil {
			e.logger.Log("ERROR", "-", "-", "-", fmt.Sprintf("%s website unblock apply failed: %v", e.backend, err))
		}
	}

	e.logger.Log("UNBLOCK", "-", "-", "-", fmt.Sprintf("Website unblocked: %s", domain))
	e.logger.EmitFirewallEvent(models.FirewallEvent{
		EventType: "policy_apply",
		Backend:   e.backend,
		Action:    "UNBLOCK",
		Detail:    fmt.Sprintf("Website unblocked: %s", domain),
		Severity:  "info",
	})
	return nil
}

// ListWebsiteBlocks returns all blocked websites.
func (e *Engine) ListWebsiteBlocks() []models.WebsiteBlock {
	return e.db.ListWebsiteBlocks()
}

// FirewallLogs returns backend-native rule/log state output for visibility.
func (e *Engine) FirewallLogs(limit int) []string {
	if limit <= 0 {
		limit = 200
	}
	e.mu.RLock()
	backend := e.backend
	live := e.liveMode
	e.mu.RUnlock()
	if !live {
		return []string{"firewall engine is in memory mode"}
	}

	var cmd *exec.Cmd
	switch backend {
	case engineNFTables:
		cmd = exec.Command("nft", "list", "ruleset")
	case engineUFW:
		cmd = exec.Command("ufw", "status", "numbered")
	default:
		cmd = exec.Command("iptables", "-S")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return []string{fmt.Sprintf("failed to read %s logs: %v", backend, err)}
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return lines
}

// TrafficVisibility returns a lightweight network visibility snapshot.
func (e *Engine) TrafficVisibility(limit int) models.TrafficVisibility {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	entries := e.logger.RecentEntries(limit)
	conns := e.ActiveConnections()

	protoCounts := make(map[string]int)
	remoteCounts := make(map[string]int)
	portCounts := make(map[string]int)
	blocked := 0
	allowed := 0

	uniqueRemote := make(map[string]struct{})
	for _, c := range conns {
		if c.RemoteIP != "" && c.RemoteIP != "0.0.0.0" && c.RemoteIP != "::" {
			uniqueRemote[c.RemoteIP] = struct{}{}
		}
		if c.Protocol != "" {
			protoCounts[strings.ToUpper(c.Protocol)]++
		}
		if c.RemoteIP != "" {
			remoteCounts[c.RemoteIP]++
		}
		if c.RemotePort != "" {
			portCounts[c.RemotePort]++
		}
	}

	for _, e := range entries {
		action := strings.ToUpper(e.Action)
		switch {
		case action == "BLOCK" || action == "DROP" || action == "REJECT":
			blocked++
		case action == "ALLOW" || action == "ACCEPT":
			allowed++
		}
	}

	e.mu.RLock()
	backend := e.backend
	e.mu.RUnlock()
	topRemote := topCounts(remoteCounts, 10)
	resolved := make([]models.ResolvedPeer, 0, len(topRemote))
	for i, item := range topRemote {
		if i >= 8 {
			break
		}
		host, verified := e.resolveHostDetailed(item.Name)
		resolved = append(resolved, models.ResolvedPeer{
			IP:    item.Name,
			Host:  host,
			Count: item.Count,
			Verified: verified,
		})
	}

	return models.TrafficVisibility{
		CaptureSource:       fmt.Sprintf("%s + /proc net sniffer", backend),
		ActiveConnections:   len(conns),
		UniqueRemoteIPs:     len(uniqueRemote),
		TopProtocols:        topCounts(protoCounts, 6),
		TopRemoteIPs:        topRemote,
		TopDestinationPorts: topCounts(portCounts, 10),
		ResolvedPeers:       resolved,
		RecentBlocked:       blocked,
		RecentAllowed:       allowed,
	}
}

func (e *Engine) resolveHost(ip string) string {
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return "-"
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "-"
	}
	if parsed.IsLoopback() || parsed.IsPrivate() {
		return "local/private"
	}

	now := time.Now()
	e.dnsMu.Lock()
	e.lookupsTotal++
	e.dnsMu.Unlock()

	e.dnsMu.RLock()
	if ent, ok := e.dnsCache[ip]; ok && ent.expires.After(now) {
		e.dnsMu.RUnlock()
		e.dnsMu.Lock()
		e.cacheHits++
		e.dnsMu.Unlock()
		return ent.host
	}
	e.dnsMu.RUnlock()
	e.dnsMu.Lock()
	e.cacheMisses++
	e.dnsMu.Unlock()

	host := "unresolved"
	verified := false
	if e.nslookup != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
		defer cancel()
		out, err := exec.CommandContext(ctx, e.nslookup, ip).CombinedOutput()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				l := strings.TrimSpace(line)
				if strings.Contains(l, "name =") {
					parts := strings.SplitN(l, "=", 2)
					if len(parts) == 2 {
						host = strings.TrimSuffix(strings.TrimSpace(parts[1]), ".")
						break
					}
				}
				if strings.HasPrefix(strings.ToLower(l), "name:") {
					host = strings.TrimSpace(strings.TrimPrefix(l, "Name:"))
					host = strings.TrimSpace(strings.TrimPrefix(host, "name:"))
					host = strings.TrimSuffix(host, ".")
					break
				}
			}
		}
	}

	if host == "unresolved" {
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			host = strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
		}
	}

	if host != "unresolved" && host != "local/private" && host != "-" {
		if ips, err := net.LookupHost(host); err == nil {
			for _, resolvedIP := range ips {
				if resolvedIP == ip {
					verified = true
					break
				}
			}
		}
	}

	if verified {
		e.dnsMu.Lock()
		e.verifiedPTR++
		e.dnsMu.Unlock()
	} else if host == "unresolved" {
		e.dnsMu.Lock()
		e.unresolved++
		e.dnsMu.Unlock()
	}

	e.dnsMu.Lock()
	e.dnsCache[ip] = dnsCacheEntry{host: host, verified: verified, expires: now.Add(10 * time.Minute)}
	e.dnsMu.Unlock()
	e.logger.EmitFirewallEvent(models.FirewallEvent{
		EventType: "dns_lookup",
		Backend:   e.backend,
		Action:    "RESOLVE",
		SrcIP:     ip,
		Detail:    fmt.Sprintf("host=%s verified=%t", host, verified),
		Severity:  "info",
	})
	return host
}

func (e *Engine) resolveHostDetailed(ip string) (string, bool) {
	h := e.resolveHost(ip)
	e.dnsMu.RLock()
	defer e.dnsMu.RUnlock()
	if ent, ok := e.dnsCache[ip]; ok {
		return h, ent.verified
	}
	return h, false
}

// DNSStats returns DNS cache and lookup effectiveness metrics.
func (e *Engine) DNSStats() models.DNSStats {
	e.dnsMu.RLock()
	defer e.dnsMu.RUnlock()
	return models.DNSStats{
		LookupsTotal: e.lookupsTotal,
		CacheHits:    e.cacheHits,
		CacheMisses:  e.cacheMisses,
		VerifiedPTR:  e.verifiedPTR,
		Unresolved:   e.unresolved,
		CacheEntries: len(e.dnsCache),
	}
}

// ClearDNSCache clears cached DNS results and related counters.
func (e *Engine) ClearDNSCache() {
	e.dnsMu.Lock()
	e.dnsCache = make(map[string]dnsCacheEntry)
	e.dnsMu.Unlock()
	e.logger.EmitFirewallEvent(models.FirewallEvent{EventType: "dns_lookup", Backend: e.backend, Action: "CLEAR_CACHE", Detail: "DNS cache cleared", Severity: "warning"})
}

// RefreshDNS resolves a list of IPs and refreshes cache entries.
func (e *Engine) RefreshDNS(ips []string) []models.ResolvedPeer {
	out := make([]models.ResolvedPeer, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		host, verified := e.resolveHostDetailed(ip)
		out = append(out, models.ResolvedPeer{IP: ip, Host: host, Verified: verified, Count: 0})
	}
	return out
}

// ---------- Statistics ----------

// Stats computes dashboard statistics including real OS metrics.
func (e *Engine) Stats() models.DashboardStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	active := 0
	for _, r := range e.rules {
		if r.Enabled {
			active++
		}
	}

	blocked, allowed := e.logger.TodayCounts()
	conns := len(e.ActiveConnections())

	// Gather real OS system info
	si := sysinfo.Gather()

	return models.DashboardStats{
		TotalRules:        len(e.rules),
		ActiveRules:       active,
		BlockedToday:      blocked,
		AllowedToday:      allowed,
		ActiveConnections: conns,
		Hostname:          si.Hostname,
		OS:                si.OS,
		Kernel:            si.Kernel,
		Uptime:            si.Uptime,
		UptimeSec:         si.UptimeSec,
		CPUUsage:          si.CPUUsage,
		CPUCores:          si.CPUCores,
		MemTotal:          si.MemTotal,
		MemUsed:           si.MemUsed,
		MemPercent:        si.MemPercent,
		SwapTotal:         si.SwapTotal,
		SwapUsed:          si.SwapUsed,
		LoadAvg:           si.LoadAvg,
		NetRxBytes:        si.NetRxBytes,
		NetTxBytes:        si.NetTxBytes,
		FirewallEngine:    e.backend,
		EngineLiveMode:    e.liveMode,
	}
}

// ActiveConnections reads /proc/net/tcp, tcp6, and udp to list real connections.
func (e *Engine) ActiveConnections() []models.Connection {
	conns := make([]models.Connection, 0)

	// Read TCP, TCP6, and UDP from /proc/net
	procFiles := []struct {
		path     string
		protocol string
	}{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp6"},
	}

	for _, pf := range procFiles {
		parsed := parseProcNet(pf.path, pf.protocol)
		conns = append(conns, parsed...)
	}

	return conns
}

// parseProcNet reads a /proc/net/* file and returns parsed connections.
func parseProcNet(path, protocol string) []models.Connection {
	var conns []models.Connection
	file, err := os.Open(path)
	if err != nil {
		return conns
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip header

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localIP, localPort := parseHexAddr(fields[1])
		remoteIP, remotePort := parseHexAddr(fields[2])
		state := tcpState(fields[3])

		conns = append(conns, models.Connection{
			Protocol:   protocol,
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      state,
		})
	}
	return conns
}

// ---------- Firewall backend interaction ----------

func (e *Engine) syncLiveConfig() error {
	e.mu.RLock()
	rules := make([]models.Rule, len(e.rules))
	copy(rules, e.rules)
	backend := e.backend
	e.mu.RUnlock()

	if !e.liveMode || backend == engineMemory {
		return nil
	}
	if err := e.flushBackend(backend); err != nil {
		e.setLastError(err.Error())
		return err
	}

	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if err := e.applyRuleBackend(backend, r); err != nil {
			e.setLastError(err.Error())
			return err
		}
	}

	if e.db != nil {
		for _, b := range e.db.ListBlockedIPs() {
			if err := e.applyIPBlockBackend(backend, b.IP); err != nil {
				e.setLastError(err.Error())
				return err
			}
		}
		for _, w := range e.db.ListWebsiteBlocks() {
			if !w.Enabled {
				continue
			}
			if err := e.applyWebsiteBlockBackend(backend, w.Domain); err != nil {
				e.setLastError(err.Error())
				return err
			}
		}
	}
	e.setLastError("")
	return nil
}

func (e *Engine) flushBackend(backend string) error {
	switch backend {
	case engineNFTables:
		_ = e.runCommand("nft", "flush", "table", "inet", "kaliwall")
		_ = e.runCommand("nft", "delete", "table", "inet", "kaliwall")
		if err := e.runCommand("nft", "add", "table", "inet", "kaliwall"); err != nil {
			return err
		}
		for _, chain := range []string{"input", "output", "forward"} {
			if err := e.runCommand("nft", "add", "chain", "inet", "kaliwall", chain, "{", "type", "filter", "hook", chain, "priority", "0", ";", "policy", "accept", ";", "}"); err != nil {
				return err
			}
		}
		return nil
	case engineUFW:
		_ = e.runCommand("ufw", "--force", "reset")
		if err := e.runCommand("ufw", "--force", "enable"); err != nil {
			return err
		}
		return nil
	default:
		for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			if err := e.runCommand("iptables", "-F", chain); err != nil {
				return err
			}
		}
		return nil
	}
}

func (e *Engine) applyRuleBackend(backend string, r models.Rule) error {
	switch backend {
	case engineNFTables:
		return e.runCommand("nft", buildNFTRuleArgs(r)...)
	case engineUFW:
		return e.runCommand("ufw", buildUFWRuleArgs(r)...)
	default:
		return e.runCommand("iptables", buildIPTablesArgs("-A", r)...)
	}
}

func (e *Engine) applyIPBlockBackend(backend, ip string) error {
	switch backend {
	case engineNFTables:
		if err := e.runCommand("nft", "add", "rule", "inet", "kaliwall", "input", "ip", "saddr", ip, "drop"); err != nil {
			return err
		}
		if err := e.runCommand("nft", "add", "rule", "inet", "kaliwall", "output", "ip", "daddr", ip, "drop"); err != nil {
			return err
		}
		return nil
	case engineUFW:
		if err := e.runCommand("ufw", "deny", "from", ip); err != nil {
			return err
		}
		if err := e.runCommand("ufw", "deny", "to", ip); err != nil {
			return err
		}
		return nil
	default:
		if err := e.runCommand("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"); err != nil {
			return err
		}
		if err := e.runCommand("iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"); err != nil {
			return err
		}
		if err := e.runCommand("iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"); err != nil {
			return err
		}
		return e.runCommand("iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP")
	}
}

func (e *Engine) applyWebsiteBlockBackend(backend, domain string) error {
	switch backend {
	case engineNFTables:
		// nft payload string matching is distro-specific; use a comment marker entry.
		return e.runCommand("nft", "add", "rule", "inet", "kaliwall", "output", "meta", "l4proto", "{", "tcp", ",", "udp", "}", "counter", "comment", "kaliwall-domain:"+domain)
	case engineUFW:
		// UFW cannot match HTTP host names at kernel level; log intent for visibility.
		e.logger.Log("INFO", "-", "-", "dns", fmt.Sprintf("UFW domain policy staged: %s", domain))
		return nil
	default:
		if err := e.runCommand("iptables", "-A", "OUTPUT", "-m", "string", "--string", domain, "--algo", "kmp", "-j", "DROP"); err != nil {
			return err
		}
		return e.runCommand("iptables", "-A", "FORWARD", "-m", "string", "--string", domain, "--algo", "kmp", "-j", "DROP")
	}
}

func (e *Engine) runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (e *Engine) setLastError(msg string) {
	e.mu.Lock()
	e.lastError = msg
	e.mu.Unlock()
}

func buildIPTablesArgs(op string, r models.Rule) []string {
	args := []string{op, r.Chain}
	if state := normalizeConnectionState(r.ConnectionState); state != "any" {
		args = append(args, "-m", "conntrack", "--ctstate", state)
	}
	if r.Protocol != "" && r.Protocol != "all" {
		args = append(args, "-p", r.Protocol)
	}
	if r.SrcIP != "" && r.SrcIP != "any" {
		args = append(args, "-s", r.SrcIP)
	}
	if r.DstIP != "" && r.DstIP != "any" {
		args = append(args, "-d", r.DstIP)
	}
	if r.DstPort != "" && r.DstPort != "any" {
		args = append(args, "--dport", r.DstPort)
	}
	if r.SrcPort != "" && r.SrcPort != "any" {
		args = append(args, "--sport", r.SrcPort)
	}
	args = append(args, "-j", r.Action)
	if r.Comment != "" {
		args = append(args, "-m", "comment", "--comment", r.Comment)
	}
	return args
}

func buildUFWRuleArgs(r models.Rule) []string {
	action := strings.ToLower(r.Action)
	if action == "accept" {
		action = "allow"
	}
	if action == "reject" {
		action = "deny"
	}
	args := []string{"--force", action}
	if strings.EqualFold(r.Chain, "OUTPUT") {
		args = append(args, "out")
	} else if strings.EqualFold(r.Chain, "FORWARD") {
		args = append(args, "route")
	} else {
		args = append(args, "in")
	}

	from := "any"
	to := "any"
	if r.SrcIP != "" && r.SrcIP != "any" {
		from = r.SrcIP
	}
	if r.DstIP != "" && r.DstIP != "any" {
		to = r.DstIP
	}
	args = append(args, "from", from, "to", to)

	if r.DstPort != "" && r.DstPort != "any" {
		args = append(args, "port", r.DstPort)
	}
	if r.Protocol != "" && r.Protocol != "all" {
		args = append(args, "proto", r.Protocol)
	}
	return args
}

func buildNFTRuleArgs(r models.Rule) []string {
	chain := strings.ToLower(r.Chain)
	args := []string{"add", "rule", "inet", "kaliwall", chain}
	if state := normalizeConnectionState(r.ConnectionState); state != "any" {
		args = append(args, "ct", "state", strings.ToLower(state))
	}
	if r.SrcIP != "" && r.SrcIP != "any" {
		args = append(args, "ip", "saddr", r.SrcIP)
	}
	if r.DstIP != "" && r.DstIP != "any" {
		args = append(args, "ip", "daddr", r.DstIP)
	}
	if r.Protocol != "" && r.Protocol != "all" {
		switch strings.ToLower(r.Protocol) {
		case "tcp", "udp":
			args = append(args, r.Protocol)
			if r.SrcPort != "" && r.SrcPort != "any" {
				args = append(args, "sport", r.SrcPort)
			}
			if r.DstPort != "" && r.DstPort != "any" {
				args = append(args, "dport", r.DstPort)
			}
		case "icmp":
			args = append(args, "ip", "protocol", "icmp")
		}
	}
	args = append(args, strings.ToLower(r.Action))
	return args
}

// ---------- Validation ----------

var validChains = map[string]bool{"INPUT": true, "OUTPUT": true, "FORWARD": true}
var validActions = map[string]bool{"ACCEPT": true, "DROP": true, "REJECT": true}
var validProtocols = map[string]bool{"tcp": true, "udp": true, "icmp": true, "all": true}
var validConnectionStates = map[string]bool{"ANY": true, "NEW": true, "ESTABLISHED": true, "RELATED": true, "INVALID": true}
var portRegex = regexp.MustCompile(`^(\d{1,5}|any)$`)

func validateRuleRequest(req models.RuleRequest) error {
	chain := strings.ToUpper(req.Chain)
	if !validChains[chain] {
		return fmt.Errorf("invalid chain: %s (must be INPUT, OUTPUT, or FORWARD)", req.Chain)
	}
	action := strings.ToUpper(req.Action)
	if !validActions[action] {
		return fmt.Errorf("invalid action: %s (must be ACCEPT, DROP, or REJECT)", req.Action)
	}
	proto := strings.ToLower(req.Protocol)
	if !validProtocols[proto] {
		return fmt.Errorf("invalid protocol: %s (must be tcp, udp, icmp, or all)", req.Protocol)
	}
	connState := strings.ToUpper(normalizeConnectionState(req.ConnectionState))
	if !validConnectionStates[connState] {
		return fmt.Errorf("invalid connection_state: %s (must be any, NEW, ESTABLISHED, RELATED, or INVALID)", req.ConnectionState)
	}
	// Validate IP addresses (basic)
	if req.SrcIP != "any" && req.SrcIP != "" {
		if !isValidCIDROrIP(req.SrcIP) {
			return fmt.Errorf("invalid source IP: %s", req.SrcIP)
		}
	}
	if req.DstIP != "any" && req.DstIP != "" {
		if !isValidCIDROrIP(req.DstIP) {
			return fmt.Errorf("invalid destination IP: %s", req.DstIP)
		}
	}
	// Validate ports
	if req.SrcPort != "" && !portRegex.MatchString(req.SrcPort) {
		return fmt.Errorf("invalid source port: %s", req.SrcPort)
	}
	if req.DstPort != "" && !portRegex.MatchString(req.DstPort) {
		return fmt.Errorf("invalid destination port: %s", req.DstPort)
	}
	return nil
}

// ValidateRuleRequest exposes rule payload validation for API pre-checks.
func ValidateRuleRequest(req models.RuleRequest) error {
	return validateRuleRequest(req)
}

func isValidCIDROrIP(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// ---------- Helpers ----------

func normalise(v string) string {
	if v == "" {
		return "any"
	}
	return v
}

func normalizeConnectionState(v string) string {
	v = strings.TrimSpace(strings.ToUpper(v))
	if v == "" {
		return "any"
	}
	if v == "ANY" {
		return "any"
	}
	return v
}

func topCounts(counts map[string]int, limit int) []models.NameCount {
	items := make([]models.NameCount, 0, len(counts))
	for name, c := range counts {
		if name == "" {
			continue
		}
		items = append(items, models.NameCount{Name: name, Count: c})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Name < items[j].Name
		}
		return items[i].Count > items[j].Count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

// parseHexAddr converts /proc/net/tcp hex address (e.g. "0100007F:0050") to IP and port.
func parseHexAddr(s string) (string, string) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return s, ""
	}
	var ip string
	if len(parts[0]) == 8 {
		a := hexToByte(parts[0][6:8])
		b := hexToByte(parts[0][4:6])
		c := hexToByte(parts[0][2:4])
		d := hexToByte(parts[0][0:2])
		ip = fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
	} else {
		ip = parts[0]
	}
	port := fmt.Sprintf("%d", hexToUint16(parts[1]))
	return ip, port
}

func hexToByte(h string) byte {
	var b byte
	fmt.Sscanf(h, "%x", &b)
	return b
}

func hexToUint16(h string) uint16 {
	var v uint16
	fmt.Sscanf(h, "%x", &v)
	return v
}

// tcpState maps hex state code from /proc/net/tcp to human-readable string.
func tcpState(hex string) string {
	states := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING",
	}
	if s, ok := states[strings.ToUpper(hex)]; ok {
		return s
	}
	return hex
}

