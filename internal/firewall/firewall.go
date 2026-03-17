// Package firewall manages iptables/nftables rule application and in-memory rule storage.
// On Linux with root privileges it executes real iptables commands.
// Otherwise it operates in demo mode with in-memory rules only.
package firewall

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
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
}

// New creates a new firewall engine and detects whether live iptables mode is available.
func New(l *logger.TrafficLogger, db *database.Store) *Engine {
	e := &Engine{rules: make([]models.Rule, 0), logger: l, db: db, backend: engineMemory}
	e.detectMode()

	// Load persisted rules from database
	if db != nil {
		saved := db.LoadRules()
		if len(saved) > 0 {
			e.rules = saved
			fmt.Printf("[+] Restored %d rules from database\n", len(saved))
		}
	}

	if e.liveMode {
		e.syncLiveConfig()
	}

	return e
}

// detectMode checks available firewall backends and whether live mode is possible.
func (e *Engine) detectMode() {
	e.root = os.Getuid() == 0
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
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.root {
		return fmt.Errorf("switching backend requires root")
	}
	if name == "" || name == engineMemory {
		e.backend = engineMemory
		e.liveMode = false
		e.lastError = ""
		return nil
	}
	ok := false
	for _, a := range e.available {
		if a == name {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("backend %s is not available", name)
	}
	e.backend = name
	e.liveMode = true
	e.lastError = ""
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
	needsSync := e.liveMode && e.rules[idx].Enabled

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
			return result, nil
		}
	}
	e.mu.Unlock()
	return models.Rule{}, fmt.Errorf("rule %s not found", id)
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

	entry := e.db.AddBlockedIP(ip, reason)

	if e.liveMode {
		if err := e.syncLiveConfig(); err != nil {
			e.logger.Log("ERROR", ip, "-", "-", fmt.Sprintf("%s IP block apply failed: %v", e.backend, err))
		}
	}

	e.logger.Log("BLOCK", ip, "-", "-", fmt.Sprintf("IP blocked: %s (%s)", ip, reason))
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

	return models.TrafficVisibility{
		CaptureSource:       fmt.Sprintf("%s + /proc net sniffer", backend),
		ActiveConnections:   len(conns),
		UniqueRemoteIPs:     len(uniqueRemote),
		TopProtocols:        topCounts(protoCounts, 6),
		TopRemoteIPs:        topCounts(remoteCounts, 10),
		TopDestinationPorts: topCounts(portCounts, 10),
		RecentBlocked:       blocked,
		RecentAllowed:       allowed,
	}
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

