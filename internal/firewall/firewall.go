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
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"kaliwall/internal/database"
	"kaliwall/internal/logger"
	"kaliwall/internal/models"
	"kaliwall/internal/sysinfo"
)

// Engine is the core firewall management component.
type Engine struct {
	mu       sync.RWMutex
	rules    []models.Rule
	logger   *logger.TrafficLogger
	db       *database.Store
	liveMode bool // true when running as root on Linux with iptables available
}

// New creates a new firewall engine and detects whether live iptables mode is available.
func New(l *logger.TrafficLogger, db *database.Store) *Engine {
	e := &Engine{
		rules:  make([]models.Rule, 0),
		logger: l,
		db:     db,
	}
	e.detectMode()

	// Load persisted rules from database
	if db != nil {
		saved := db.LoadRules()
		if len(saved) > 0 {
			e.rules = saved
			fmt.Printf("[+] Restored %d rules from database\n", len(saved))
			if e.liveMode {
				for _, r := range saved {
					if r.Enabled {
						e.applyRule(r)
					}
				}
			}
		}
		// Re-apply blocked IPs
		blocked := db.ListBlockedIPs()
		if e.liveMode && len(blocked) > 0 {
			for _, b := range blocked {
				applyIPBlock(b.IP)
			}
			fmt.Printf("[+] Re-applied %d IP blocks\n", len(blocked))
		}
		// Re-apply website blocks
		websites := db.ListWebsiteBlocks()
		if e.liveMode && len(websites) > 0 {
			for _, w := range websites {
				if w.Enabled {
					applyWebsiteBlock(w.Domain)
				}
			}
			fmt.Printf("[+] Re-applied %d website blocks\n", len(websites))
		}
	}

	return e
}

// detectMode checks if iptables is available and we have root privileges.
func (e *Engine) detectMode() {
	if os.Getuid() != 0 {
		fmt.Println("[!] Not running as root — rules stored in-memory only")
		e.liveMode = false
		return
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		fmt.Println("[!] iptables not found — rules stored in-memory only")
		e.liveMode = false
		return
	}
	fmt.Println("[+] Running as root with iptables — live mode enabled")
	e.liveMode = true
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

	// Apply to iptables if live
	if e.liveMode && rule.Enabled {
		if err := e.applyRule(rule); err != nil {
			e.logger.Log("ERROR", "-", "-", "-", fmt.Sprintf("iptables apply failed: %v", err))
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
	defer e.mu.Unlock()

	idx := -1
	for i, r := range e.rules {
		if r.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("rule %s not found", id)
	}

	rule := e.rules[idx]

	// Remove from iptables if live
	if e.liveMode && rule.Enabled {
		e.removeIPTablesRule(rule)
	}

	e.rules = append(e.rules[:idx], e.rules[idx+1:]...)
	e.logger.Log("CONFIG", "-", "-", "-", fmt.Sprintf("Rule removed: %s", id))

	// Persist
	if e.db != nil {
		rulesCopy := make([]models.Rule, len(e.rules))
		copy(rulesCopy, e.rules)
		go e.db.SaveRules(rulesCopy)
	}

	return nil
}

// ToggleRule enables or disables a rule by ID.
func (e *Engine) ToggleRule(id string) (models.Rule, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, r := range e.rules {
		if r.ID == id {
			e.rules[i].Enabled = !e.rules[i].Enabled
			if e.liveMode {
				if e.rules[i].Enabled {
					e.applyRule(e.rules[i])
				} else {
					e.removeIPTablesRule(e.rules[i])
				}
			}
			// Persist
			if e.db != nil {
				rulesCopy := make([]models.Rule, len(e.rules))
				copy(rulesCopy, e.rules)
				go e.db.SaveRules(rulesCopy)
			}
			return e.rules[i], nil
		}
	}
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
	defer e.mu.Unlock()

	for i, r := range e.rules {
		if r.ID == id {
			// Remove old iptables rule if live
			if e.liveMode && r.Enabled {
				e.removeIPTablesRule(r)
			}

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

			// Re-apply if live and enabled
			if e.liveMode && e.rules[i].Enabled {
				e.applyRule(e.rules[i])
			}

			// Persist
			if e.db != nil {
				rulesCopy := make([]models.Rule, len(e.rules))
				copy(rulesCopy, e.rules)
				go e.db.SaveRules(rulesCopy)
			}

			e.logger.Log("CONFIG", "-", "-", "-",
				fmt.Sprintf("Rule updated: %s %s %s [%s]",
					e.rules[i].Action, e.rules[i].Chain, e.rules[i].Protocol, e.rules[i].Comment))

			return e.rules[i], nil
		}
	}
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
		applyIPBlock(ip)
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
		removeIPBlock(ip)
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

func applyIPBlock(ip string) {
	exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP").Run()
	exec.Command("iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP").Run()
	exec.Command("iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP").Run()
	exec.Command("iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP").Run()
}

func removeIPBlock(ip string) {
	exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
	exec.Command("iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP").Run()
	exec.Command("iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP").Run()
	exec.Command("iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP").Run()
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
		applyWebsiteBlock(domain)
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
		removeWebsiteBlock(domain)
	}

	e.logger.Log("UNBLOCK", "-", "-", "-", fmt.Sprintf("Website unblocked: %s", domain))
	return nil
}

// ListWebsiteBlocks returns all blocked websites.
func (e *Engine) ListWebsiteBlocks() []models.WebsiteBlock {
	return e.db.ListWebsiteBlocks()
}

func applyWebsiteBlock(domain string) {
	// Block outgoing traffic containing the domain string (HTTP Host / SNI)
	exec.Command("iptables", "-A", "OUTPUT", "-m", "string",
		"--string", domain, "--algo", "kmp", "-j", "DROP").Run()
	exec.Command("iptables", "-A", "FORWARD", "-m", "string",
		"--string", domain, "--algo", "kmp", "-j", "DROP").Run()
}

func removeWebsiteBlock(domain string) {
	exec.Command("iptables", "-D", "OUTPUT", "-m", "string",
		"--string", domain, "--algo", "kmp", "-j", "DROP").Run()
	exec.Command("iptables", "-D", "FORWARD", "-m", "string",
		"--string", domain, "--algo", "kmp", "-j", "DROP").Run()
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

// ---------- iptables interaction ----------

// applyRule translates a Rule into an iptables -A command and executes it.
func (e *Engine) applyRule(r models.Rule) error {
	args := buildIPTablesArgs("-A", r)
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

// removeIPTablesRule translates a Rule into an iptables -D command and executes it.
func (e *Engine) removeIPTablesRule(r models.Rule) {
	args := buildIPTablesArgs("-D", r)
	cmd := exec.Command("iptables", args...)
	cmd.CombinedOutput() // best-effort removal
}

// buildIPTablesArgs creates the argument slice for an iptables command.
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

