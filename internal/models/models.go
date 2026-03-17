// Package models defines data structures used across KaliWall.
package models

import "time"

// Rule represents a single firewall rule.
type Rule struct {
	ID        string    `json:"id"`
	Chain     string    `json:"chain"`     // INPUT, OUTPUT, FORWARD
	Protocol  string    `json:"protocol"`  // tcp, udp, icmp, all
	SrcIP     string    `json:"src_ip"`    // Source IP/CIDR ("any" for all)
	DstIP     string    `json:"dst_ip"`    // Destination IP/CIDR ("any" for all)
	SrcPort   string    `json:"src_port"`  // Source port ("any" for all)
	DstPort   string    `json:"dst_port"`  // Destination port ("any" for all)
	Action    string    `json:"action"`    // ACCEPT, DROP, REJECT
	Comment   string    `json:"comment"`   // Human-readable description
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// RuleRequest is the payload for creating/updating a rule via the API.
type RuleRequest struct {
	Chain    string `json:"chain"`
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  string `json:"src_port"`
	DstPort  string `json:"dst_port"`
	Action   string `json:"action"`
	Comment  string `json:"comment"`
	Enabled  bool   `json:"enabled"`
}

// TrafficEntry represents a single logged traffic event.
type TrafficEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // ALLOW, BLOCK, REJECT
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	Protocol  string    `json:"protocol"`
	Detail    string    `json:"detail"`
}

// Connection represents an active network connection (from /proc/net).
type Connection struct {
	Protocol string `json:"protocol"`
	LocalIP  string `json:"local_ip"`
	LocalPort string `json:"local_port"`
	RemoteIP  string `json:"remote_ip"`
	RemotePort string `json:"remote_port"`
	State     string `json:"state"`
}

// DashboardStats holds summary statistics for the web UI dashboard.
type DashboardStats struct {
	TotalRules        int     `json:"total_rules"`
	ActiveRules       int     `json:"active_rules"`
	BlockedToday      int     `json:"blocked_today"`
	AllowedToday      int     `json:"allowed_today"`
	ActiveConnections int     `json:"active_connections"`
	Hostname          string  `json:"hostname"`
	OS                string  `json:"os"`
	Kernel            string  `json:"kernel"`
	Uptime            string  `json:"uptime"`
	UptimeSec         float64 `json:"uptime_seconds"`
	CPUUsage          float64 `json:"cpu_usage_percent"`
	CPUCores          int     `json:"cpu_cores"`
	MemTotal          uint64  `json:"mem_total_bytes"`
	MemUsed           uint64  `json:"mem_used_bytes"`
	MemPercent        float64 `json:"mem_usage_percent"`
	SwapTotal         uint64  `json:"swap_total_bytes"`
	SwapUsed          uint64  `json:"swap_used_bytes"`
	LoadAvg           string  `json:"load_average"`
	NetRxBytes        uint64  `json:"net_rx_bytes"`
	NetTxBytes        uint64  `json:"net_tx_bytes"`
	FirewallEngine    string  `json:"firewall_engine"`
	EngineLiveMode    bool    `json:"engine_live_mode"`
}

// FirewallEngineInfo reports detected and active packet-filter engines.
type FirewallEngineInfo struct {
	CurrentEngine  string   `json:"current_engine"`
	Available      []string `json:"available_engines"`
	LiveMode       bool     `json:"live_mode"`
	Root           bool     `json:"root"`
	LastError      string   `json:"last_error,omitempty"`
}

// NameCount is a generic counter item used for protocol/IP/port summaries.
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// TrafficVisibility provides low-overhead packet/flow visibility for the UI.
type TrafficVisibility struct {
	CaptureSource      string      `json:"capture_source"`
	ActiveConnections  int         `json:"active_connections"`
	UniqueRemoteIPs    int         `json:"unique_remote_ips"`
	TopProtocols       []NameCount `json:"top_protocols"`
	TopRemoteIPs       []NameCount `json:"top_remote_ips"`
	TopDestinationPorts []NameCount `json:"top_destination_ports"`
	RecentBlocked      int         `json:"recent_blocked"`
	RecentAllowed      int         `json:"recent_allowed"`
}

// BlockedIP represents a manually blocked IP address.
type BlockedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// WebsiteBlock represents a blocked domain/website.
type WebsiteBlock struct {
	Domain    string    `json:"domain"`
	Reason    string    `json:"reason"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// ThreatCacheEntry is a VT cache item for display in the threat intel dashboard.
type ThreatCacheEntry struct {
	IP           string  `json:"ip"`
	ThreatLevel  string  `json:"threat_level"`
	Malicious    int     `json:"malicious"`
	Suspicious   int     `json:"suspicious"`
	Harmless     int     `json:"harmless"`
	Reputation   int     `json:"reputation"`
	Country      string  `json:"country"`
	Owner        string  `json:"owner"`
	CheckedAt    string  `json:"checked_at"`
	HasConnection bool  `json:"has_connection"`
	IsBlocked    bool    `json:"is_blocked"`
}

// APIResponse wraps all API responses with a consistent envelope.
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}
