package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"kaliwall/internal/logger"
	"kaliwall/internal/models"
	"kaliwall/internal/threatintel"
)

const blockReasonMaliciousDomain = "Malicious Domain"

// EscalationConfig controls automatic source-IP blocking when VT score is high.
type EscalationConfig struct {
	Enabled                 bool
	VTMaliciousThreshold    int
	AllowPrivateIPBlock     bool
}

// EscalationResult describes whether auto-escalation was triggered.
type EscalationResult struct {
	Enabled     bool   `json:"enabled"`
	Triggered   bool   `json:"triggered"`
	Reason      string `json:"reason"`
	Threshold   int    `json:"threshold"`
	DomainScore int    `json:"domain_score"`
	URLScore    int    `json:"url_score"`
	AppliedIP   string `json:"applied_ip,omitempty"`
}

type sourceIPBlocker interface {
	BlockIP(ip, reason string) (models.BlockedIP, error)
	IsIPBlocked(ip string) bool
}

// BlockedEvent is a machine-readable blocked-request record.
type BlockedEvent struct {
	EventID    string    `json:"event_id"`
	Timestamp  time.Time `json:"timestamp"`
	Reason     string    `json:"reason"`
	AttackerIP string    `json:"attacker_ip"`
	Domain     string    `json:"domain"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	UserAgent  string    `json:"user_agent"`
	VirusTotal threatintel.DomainURLAssessment `json:"virustotal"`
	Escalation EscalationResult `json:"escalation"`
}

// BlockedEventLogger appends blocked events as JSON lines.
type BlockedEventLogger struct {
	mu      sync.Mutex
	file    *os.File
	entries []BlockedEvent
}

// NewBlockedEventLogger creates/open log file used for blocked request events.
func NewBlockedEventLogger(path string) (*BlockedEventLogger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("blocked event log path cannot be empty")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open blocked event log: %w", err)
	}
	return &BlockedEventLogger{file: f, entries: make([]BlockedEvent, 0, 4096)}, nil
}

// Close closes the underlying file handle.
func (l *BlockedEventLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Log appends a blocked event to file in NDJSON format.
func (l *BlockedEventLogger) Log(ev BlockedEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal blocked event: %w", err)
	}
	if _, err := fmt.Fprintf(l.file, "%s\n", line); err != nil {
		return fmt.Errorf("write blocked event: %w", err)
	}
	if len(l.entries) >= 10000 {
		l.entries = l.entries[1:]
	}
	l.entries = append(l.entries, ev)
	return nil
}

// Recent returns newest blocked events.
func (l *BlockedEventLogger) Recent(limit int) []BlockedEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit <= 0 || limit > len(l.entries) {
		limit = len(l.entries)
	}
	start := len(l.entries) - limit
	out := make([]BlockedEvent, limit)
	copy(out, l.entries[start:])
	return out
}

// FirewallProxy is an HTTP forward proxy with domain-based blocking.
type FirewallProxy struct {
	blocklist *DomainBlocklist
	events    *BlockedEventLogger
	logger    *logger.TrafficLogger
	threat    *threatintel.Service
	srcBlocker sourceIPBlocker
	escalation EscalationConfig
	transport *http.Transport
}

// NewFirewallProxy builds a proxy handler that blocks malicious hosts.
func NewFirewallProxy(blocklist *DomainBlocklist, eventLogger *BlockedEventLogger, tl *logger.TrafficLogger, ti *threatintel.Service, blocker sourceIPBlocker, escalation EscalationConfig) *FirewallProxy {
	if escalation.VTMaliciousThreshold <= 0 {
		escalation.VTMaliciousThreshold = 5
	}
	return &FirewallProxy{
		blocklist: blocklist,
		events:    eventLogger,
		logger:    tl,
		threat:    ti,
		srcBlocker: blocker,
		escalation: escalation,
		transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// DomainStats returns metadata for APIs and diagnostics.
func (p *FirewallProxy) DomainStats() DomainBlocklistStats {
	return p.blocklist.Stats()
}

// DomainList returns current blocked domains.
func (p *FirewallProxy) DomainList() []string {
	return p.blocklist.List()
}

// ReloadDomains forces a manual blocklist reload.
func (p *FirewallProxy) ReloadDomains() (int, error) {
	return p.blocklist.Reload()
}

// AddDomain adds a blocked domain into the runtime and persisted list.
func (p *FirewallProxy) AddDomain(domain string) (bool, string, error) {
	return p.blocklist.AddDomain(domain)
}

// RemoveDomain removes a blocked domain from runtime and persisted list.
func (p *FirewallProxy) RemoveDomain(domain string) (bool, string, error) {
	return p.blocklist.RemoveDomain(domain)
}

// IsDomainBlocked reports whether domain is blocked by proxy list.
func (p *FirewallProxy) IsDomainBlocked(domain string) bool {
	return p.blocklist.IsBlocked(domain)
}

// RecentBlockedEvents returns newest blocked request events.
func (p *FirewallProxy) RecentBlockedEvents(limit int) []BlockedEvent {
	if p.events == nil {
		return nil
	}
	return p.events.Recent(limit)
}

// StartAutoReload keeps the blocklist in sync with file changes.
func (p *FirewallProxy) StartAutoReload(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				changed, count, err := p.blocklist.ReloadIfChanged()
				if err != nil {
					if p.logger != nil {
						p.logger.Log("ERROR", "-", "-", "HTTP-PROXY", fmt.Sprintf("domain reload failed: %v", err))
					}
					continue
				}
				if changed && p.logger != nil {
					p.logger.Log("CONFIG", "-", "-", "HTTP-PROXY", fmt.Sprintf("malicious domain list reloaded: %d domains", count))
				}
			}
		}
	}()
}

// ServeHTTP handles proxied requests with domain blocking.
func (p *FirewallProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	host := targetHost(r)
	if host == "" {
		http.Error(w, "Bad request: missing target host", http.StatusBadRequest)
		return
	}

	if p.blocklist.IsBlocked(host) {
		p.blockRequest(w, r, host)
		return
	}

	proxyReq := r.Clone(r.Context())
	if proxyReq.URL.Scheme == "" {
		proxyReq.URL.Scheme = "http"
	}
	proxyReq.URL.Host = host
	proxyReq.RequestURI = ""

	resp, err := p.transport.RoundTrip(proxyReq)
	if err != nil {
		http.Error(w, "Upstream request failed", http.StatusBadGateway)
		if p.logger != nil {
			p.logger.Log("ERROR", clientIP(r), host, "HTTP-PROXY", fmt.Sprintf("proxy upstream failed: %v", err))
		}
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	if p.logger != nil {
		p.logger.Log("ALLOW", clientIP(r), host, "HTTP", fmt.Sprintf("proxied %s %s", r.Method, r.URL.Path))
	}
}

func (p *FirewallProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostOnly := targetHost(r)
	if hostOnly == "" {
		http.Error(w, "Bad request: missing target host", http.StatusBadRequest)
		return
	}
	if p.blocklist.IsBlocked(hostOnly) {
		p.blockRequest(w, r, hostOnly)
		return
	}

	address := strings.TrimSpace(r.Host)
	if address == "" {
		address = hostOnly + ":443"
	} else if _, _, err := net.SplitHostPort(address); err != nil {
		address = address + ":443"
	}

	targetConn, err := net.DialTimeout("tcp", address, 20*time.Second)
	if err != nil {
		http.Error(w, "Tunnel upstream failed", http.StatusBadGateway)
		if p.logger != nil {
			p.logger.Log("ERROR", clientIP(r), hostOnly, "HTTPS", fmt.Sprintf("connect dial failed: %v", err))
		}
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		http.Error(w, "Tunnel setup failed", http.StatusInternalServerError)
		return
	}

	_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = rw.Flush()

	go transferAndClose(targetConn, clientConn)
	go transferAndClose(clientConn, targetConn)

	if p.logger != nil {
		p.logger.Log("ALLOW", clientIP(r), hostOnly, "HTTPS", "CONNECT tunnel established")
	}
}

func (p *FirewallProxy) blockRequest(w http.ResponseWriter, r *http.Request, host string) {
	now := time.Now().UTC()
	eventID := uuid.NewString()
	attacker := clientIP(r)
	requestURL := rawRequestURL(r, host)
	vtAssessment := threatintel.DomainURLAssessment{}
	escalation := EscalationResult{Enabled: p.escalation.Enabled, Threshold: p.escalation.VTMaliciousThreshold}
	if p.threat != nil {
		if res, err := p.threat.CheckDomainAndURL(host, requestURL); err != nil {
			vtAssessment = res
			if p.logger != nil {
				p.logger.Log("ERROR", attacker, host, "HTTP", fmt.Sprintf("virustotal lookup failed event_id=%s err=%v", eventID, err))
			}
		} else {
			vtAssessment = res
		}
	}
	escalation = p.maybeEscalate(attacker, host, eventID, vtAssessment)

	ev := BlockedEvent{
		EventID:    eventID,
		Timestamp:  now,
		Reason:     blockReasonMaliciousDomain,
		AttackerIP: attacker,
		Domain:     host,
		Method:     r.Method,
		Path:       r.URL.Path,
		UserAgent:  r.UserAgent(),
		VirusTotal: vtAssessment,
		Escalation: escalation,
	}
	if p.events != nil {
		_ = p.events.Log(ev)
	}
	if p.logger != nil {
		p.logger.Log("BLOCK", attacker, host, "HTTP", fmt.Sprintf("blocked malicious domain=%s event_id=%s", host, eventID))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = blockPageTmpl.Execute(w, map[string]string{
		"Reason":     blockReasonMaliciousDomain,
		"AttackerIP": attacker,
		"Timestamp":  now.Format(time.RFC3339),
		"EventID":    eventID,
		"Domain":     host,
		"VTDomain":   vtAssessment.Domain.ThreatLevel,
		"VTURL":      vtAssessment.URL.ThreatLevel,
	})
}

func (p *FirewallProxy) maybeEscalate(attackerIP, domain, eventID string, assessment threatintel.DomainURLAssessment) EscalationResult {
	res := EscalationResult{Enabled: p.escalation.Enabled, Threshold: p.escalation.VTMaliciousThreshold}
	res.DomainScore = assessment.Domain.Malicious
	res.URLScore = assessment.URL.Malicious

	if !p.escalation.Enabled {
		res.Reason = "disabled"
		return res
	}
	maxScore := res.DomainScore
	if res.URLScore > maxScore {
		maxScore = res.URLScore
	}
	if maxScore < p.escalation.VTMaliciousThreshold {
		res.Reason = "below_threshold"
		return res
	}

	ip := strings.TrimSpace(attackerIP)
	if net.ParseIP(ip) == nil {
		res.Reason = "attacker_ip_invalid"
		return res
	}
	if !p.escalation.AllowPrivateIPBlock && !isPublicIP(ip) {
		res.Reason = "attacker_ip_not_public"
		return res
	}
	if p.srcBlocker == nil {
		res.Reason = "no_source_blocker"
		return res
	}
	if p.srcBlocker.IsIPBlocked(ip) {
		res.Triggered = true
		res.AppliedIP = ip
		res.Reason = "already_blocked"
		return res
	}

	reason := "Auto-escalation: VT malicious score=" + strconv.Itoa(maxScore) + " domain=" + domain + " event_id=" + eventID
	if _, err := p.srcBlocker.BlockIP(ip, reason); err != nil {
		res.Reason = "block_failed: " + err.Error()
		if p.logger != nil {
			p.logger.Log("ERROR", ip, domain, "HTTP", fmt.Sprintf("auto escalation failed event_id=%s err=%v", eventID, err))
		}
		return res
	}

	res.Triggered = true
	res.AppliedIP = ip
	res.Reason = "blocked"
	if p.logger != nil {
		p.logger.Log("BLOCK", ip, domain, "HTTP", fmt.Sprintf("auto escalation source block applied event_id=%s score=%d threshold=%d", eventID, maxScore, p.escalation.VTMaliciousThreshold))
	}
	return res
}

func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}
	for _, cidr := range privateCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func targetHost(r *http.Request) string {
	host := strings.TrimSpace(r.URL.Host)
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host
}

func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func transferAndClose(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, bufio.NewReader(src))
}

func rawRequestURL(r *http.Request, host string) string {
	u := r.URL.String()
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	path := r.URL.RequestURI()
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	return "http://" + host + path
}

var blockPageTmpl = template.Must(template.New("blocked-page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Blocked by KaliWall</title>
  <style>
    :root {
      color-scheme: light;
    }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: "Segoe UI", Tahoma, sans-serif;
      background: radial-gradient(circle at 20% 20%, #fef3c7, #fee2e2 45%, #fecaca 100%);
      color: #7f1d1d;
    }
    .card {
      width: min(680px, 92vw);
      background: rgba(255, 255, 255, 0.93);
      border: 1px solid #fecaca;
      border-radius: 18px;
      box-shadow: 0 12px 30px rgba(127, 29, 29, 0.15);
      padding: 28px;
    }
    h1 {
      margin: 0 0 12px;
      font-size: 1.9rem;
    }
    p {
      margin: 0 0 16px;
      color: #991b1b;
    }
    .meta {
      background: #fff7ed;
      border: 1px solid #fed7aa;
      border-radius: 12px;
      padding: 14px;
      line-height: 1.8;
      color: #7c2d12;
    }
    .label {
      font-weight: 700;
      margin-right: 8px;
    }
  </style>
</head>
<body>
  <main class="card">
		<h1>Blocked by KaliWall</h1>
    <p>The request was denied because the destination is on the malicious domain list.</p>
    <section class="meta">
      <div><span class="label">🚫 Reason:</span>{{.Reason}}</div>
      <div><span class="label">🌍 Attacker IP:</span>{{.AttackerIP}}</div>
      <div><span class="label">⏱ Timestamp:</span>{{.Timestamp}}</div>
      <div><span class="label">🆔 Event ID:</span>{{.EventID}}</div>
      <div><span class="label">Domain:</span>{{.Domain}}</div>
			<div><span class="label">VirusTotal Domain Level:</span>{{.VTDomain}}</div>
			<div><span class="label">VirusTotal URL Level:</span>{{.VTURL}}</div>
    </section>
  </main>
</body>
</html>
`))
