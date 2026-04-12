package action

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"

	"kaliwall/internal/dpi/rules"
	"kaliwall/internal/dpi/types"
	"kaliwall/internal/logger"
	"kaliwall/internal/models"
)

// IPBlocker applies source/destination IP blocks through firewall backends.
type IPBlocker interface {
	BlockIP(ip, reason string) (models.BlockedIP, error)
	IsIPBlocked(ip string) bool
}

// Engine handles final decision side effects.
type Engine struct {
	trafficLog *logger.TrafficLogger
	blocker    IPBlocker
}

func New(trafficLog *logger.TrafficLogger, blocker IPBlocker) *Engine {
	return &Engine{trafficLog: trafficLog, blocker: blocker}
}

// Handle executes side effects for a DPI decision.
// Returns true only when a BLOCK decision was actually enforced by firewall backend.
func (e *Engine) Handle(result types.InspectResult, decision rules.Decision) bool {
	e.emitVerificationLogs(result)

	entry := map[string]interface{}{
		"ts":       result.Timestamp,
		"src_ip":   result.Tuple.SrcIP,
		"dst_ip":   result.Tuple.DstIP,
		"src_port": result.Tuple.SrcPort,
		"dst_port": result.Tuple.DstPort,
		"protocol": result.Tuple.Protocol,
		"action":   decision.Action,
		"rule_id":  decision.RuleID,
		"rule_type": decision.Type,
		"reason":   decision.Reason,
		"http_host": result.HTTPHost,
		"http_url": result.HTTPURL,
		"dns_domain": result.DNSDomain,
		"tls_sni":  result.TLSSNI,
		"signals":  result.Detections,
	}
	b, _ := json.Marshal(entry)
	detail := buildDetail(result, decision)

	switch decision.Action {
	case types.ActionBlock:
		targetIP, blockNote := selectBlockTargetIP(result.Tuple.SrcIP, result.Tuple.DstIP)
		blocked, blockErr := e.enforceBlock(targetIP, detail)
		if blocked {
			detailWithTarget := appendDetail(detail, "blocked_ip="+targetIP)
			log.Printf("DPI BLOCK %s", b)
			if e.trafficLog != nil {
				e.trafficLog.Log("BLOCK", result.Tuple.SrcIP, result.Tuple.DstIP, result.Tuple.Protocol, "dpi:block:"+detailWithTarget)
				e.trafficLog.EmitFirewallEvent(models.FirewallEvent{
					EventType: "blocked_packet",
					Backend:   "dpi",
					Action:    "BLOCK",
					SrcIP:     result.Tuple.SrcIP,
					DstIP:     result.Tuple.DstIP,
					Protocol:  result.Tuple.Protocol,
					SrcPort:   fmt.Sprintf("%d", result.Tuple.SrcPort),
					DstPort:   fmt.Sprintf("%d", result.Tuple.DstPort),
					Detail:    "dpi:" + detailWithTarget,
					Severity:  "critical",
				})
			}
			return true
		}

		unenforced := appendDetail(detail, "note="+blockNote)
		if targetIP != "" {
			unenforced = appendDetail(unenforced, "target_ip="+targetIP)
		}
		if blockErr != nil {
			unenforced = appendDetail(unenforced, "error="+compactError(blockErr))
		}
		log.Printf("DPI BLOCK DECISION UNENFORCED %s", b)
		if e.trafficLog != nil {
			e.trafficLog.Log("LOG", result.Tuple.SrcIP, result.Tuple.DstIP, result.Tuple.Protocol, "dpi:block_unenforced:"+unenforced)
			e.trafficLog.EmitFirewallEvent(models.FirewallEvent{
				EventType: "dpi_decision",
				Backend:   "dpi",
				Action:    "LOG",
				SrcIP:     result.Tuple.SrcIP,
				DstIP:     result.Tuple.DstIP,
				Protocol:  result.Tuple.Protocol,
				SrcPort:   fmt.Sprintf("%d", result.Tuple.SrcPort),
				DstPort:   fmt.Sprintf("%d", result.Tuple.DstPort),
				Detail:    "dpi:block_unenforced:" + unenforced,
				Severity:  "warning",
			})
		}
		return false
	case types.ActionLog:
		log.Printf("DPI LOG %s", b)
		if e.trafficLog != nil {
			e.trafficLog.Log("LOG", result.Tuple.SrcIP, result.Tuple.DstIP, result.Tuple.Protocol, "dpi:log:"+detail)
			e.trafficLog.EmitFirewallEvent(models.FirewallEvent{
				EventType: "dpi_decision",
				Backend:   "dpi",
				Action:    "LOG",
				SrcIP:     result.Tuple.SrcIP,
				DstIP:     result.Tuple.DstIP,
				Protocol:  result.Tuple.Protocol,
				SrcPort:   fmt.Sprintf("%d", result.Tuple.SrcPort),
				DstPort:   fmt.Sprintf("%d", result.Tuple.DstPort),
				Detail:    "dpi:" + detail,
				Severity:  "warning",
			})
		}
		return false
	default:
		if e.trafficLog != nil {
			e.trafficLog.Log("ALLOW", result.Tuple.SrcIP, result.Tuple.DstIP, result.Tuple.Protocol, "dpi:allow:"+detail)
			e.trafficLog.EmitFirewallEvent(models.FirewallEvent{
				EventType: "dpi_decision",
				Backend:   "dpi",
				Action:    "ALLOW",
				SrcIP:     result.Tuple.SrcIP,
				DstIP:     result.Tuple.DstIP,
				Protocol:  result.Tuple.Protocol,
				SrcPort:   fmt.Sprintf("%d", result.Tuple.SrcPort),
				DstPort:   fmt.Sprintf("%d", result.Tuple.DstPort),
				Detail:    "dpi:" + detail,
				Severity:  "info",
			})
		}
		return false
	}
}

func (e *Engine) emitVerificationLogs(result types.InspectResult) {
	if result.HTTPMethod != "" {
		host := fallback(result.HTTPHost, "-")
		log.Printf("[HTTP] %s %s Host: %s", result.HTTPMethod, fallback(result.HTTPURL, "/"), host)
	}
	if result.DNSDomain != "" {
		log.Printf("[DNS] Query: %s", result.DNSDomain)
	}
	if result.TLSSNI != "" {
		log.Printf("[TLS] SNI: %s", result.TLSSNI)
	}
}

func buildDetail(result types.InspectResult, decision rules.Decision) string {
	parts := []string{
		fmt.Sprintf("rule=%s", fallback(decision.RuleID, "-")),
		fmt.Sprintf("type=%s", fallback(decision.Type, "-")),
		fmt.Sprintf("reason=%s", fallback(decision.Reason, "no_reason")),
		fmt.Sprintf("sport=%d", result.Tuple.SrcPort),
		fmt.Sprintf("dport=%d", result.Tuple.DstPort),
	}
	if result.HTTPMethod != "" {
		parts = append(parts, "http_method="+result.HTTPMethod)
	}
	if result.HTTPHost != "" {
		parts = append(parts, "http_host="+result.HTTPHost)
	}
	if result.HTTPURL != "" {
		parts = append(parts, "http_url="+result.HTTPURL)
	}
	if result.DNSDomain != "" {
		parts = append(parts, "dns="+result.DNSDomain)
	}
	if result.TLSSNI != "" {
		parts = append(parts, "sni="+result.TLSSNI)
	}
	if len(result.Detections) > 0 {
		parts = append(parts, "signals="+strings.Join(result.Detections, ","))
	}
	out := strings.Join(parts, " ")
	if len(out) > 420 {
		return out[:420]
	}
	return out
}

func fallback(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

func (e *Engine) enforceBlock(targetIP string, detail string) (bool, error) {
	if targetIP == "" {
		return false, nil
	}
	if e.blocker == nil {
		return false, nil
	}
	if !blockerInLiveMode(e.blocker) {
		return false, nil
	}
	if e.blocker.IsIPBlocked(targetIP) {
		return true, nil
	}
	reason := "DPI enforce block: " + detail
	if len(reason) > 200 {
		reason = reason[:200]
	}
	_, err := e.blocker.BlockIP(targetIP, reason)
	if err != nil {
		return false, err
	}
	return true, nil
}

func selectBlockTargetIP(srcIP, dstIP string) (string, string) {
	src := net.ParseIP(strings.TrimSpace(srcIP))
	dst := net.ParseIP(strings.TrimSpace(dstIP))
	srcPublic := isPublicBlockTarget(src)
	dstPublic := isPublicBlockTarget(dst)

	switch {
	case srcPublic && !dstPublic:
		return strings.TrimSpace(srcIP), "inbound_source"
	case dstPublic && !srcPublic:
		return strings.TrimSpace(dstIP), "outbound_destination"
	case srcPublic && dstPublic:
		return strings.TrimSpace(srcIP), "public_source"
	default:
		return "", "no_public_target"
	}
}

func isPublicBlockTarget(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}

func appendDetail(detail, token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		if len(detail) > 420 {
			return detail[:420]
		}
		return detail
	}
	out := strings.TrimSpace(detail + " " + token)
	if len(out) > 420 {
		return out[:420]
	}
	return out
}

func compactError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if len(msg) > 96 {
		return msg[:96]
	}
	return msg
}

func blockerInLiveMode(blocker IPBlocker) bool {
	if blocker == nil {
		return false
	}
	if infoProvider, ok := blocker.(interface{ EngineInfo() models.FirewallEngineInfo }); ok {
		return infoProvider.EngineInfo().LiveMode
	}
	return true
}
