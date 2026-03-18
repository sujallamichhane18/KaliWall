package action

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"kaliwall/internal/dpi/rules"
	"kaliwall/internal/dpi/types"
	"kaliwall/internal/logger"
	"kaliwall/internal/models"
)

// Engine handles final decision side effects.
type Engine struct {
	trafficLog *logger.TrafficLogger
}

func New(trafficLog *logger.TrafficLogger) *Engine {
	return &Engine{trafficLog: trafficLog}
}

func (e *Engine) Handle(result types.InspectResult, decision rules.Decision) {
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
		log.Printf("DPI BLOCK %s", b)
		if e.trafficLog != nil {
			e.trafficLog.Log("BLOCK", result.Tuple.SrcIP, result.Tuple.DstIP, result.Tuple.Protocol, "dpi:block:"+detail)
			e.trafficLog.EmitFirewallEvent(models.FirewallEvent{
				EventType: "blocked_packet",
				Backend:   "dpi",
				Action:    "BLOCK",
				SrcIP:     result.Tuple.SrcIP,
				DstIP:     result.Tuple.DstIP,
				Protocol:  result.Tuple.Protocol,
				SrcPort:   fmt.Sprintf("%d", result.Tuple.SrcPort),
				DstPort:   fmt.Sprintf("%d", result.Tuple.DstPort),
				Detail:    "dpi:" + detail,
				Severity:  "critical",
			})
		}
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
