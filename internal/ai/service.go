// Package ai provides provider-aware AI helper methods used by KaliWall APIs.
package ai

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	ProviderOpenRouter = "openrouter"
	ProviderOpenAI     = "openai"
	ProviderAnthropic  = "anthropic"
	ProviderGrok       = "grok"
)

var supportedProviders = []string{
	ProviderOpenRouter,
	ProviderOpenAI,
	ProviderAnthropic,
	ProviderGrok,
}

var providerSet = map[string]struct{}{
	ProviderOpenRouter: {},
	ProviderOpenAI:     {},
	ProviderAnthropic:  {},
	ProviderGrok:       {},
}

// OpenRouterService is the multi-provider AI facade consumed by API handlers.
type OpenRouterService struct {
	mu       sync.RWMutex
	provider string
	apiKeys  map[string]string
}

// NewOpenRouterService creates a service with OpenRouter as the default provider.
func NewOpenRouterService() *OpenRouterService {
	keys := make(map[string]string, len(supportedProviders))
	for _, provider := range supportedProviders {
		keys[provider] = ""
	}
	return &OpenRouterService{provider: ProviderOpenRouter, apiKeys: keys}
}

// SupportedProviders returns all supported provider identifiers.
func (s *OpenRouterService) SupportedProviders() []string {
	out := make([]string, len(supportedProviders))
	copy(out, supportedProviders)
	return out
}

// Provider returns the currently active provider.
func (s *OpenRouterService) Provider() string {
	if s == nil {
		return ProviderOpenRouter
	}
	s.mu.RLock()
	provider := s.provider
	s.mu.RUnlock()
	if provider == "" {
		return ProviderOpenRouter
	}
	return provider
}

// SetProvider sets the currently active provider.
func (s *OpenRouterService) SetProvider(provider string) error {
	if s == nil {
		return fmt.Errorf("ai service unavailable")
	}
	normalized, err := normalizeProvider(provider)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.provider = normalized
	s.mu.Unlock()
	return nil
}

// SetAPIKeyForProvider stores an API key for a provider.
func (s *OpenRouterService) SetAPIKeyForProvider(provider string, key string) error {
	if s == nil {
		return fmt.Errorf("ai service unavailable")
	}
	normalized, err := normalizeProvider(provider)
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return fmt.Errorf("api key is required")
	}
	s.mu.Lock()
	if s.apiKeys == nil {
		s.apiKeys = make(map[string]string, len(supportedProviders))
	}
	s.apiKeys[normalized] = trimmed
	s.mu.Unlock()
	return nil
}

// RemoveAPIKeyForProvider removes the saved key for the given provider.
func (s *OpenRouterService) RemoveAPIKeyForProvider(provider string) error {
	if s == nil {
		return fmt.Errorf("ai service unavailable")
	}
	normalized, err := normalizeProvider(provider)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.apiKeys == nil {
		s.apiKeys = make(map[string]string, len(supportedProviders))
	}
	s.apiKeys[normalized] = ""
	s.mu.Unlock()
	return nil
}

// GetAPIKeyForProvider returns the provider API key (or empty when unset).
func (s *OpenRouterService) GetAPIKeyForProvider(provider string) string {
	if s == nil {
		return ""
	}
	normalized, err := normalizeProvider(provider)
	if err != nil {
		return ""
	}
	s.mu.RLock()
	key := strings.TrimSpace(s.apiKeys[normalized])
	s.mu.RUnlock()
	return key
}

// HasAPIKeyForProvider reports whether a non-empty key exists for provider.
func (s *OpenRouterService) HasAPIKeyForProvider(provider string) bool {
	return strings.TrimSpace(s.GetAPIKeyForProvider(provider)) != ""
}

// ConfiguredProviders returns providers that currently have API keys.
func (s *OpenRouterService) ConfiguredProviders() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	configured := make([]string, 0, len(supportedProviders))
	for _, provider := range supportedProviders {
		if strings.TrimSpace(s.apiKeys[provider]) != "" {
			configured = append(configured, provider)
		}
	}
	return configured
}

// ProviderAPIKeys returns a copy of known provider keys including empty values.
func (s *OpenRouterService) ProviderAPIKeys() map[string]string {
	out := make(map[string]string, len(supportedProviders))
	if s == nil {
		for _, provider := range supportedProviders {
			out[provider] = ""
		}
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, provider := range supportedProviders {
		out[provider] = strings.TrimSpace(s.apiKeys[provider])
	}
	return out
}

// ConnectionStatus reports provider and key readiness.
func (s *OpenRouterService) ConnectionStatus() map[string]interface{} {
	provider := s.Provider()
	configured := s.HasAPIKeyForProvider(provider)
	status := map[string]interface{}{
		"provider":   provider,
		"configured": configured,
		"reachable":  configured,
		"model":      provider + "-chat",
	}
	if configured {
		status["message"] = "API key configured; connectivity check deferred until request"
	} else {
		status["message"] = "API key is optional but required for external provider responses"
	}
	return status
}

// ExplainBlock returns a human-readable explanation for a blocked/suspicious packet.
func (s *OpenRouterService) ExplainBlock(packetMeta map[string]interface{}) (map[string]interface{}, error) {
	summary := summarizePacketMeta(packetMeta)
	provider := s.Provider()
	configured := s.HasAPIKeyForProvider(provider)

	reasonBits := heuristicThreatSignals(packetMeta)
	explanation := "Traffic event analyzed."
	if len(reasonBits) > 0 {
		explanation = "Traffic event analyzed and flagged due to: " + strings.Join(reasonBits, ", ") + "."
	}
	if summary != "" {
		explanation += " Context: " + summary
	}
	if !configured {
		explanation += " (heuristic fallback: no API key configured for " + provider + ")"
	}

	return map[string]interface{}{
		"provider":        provider,
		"configured":      configured,
		"decision_source": decisionSource(provider, configured),
		"explanation":     explanation,
	}, nil
}

// SuggestRuleDecision recommends whether to create a firewall rule from metadata.
func (s *OpenRouterService) SuggestRuleDecision(packetMeta map[string]interface{}) (map[string]interface{}, error) {
	provider := s.Provider()
	configured := s.HasAPIKeyForProvider(provider)
	signals := heuristicThreatSignals(packetMeta)
	score := heuristicConfidence(packetMeta, signals)
	shouldCreate := score >= 62

	srcIP := guessString(packetMeta, "src_ip", "source_ip", "source")
	dstIP := guessString(packetMeta, "dst_ip", "destination_ip", "destination")
	protocol := strings.ToLower(guessString(packetMeta, "protocol", "proto"))
	if protocol == "" {
		protocol = "tcp"
	}
	dstPort := guessPort(packetMeta, "dst_port", "destination_port", "port")
	if dstPort == "" {
		dstPort = "any"
	}

	reason := "insufficient risk signal for automatic rule creation"
	if len(signals) > 0 {
		reason = "detected risk signals: " + strings.Join(signals, ", ")
	}
	if !configured {
		reason += "; heuristic fallback active for provider " + provider
	}

	rule := map[string]interface{}{
		"chain":    "INPUT",
		"protocol": protocol,
		"src_ip":   normalizedRuleIP(srcIP),
		"dst_ip":   normalizedRuleIP(dstIP),
		"src_port": "any",
		"dst_port": dstPort,
		"action":   "DROP",
		"comment":  "AI suggested security rule",
	}
	if shouldCreate {
		rule["comment"] = "AI suggested rule: " + truncateReason(reason, 72)
	}

	return map[string]interface{}{
		"provider":           provider,
		"configured":         configured,
		"decision_source":    decisionSource(provider, configured),
		"should_create_rule": shouldCreate,
		"confidence":         score,
		"reason":             reason,
		"rule":               rule,
	}, nil
}

func normalizeProvider(provider string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(provider))
	if normalized == "" {
		return "", fmt.Errorf("provider is required")
	}
	if _, ok := providerSet[normalized]; !ok {
		return "", fmt.Errorf("unsupported AI provider: %s", provider)
	}
	return normalized, nil
}

func summarizePacketMeta(packetMeta map[string]interface{}) string {
	if len(packetMeta) == 0 {
		return ""
	}
	parts := make([]string, 0, 6)
	if src := guessString(packetMeta, "src_ip", "source_ip", "source"); src != "" {
		parts = append(parts, "src="+src)
	}
	if dst := guessString(packetMeta, "dst_ip", "destination_ip", "destination"); dst != "" {
		parts = append(parts, "dst="+dst)
	}
	if proto := guessString(packetMeta, "protocol", "proto"); proto != "" {
		parts = append(parts, "proto="+strings.ToLower(proto))
	}
	if port := guessPort(packetMeta, "dst_port", "destination_port", "port"); port != "" {
		parts = append(parts, "dst_port="+port)
	}
	if detail := guessString(packetMeta, "detail", "packet_data", "payload", "summary"); detail != "" {
		parts = append(parts, "detail="+truncateReason(detail, 96))
	}
	return strings.Join(parts, "; ")
}

func heuristicThreatSignals(packetMeta map[string]interface{}) []string {
	text := strings.ToLower(strings.TrimSpace(flattenMetaText(packetMeta)))
	if text == "" {
		return nil
	}

	rules := map[string][]string{
		"port_scan":          {"port scan", "scan", "nmap", "sweep"},
		"exploit_payload":    {"exploit", "shellshock", "log4shell", "jndi", "rce"},
		"web_attack":         {"sqli", "sql injection", "xss", "<script", "union select"},
		"malware_indicator":  {"malware", "payload", "dropper", "trojan", "botnet"},
		"credential_abuse":   {"bruteforce", "brute force", "credential", "password spray"},
		"command_execution":  {"powershell", "cmd.exe", "curl http", "wget", "base64 -d"},
		"blocked_by_policy":  {"blocked", "drop", "reject", "dpi:block"},
	}

	hits := make([]string, 0, len(rules))
	for signal, patterns := range rules {
		for _, pattern := range patterns {
			if strings.Contains(text, pattern) {
				hits = append(hits, signal)
				break
			}
		}
	}
	sort.Strings(hits)
	return hits
}

func heuristicConfidence(packetMeta map[string]interface{}, signals []string) int {
	score := 25
	score += len(signals) * 14

	action := strings.ToUpper(guessString(packetMeta, "action"))
	switch action {
	case "BLOCK", "DROP", "REJECT":
		score += 16
	case "LOG":
		score += 6
	}

	if guessPort(packetMeta, "dst_port", "destination_port", "port") == "22" {
		score += 4
	}
	if strings.TrimSpace(guessString(packetMeta, "src_ip", "source_ip", "source")) != "" {
		score += 4
	}
	if strings.TrimSpace(guessString(packetMeta, "dst_ip", "destination_ip", "destination")) != "" {
		score += 4
	}
	if score > 96 {
		score = 96
	}
	if score < 5 {
		score = 5
	}
	return score
}

func flattenMetaText(packetMeta map[string]interface{}) string {
	if len(packetMeta) == 0 {
		return ""
	}
	parts := make([]string, 0, len(packetMeta))
	for key, value := range packetMeta {
		switch v := value.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				parts = append(parts, key+":"+v)
			}
		case fmt.Stringer:
			parts = append(parts, key+":"+v.String())
		case []interface{}:
			for _, item := range v {
				parts = append(parts, fmt.Sprintf("%v", item))
			}
		default:
			parts = append(parts, fmt.Sprintf("%v", v))
		}
	}
	return strings.Join(parts, " ")
}

func guessString(meta map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		v, ok := meta[key]
		if !ok || v == nil {
			continue
		}
		switch s := v.(type) {
		case string:
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				return trimmed
			}
		default:
			rendered := strings.TrimSpace(fmt.Sprintf("%v", s))
			if rendered != "" && rendered != "<nil>" {
				return rendered
			}
		}
	}
	return ""
}

func guessPort(meta map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		v, ok := meta[key]
		if !ok || v == nil {
			continue
		}
		switch p := v.(type) {
		case string:
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				return trimmed
			}
		case int:
			if p > 0 {
				return strconv.Itoa(p)
			}
		case int64:
			if p > 0 {
				return strconv.FormatInt(p, 10)
			}
		case float64:
			if p > 0 {
				return strconv.Itoa(int(p))
			}
		default:
			rendered := strings.TrimSpace(fmt.Sprintf("%v", p))
			if rendered != "" && rendered != "<nil>" {
				return rendered
			}
		}
	}
	return ""
}

func decisionSource(provider string, configured bool) string {
	if configured {
		return provider + "_heuristic"
	}
	return "heuristic_no_api_key"
}

func normalizedRuleIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "any"
	}
	if strings.EqualFold(ip, "-") {
		return "any"
	}
	return ip
}

func truncateReason(text string, maxLen int) string {
	trimmed := strings.TrimSpace(text)
	if maxLen <= 0 || len(trimmed) <= maxLen {
		return trimmed
	}
	if maxLen <= 3 {
		return trimmed[:maxLen]
	}
	return trimmed[:maxLen-3] + "..."
}
