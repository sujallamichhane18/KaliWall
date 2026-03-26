package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"kaliwall/internal/models"
)

type RuleDecision struct {
	ShouldCreateRule bool               `json:"should_create_rule"`
	Confidence       int                `json:"confidence"`
	Reason           string             `json:"reason"`
	DecisionSource   string             `json:"decision_source"`
	Rule             models.RuleRequest `json:"rule"`
}

type ConnectivityStatus struct {
	Configured bool   `json:"configured"`
	Reachable  bool   `json:"reachable"`
	Provider   string `json:"provider,omitempty"`
	Model      string `json:"model,omitempty"`
	Message    string `json:"message"`
}

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

var providerModelFallback = map[string][]string{
	ProviderOpenRouter: {
		"google/gemma-3-4b-it:free",
		"mistralai/mistral-7b-instruct:free",
	},
	ProviderOpenAI: {
		"gpt-4o-mini",
	},
	ProviderAnthropic: {
		"claude-3-5-haiku-latest",
	},
	ProviderGrok: {
		"grok-2-latest",
	},
}

type OpenRouterService struct {
	mu       sync.RWMutex
	provider string
	apiKeys  map[string]string
	client   *http.Client
}

func NewOpenRouterService() *OpenRouterService {
	return &OpenRouterService{
		provider: ProviderOpenRouter,
		apiKeys:  make(map[string]string),
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *OpenRouterService) SetAPIKey(key string) {
	s.mu.RLock()
	provider := s.provider
	s.mu.RUnlock()
	_ = s.SetAPIKeyForProvider(provider, key)
}

func (s *OpenRouterService) SetAPIKeyForProvider(provider, key string) error {
	normalized, ok := normalizeProvider(provider)
	if !ok {
		return fmt.Errorf("unsupported AI provider: %s", provider)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys[normalized] = strings.TrimSpace(key)
	return nil
}

func (s *OpenRouterService) RemoveAPIKeyForProvider(provider string) error {
	normalized, ok := normalizeProvider(provider)
	if !ok {
		return fmt.Errorf("unsupported AI provider: %s", provider)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.apiKeys, normalized)
	return nil
}

func (s *OpenRouterService) HasAPIKey() bool {
	s.mu.RLock()
	provider := s.provider
	s.mu.RUnlock()
	return s.HasAPIKeyForProvider(provider)
}

func (s *OpenRouterService) HasAPIKeyForProvider(provider string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	normalized, ok := normalizeProvider(provider)
	if !ok {
		return false
	}
	return strings.TrimSpace(s.apiKeys[normalized]) != ""
}

func (s *OpenRouterService) GetAPIKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.apiKeys[s.provider])
}

func (s *OpenRouterService) GetAPIKeyForProvider(provider string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	normalized, ok := normalizeProvider(provider)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s.apiKeys[normalized])
}

func (s *OpenRouterService) SetProvider(provider string) error {
	normalized, ok := normalizeProvider(provider)
	if !ok {
		return fmt.Errorf("unsupported AI provider: %s", provider)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.provider = normalized
	return nil
}

func (s *OpenRouterService) Provider() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.provider
}

func (s *OpenRouterService) SupportedProviders() []string {
	providers := make([]string, len(supportedProviders))
	copy(providers, supportedProviders)
	return providers
}

func (s *OpenRouterService) ConfiguredProviders() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	configured := make([]string, 0, len(s.apiKeys))
	for _, provider := range supportedProviders {
		if strings.TrimSpace(s.apiKeys[provider]) != "" {
			configured = append(configured, provider)
		}
	}
	sort.Strings(configured)
	return configured
}

func (s *OpenRouterService) ProviderAPIKeys() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(supportedProviders))
	for _, provider := range supportedProviders {
		out[provider] = strings.TrimSpace(s.apiKeys[provider])
	}
	return out
}

func (s *OpenRouterService) ConnectionStatus() ConnectivityStatus {
	s.mu.RLock()
	provider := s.provider
	key := strings.TrimSpace(s.apiKeys[provider])
	s.mu.RUnlock()

	if key == "" {
		return ConnectivityStatus{
			Configured: false,
			Reachable:  false,
			Provider:   provider,
			Message:    providerDisplayName(provider) + " API key not configured",
		}
	}

	probePrompt := "Reply with exactly: OK"
	var errs []string
	for _, model := range modelsForProvider(provider) {
		_, err := s.callProviderModel(provider, key, model, probePrompt, 3)
		if err == nil {
			return ConnectivityStatus{
				Configured: true,
				Reachable:  true,
				Provider:   provider,
				Model:      model,
				Message:    providerDisplayName(provider) + " API reachable",
			}
		}
		errs = append(errs, model+": "+err.Error())
	}

	return ConnectivityStatus{
		Configured: true,
		Reachable:  false,
		Provider:   provider,
		Message:    providerDisplayName(provider) + " API unreachable: " + strings.Join(errs, " | "),
	}
}

func (s *OpenRouterService) ExplainBlock(packetMeta map[string]interface{}) (string, error) {
	s.mu.RLock()
	provider := s.provider
	key := strings.TrimSpace(s.apiKeys[provider])
	s.mu.RUnlock()

	if key == "" {
		return "", fmt.Errorf("%s API key not configured", providerDisplayName(provider))
	}

	if !isBlockedOrSuspiciousTraffic(packetMeta) {
		return "AI explanation is only available for blocked or suspicious traffic.", nil
	}

	packetBytes, err := json.MarshalIndent(packetMeta, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal packet: %w", err)
	}

	prompt := fmt.Sprintf("You are an AI security assistant. Return exactly one short sentence in plain language explaining why this packet was blocked. Use only key facts. No rule names. No extra text. Keep it very brief.\n\nBlocked packet:\n%s", string(packetBytes))

	content, err := s.callProviderWithFallback(provider, key, prompt, 50)
	if err != nil {
		// Fail-open to a deterministic explanation so protection remains usable.
		return heuristicExplanation(packetMeta), nil
	}

	return content, nil
}

func (s *OpenRouterService) SuggestRuleDecision(packetMeta map[string]interface{}) (RuleDecision, error) {
	s.mu.RLock()
	provider := s.provider
	key := strings.TrimSpace(s.apiKeys[provider])
	s.mu.RUnlock()

	if key == "" {
		return RuleDecision{}, fmt.Errorf("%s API key not configured", providerDisplayName(provider))
	}

	packetBytes, err := json.MarshalIndent(packetMeta, "", "  ")
	if err != nil {
		return RuleDecision{}, fmt.Errorf("failed to marshal packet: %w", err)
	}

	prompt := fmt.Sprintf("You are a firewall AI assistant. Based on this blocked or suspicious traffic metadata, decide if a new firewall rule should be suggested. Return ONLY strict JSON with this schema: {\"should_create_rule\":boolean,\"confidence\":number,\"reason\":string,\"rule\":{\"chain\":\"INPUT|OUTPUT|FORWARD\",\"protocol\":\"tcp|udp|icmp|all\",\"src_ip\":\"any or IP/CIDR\",\"dst_ip\":\"any or IP/CIDR\",\"src_port\":\"any or port\",\"dst_port\":\"any or port\",\"action\":\"DROP or REJECT\",\"comment\":string,\"enabled\":true}}. Keep reason concise.\n\nTraffic metadata:\n%s", string(packetBytes))

	content, err := s.callProviderWithFallback(provider, key, prompt, 220)
	if err != nil {
		return RuleDecision{}, fmt.Errorf("AI decision unavailable: %w", err)
	}

	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var decision RuleDecision
	if err := json.Unmarshal([]byte(content), &decision); err != nil {
		return RuleDecision{}, fmt.Errorf("AI returned non-JSON decision: %w", err)
	}

	if decision.Confidence < 0 {
		decision.Confidence = 0
	}
	if decision.Confidence > 100 {
		decision.Confidence = 100
	}

	decision.Rule = sanitizeSuggestedRule(decision.Rule)
	decision.DecisionSource = provider + "-ai"
	if decision.Reason == "" {
		decision.Reason = "AI rule decision generated."
	}

	return decision, nil
}

func (s *OpenRouterService) callProviderWithFallback(provider, key, prompt string, maxTokens int) (string, error) {
	var errs []string
	for _, model := range modelsForProvider(provider) {
		content, err := s.callProviderModel(provider, key, model, prompt, maxTokens)
		if err == nil {
			return content, nil
		}
		errs = append(errs, model+": "+err.Error())
	}
	return "", fmt.Errorf("%s unavailable across fallback models (%s)", providerDisplayName(provider), strings.Join(errs, " | "))
}

func (s *OpenRouterService) callProviderModel(provider, key, model, prompt string, maxTokens int) (string, error) {
	switch provider {
	case ProviderOpenRouter:
		return s.callOpenAICompatibleModel(
			provider,
			"https://openrouter.ai/api/v1/chat/completions",
			key,
			model,
			prompt,
			maxTokens,
			map[string]string{
				"HTTP-Referer": "http://localhost:8080",
				"X-Title":      "KaliWall",
			},
		)
	case ProviderOpenAI:
		return s.callOpenAICompatibleModel(
			provider,
			"https://api.openai.com/v1/chat/completions",
			key,
			model,
			prompt,
			maxTokens,
			nil,
		)
	case ProviderGrok:
		return s.callOpenAICompatibleModel(
			provider,
			"https://api.x.ai/v1/chat/completions",
			key,
			model,
			prompt,
			maxTokens,
			nil,
		)
	case ProviderAnthropic:
		return s.callAnthropicModel(key, model, prompt, maxTokens)
	default:
		return "", fmt.Errorf("unsupported AI provider: %s", provider)
	}
}

func (s *OpenRouterService) callOpenAICompatibleModel(provider, endpoint, key, model, prompt string, maxTokens int, extraHeaders map[string]string) (string, error) {
	reqBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.3,
		"max_tokens":  maxTokens,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", providerStatusError(provider, resp.StatusCode, string(respBody))
	}

	var orResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(respBody, &orResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(orResp.Choices) == 0 {
		return "", fmt.Errorf("no response choices returned")
	}

	content := strings.TrimSpace(orResp.Choices[0].Message.Content)
	if content == "" {
		return "", fmt.Errorf("empty response content")
	}

	return content, nil
}

func (s *OpenRouterService) callAnthropicModel(key, model, prompt string, maxTokens int) (string, error) {
	reqBody := map[string]interface{}{
		"model":       model,
		"max_tokens":  maxTokens,
		"temperature": 0.3,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", providerStatusError(ProviderAnthropic, resp.StatusCode, string(respBody))
	}

	var aResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.Unmarshal(respBody, &aResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	for _, part := range aResp.Content {
		if part.Type == "text" && strings.TrimSpace(part.Text) != "" {
			return strings.TrimSpace(part.Text), nil
		}
	}

	return "", fmt.Errorf("no response content returned")
}

func providerStatusError(provider string, status int, body string) error {
	lower := strings.ToLower(body)
	if provider == ProviderOpenRouter && status == http.StatusNotFound && strings.Contains(lower, "no endpoints available matching your guardrail restrictions") {
		return fmt.Errorf("model blocked by OpenRouter privacy/guardrail policy; update policy at https://openrouter.ai/settings/privacy or use another compatible free model")
	}
	if status == http.StatusUnauthorized {
		return fmt.Errorf("invalid %s API key", providerDisplayName(provider))
	}
	if status == http.StatusTooManyRequests {
		return fmt.Errorf("%s rate limit reached", providerDisplayName(provider))
	}
	if len(body) > 240 {
		body = body[:240] + "..."
	}
	return fmt.Errorf("%s API error (%d): %s", providerDisplayName(provider), status, body)
}

func modelsForProvider(provider string) []string {
	if models, ok := providerModelFallback[provider]; ok && len(models) > 0 {
		out := make([]string, len(models))
		copy(out, models)
		return out
	}
	return []string{"gpt-4o-mini"}
}

func normalizeProvider(provider string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case ProviderOpenRouter:
		return ProviderOpenRouter, true
	case ProviderOpenAI:
		return ProviderOpenAI, true
	case ProviderAnthropic:
		return ProviderAnthropic, true
	case ProviderGrok:
		return ProviderGrok, true
	default:
		return "", false
	}
}

func providerDisplayName(provider string) string {
	switch provider {
	case ProviderOpenRouter:
		return "OpenRouter"
	case ProviderOpenAI:
		return "OpenAI"
	case ProviderAnthropic:
		return "Anthropic"
	case ProviderGrok:
		return "Grok"
	default:
		return "AI"
	}
}

func defaultSuggestedRule() models.RuleRequest {
	return models.RuleRequest{
		Chain:    "INPUT",
		Protocol: "all",
		SrcIP:    "any",
		DstIP:    "any",
		SrcPort:  "any",
		DstPort:  "any",
		Action:   "DROP",
		Comment:  "AI suggested security rule",
		Enabled:  true,
	}
}

func sanitizeSuggestedRule(rule models.RuleRequest) models.RuleRequest {
	out := defaultSuggestedRule()

	chain := strings.ToUpper(strings.TrimSpace(rule.Chain))
	if chain == "INPUT" || chain == "OUTPUT" || chain == "FORWARD" {
		out.Chain = chain
	}

	protocol := strings.ToLower(strings.TrimSpace(rule.Protocol))
	if protocol == "tcp" || protocol == "udp" || protocol == "icmp" || protocol == "all" {
		out.Protocol = protocol
	}

	srcIP := strings.TrimSpace(rule.SrcIP)
	if srcIP != "" {
		out.SrcIP = srcIP
	}
	dstIP := strings.TrimSpace(rule.DstIP)
	if dstIP != "" {
		out.DstIP = dstIP
	}

	srcPort := strings.TrimSpace(rule.SrcPort)
	if srcPort != "" {
		out.SrcPort = srcPort
	}
	dstPort := strings.TrimSpace(rule.DstPort)
	if dstPort != "" {
		out.DstPort = dstPort
	}

	action := strings.ToUpper(strings.TrimSpace(rule.Action))
	if action == "DROP" || action == "REJECT" {
		out.Action = action
	}

	comment := strings.TrimSpace(rule.Comment)
	if comment != "" {
		out.Comment = comment
	}

	out.Enabled = true
	return out
}

func heuristicExplanation(packetMeta map[string]interface{}) string {
	flat := strings.ToLower(fmt.Sprintf("%v", packetMeta))
	src := extractValue(flat, `source:\s*([^\s,}]+)`)
	proto := extractValue(flat, `protocol:\s*([^\s,}]+)`)

	if strings.Contains(flat, "sqli") || strings.Contains(flat, "sql injection") {
		if src != "" {
			return "Traffic from " + src + " was blocked due to SQL injection indicators."
		}
		return "Traffic was blocked due to SQL injection indicators."
	}
	if strings.Contains(flat, "xss") {
		return "Traffic was blocked due to cross-site scripting indicators."
	}
	if strings.Contains(flat, "malware") || strings.Contains(flat, "botnet") || strings.Contains(flat, "c2") || strings.Contains(flat, "command and control") {
		return "Traffic was blocked due to suspected malware command-and-control communication."
	}
	if strings.Contains(flat, "suspicious") || strings.Contains(flat, "malicious") || strings.Contains(flat, "attack") {
		if src != "" && proto != "" {
			return "Suspicious " + strings.ToUpper(proto) + " traffic from " + src + " was blocked."
		}
		return "Suspicious traffic was blocked due to detected threat indicators."
	}
	return "Traffic was blocked because it matched suspicious or malicious behavior indicators."
}

func extractValue(input, pattern string) string {
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(input)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func isBlockedOrSuspiciousTraffic(packetMeta map[string]interface{}) bool {
	if len(packetMeta) == 0 {
		return false
	}

	flat := strings.ToLower(fmt.Sprintf("%v", packetMeta))

	riskyKeywords := []string{
		"blocked", "block", "drop", "reject", "deny", "denied",
		"suspicious", "supicious", "malicious", "malware", "botnet", "threat", "exploit", "attack", "anomaly", "c2", "command and control", "communcation with",
	}
	for _, k := range riskyKeywords {
		if strings.Contains(flat, k) {
			return true
		}
	}

	normalKeywords := []string{"allow", "allowed", "accept", "accepted", "benign", "normal"}
	for _, k := range normalKeywords {
		if strings.Contains(flat, k) {
			return false
		}
	}

	return false
}
