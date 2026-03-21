package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type OpenRouterService struct {
	mu     sync.RWMutex
	apiKey string
	client *http.Client
}

func NewOpenRouterService() *OpenRouterService {
	return &OpenRouterService{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *OpenRouterService) SetAPIKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKey = key
}

func (s *OpenRouterService) HasAPIKey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.apiKey != ""
}

func (s *OpenRouterService) ExplainBlock(packetMeta map[string]interface{}) (string, error) {
	s.mu.RLock()
	key := s.apiKey
	s.mu.RUnlock()

	if key == "" {
		return "", fmt.Errorf("openrouter API key not configured")
	}

	packetBytes, err := json.MarshalIndent(packetMeta, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal packet: %w", err)
	}

	prompt := fmt.Sprintf("You are an AI security assistant focused on succinct explanations. Given the blocked packet metadata below, generate a **single concise sentence** that explains **why the packet was blocked** in plain language, using only the key facts. Do not include firewall rule names or unnecessary text — make it minimal to save API tokens.\n\nBlocked packet:\n%s", string(packetBytes))

	reqBody := map[string]interface{}{
		"model": "qwen/qwen-2.5-7b-instruct:free",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.3,
		"max_tokens":  60,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequest("POST", "https://openrouter.ai/api/v1/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("HTTP-Referer", "http://localhost:8080")
	req.Header.Set("X-Title", "KaliWall")

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
		return "", fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
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

	return orResp.Choices[0].Message.Content, nil
}
