package ndpi

import "time"

// Config controls optional nDPI flow classification behavior.
type Config struct {
	EnableGuess     bool
	MaxTCPPackets   int
	MaxUDPPackets   int
	IdleTTL         time.Duration
	CleanupInterval time.Duration
}

// Result represents one nDPI classification decision.
type Result struct {
	MasterProtocol string `json:"master_protocol"`
	AppProtocol    string `json:"app_protocol"`
	Category       string `json:"category"`
	Confidence     string `json:"confidence"`
	Guessed        bool   `json:"guessed"`
}

// DefaultConfig returns sane defaults for live packet processing.
func DefaultConfig() Config {
	return Config{
		EnableGuess:     true,
		MaxTCPPackets:   80,
		MaxUDPPackets:   24,
		IdleTTL:         3 * time.Minute,
		CleanupInterval: 30 * time.Second,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.MaxTCPPackets > 0 {
		d.MaxTCPPackets = c.MaxTCPPackets
	}
	if c.MaxUDPPackets > 0 {
		d.MaxUDPPackets = c.MaxUDPPackets
	}
	if c.IdleTTL > 0 {
		d.IdleTTL = c.IdleTTL
	}
	if c.CleanupInterval > 0 {
		d.CleanupInterval = c.CleanupInterval
	}
	d.EnableGuess = c.EnableGuess
	return d
}
