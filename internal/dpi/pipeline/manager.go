package pipeline

import (
	"context"
	"sync"

	"kaliwall/internal/dpi/action"
	"kaliwall/internal/logger"
)

// Manager controls DPI pipeline lifecycle for runtime enable/disable from API.
type Manager struct {
	mu      sync.RWMutex
	cfg     Config
	log     *logger.TrafficLogger
	blocker action.IPBlocker
	pipe    *Pipeline
	enabled bool
}

// NewManager creates a lifecycle manager with constructor-injected dependencies.
func NewManager(cfg Config, l *logger.TrafficLogger) *Manager {
	return &Manager{cfg: cfg, log: l}
}

// NewManagerWithBlocker creates a manager with firewall block enforcement support.
func NewManagerWithBlocker(cfg Config, l *logger.TrafficLogger, blocker action.IPBlocker) *Manager {
	return &Manager{cfg: cfg, log: l, blocker: blocker}
}

// SetBlocker updates the runtime blocker used for DPI block enforcement.
func (m *Manager) SetBlocker(blocker action.IPBlocker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocker = blocker
}

// SetEnabled starts or stops DPI safely.
func (m *Manager) SetEnabled(enabled bool) error {
	if enabled {
		return m.Start(context.Background())
	}
	m.Stop()
	return nil
}

// Start creates and starts a new pipeline instance when not already running.
func (m *Manager) Start(parent context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pipe != nil {
		st := m.pipe.Status()
		if st.Running {
			m.enabled = true
			return nil
		}
		m.pipe.Stop()
		m.pipe = nil
	}

	pipe, err := New(m.cfg, m.log, m.blocker)
	if err != nil {
		m.enabled = false
		return err
	}
	if err := pipe.Start(parent); err != nil {
		m.enabled = false
		return err
	}
	m.pipe = pipe
	m.enabled = true
	return nil
}

// Stop halts DPI and releases the running pipeline instance.
func (m *Manager) Stop() {
	m.mu.Lock()
	pipe := m.pipe
	m.pipe = nil
	m.enabled = false
	m.mu.Unlock()

	if pipe != nil {
		pipe.Stop()
	}
}

// Status returns a best-effort runtime status snapshot.
func (m *Manager) Status() Status {
	m.mu.RLock()
	pipe := m.pipe
	enabled := m.enabled
	cfg := m.cfg
	m.mu.RUnlock()

	if pipe == nil {
		return Status{
			Enabled:   enabled,
			Running:   false,
			Interface: cfg.Interface,
			Workers:   cfg.Workers,
		}
	}

	s := pipe.Status()
	s.Enabled = enabled
	return s
}
