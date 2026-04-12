// Package logger provides structured traffic logging for KaliWall.
// Logs are written to a local file with timestamps and can be queried for daily counts.
package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"kaliwall/internal/models"
)

// TrafficLogger writes structured log entries to a file.
type TrafficLogger struct {
	mu          sync.Mutex
	file        *os.File
	entries     []models.TrafficEntry // in-memory buffer for API queries
	subscribers map[uint64]chan models.TrafficEntry
	nextSubID   uint64
	events      []models.FirewallEvent
	eventSubscribers map[uint64]chan models.FirewallEvent
	nextEventSubID uint64
	backendProvider func() string
	maliciousIPChecker func(string) bool
}

// New opens (or creates) the log file and returns a TrafficLogger.
func New(path string) (*TrafficLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	tl := &TrafficLogger{
		file:        f,
		entries:     make([]models.TrafficEntry, 0, 1024),
		subscribers: make(map[uint64]chan models.TrafficEntry),
		events:      make([]models.FirewallEvent, 0, 1024),
		eventSubscribers: make(map[uint64]chan models.FirewallEvent),
	}
	tl.Log("SYSTEM", "-", "-", "-", "KaliWall daemon started")
	return tl, nil
}

// Close flushes and closes the log file.
func (tl *TrafficLogger) Close() {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.file.Close()
}

// Log writes a single traffic event to the log file and in-memory buffer.
func (tl *TrafficLogger) Log(action, srcIP, dstIP, protocol, detail string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	action = strings.ToUpper(strings.TrimSpace(action))
	if matchedIP := tl.lookupMaliciousIP(action, srcIP, dstIP); matchedIP != "" {
		action = "BLOCK"
		if !strings.Contains(strings.ToLower(detail), "malicious ip feed") {
			detail = fmt.Sprintf("Malicious IP feed match (%s): %s", matchedIP, detail)
		}
	}

	entry := models.TrafficEntry{
		Timestamp: time.Now(),
		Action:    action,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Protocol:  protocol,
		Detail:    detail,
	}

	// Write to file as JSON line
	line, _ := json.Marshal(entry)
	fmt.Fprintf(tl.file, "%s\n", line)

	// Keep in-memory (cap at 10000 entries)
	if len(tl.entries) >= 10000 {
		tl.entries = tl.entries[1:]
	}
	tl.entries = append(tl.entries, entry)

	// Notify live subscribers (non-blocking)
	for _, ch := range tl.subscribers {
		select {
		case ch <- entry:
		default:
		}
	}

	// Lightweight bridge for kernel blocked packet events into structured event stream.
	if strings.EqualFold(action, "BLOCK") && strings.Contains(strings.ToLower(detail), "kernel:") {
		backend := "disabled"
		if tl.backendProvider != nil {
			backend = tl.backendProvider()
		}
		tl.emitFirewallEventLocked(models.FirewallEvent{
			Timestamp: entry.Timestamp,
			EventType: "blocked_packet",
			Backend:   backend,
			Action:    strings.ToUpper(action),
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Protocol:  protocol,
			Detail:    detail,
			Severity:  "critical",
		})
	}
}

// SetBackendProvider wires a callback that returns current firewall backend name.
func (tl *TrafficLogger) SetBackendProvider(provider func() string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.backendProvider = provider
}

// SetMaliciousIPChecker wires a callback used to detect malicious IP indicators.
func (tl *TrafficLogger) SetMaliciousIPChecker(checker func(string) bool) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.maliciousIPChecker = checker
}

func (tl *TrafficLogger) lookupMaliciousIP(action, srcIP, dstIP string) string {
	if tl.maliciousIPChecker == nil {
		return ""
	}
	if !isTrafficAction(action) {
		return ""
	}
	if tl.maliciousIPChecker(strings.TrimSpace(srcIP)) {
		return strings.TrimSpace(srcIP)
	}
	if tl.maliciousIPChecker(strings.TrimSpace(dstIP)) {
		return strings.TrimSpace(dstIP)
	}
	return ""
}

func isTrafficAction(action string) bool {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "ALLOW", "ACCEPT", "LOG":
		return true
	default:
		return false
	}
}

func (tl *TrafficLogger) emitFirewallEventLocked(ev models.FirewallEvent) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	if len(tl.events) >= 5000 {
		tl.events = tl.events[1:]
	}
	tl.events = append(tl.events, ev)
	for _, ch := range tl.eventSubscribers {
		select {
		case ch <- ev:
		default:
		}
	}
}

// EmitFirewallEvent publishes a normalized firewall event.
func (tl *TrafficLogger) EmitFirewallEvent(ev models.FirewallEvent) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.emitFirewallEventLocked(ev)
}

// RecentFirewallEvents returns latest n normalized firewall events.
func (tl *TrafficLogger) RecentFirewallEvents(n int) []models.FirewallEvent {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if n <= 0 || n > len(tl.events) {
		n = len(tl.events)
	}
	start := len(tl.events) - n
	out := make([]models.FirewallEvent, n)
	copy(out, tl.events[start:])
	return out
}

// SubscribeFirewallEvents subscribes to real-time firewall events.
func (tl *TrafficLogger) SubscribeFirewallEvents() (uint64, chan models.FirewallEvent) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.nextEventSubID++
	id := tl.nextEventSubID
	ch := make(chan models.FirewallEvent, 64)
	tl.eventSubscribers[id] = ch
	return id, ch
}

// UnsubscribeFirewallEvents unsubscribes and closes channel.
func (tl *TrafficLogger) UnsubscribeFirewallEvents(id uint64) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if ch, ok := tl.eventSubscribers[id]; ok {
		close(ch)
		delete(tl.eventSubscribers, id)
	}
}

// RecentEntries returns the last n log entries.
func (tl *TrafficLogger) RecentEntries(n int) []models.TrafficEntry {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	if n <= 0 || n > len(tl.entries) {
		n = len(tl.entries)
	}
	start := len(tl.entries) - n
	out := make([]models.TrafficEntry, n)
	copy(out, tl.entries[start:])
	return out
}

// TodayCounts returns the number of BLOCK and ALLOW events logged today.
func (tl *TrafficLogger) TodayCounts() (blocked int, allowed int) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	today := time.Now().Truncate(24 * time.Hour)
	for _, e := range tl.entries {
		if e.Timestamp.Before(today) {
			continue
		}
		upper := strings.ToUpper(e.Action)
		switch {
		case upper == "BLOCK" || upper == "DROP":
			blocked++
		case upper == "ALLOW" || upper == "ACCEPT":
			allowed++
		}
	}
	return
}

// Subscribe registers a channel to receive new log entries in real-time.
// Returns a subscription ID for unsubscribing.
func (tl *TrafficLogger) Subscribe() (uint64, chan models.TrafficEntry) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	tl.nextSubID++
	id := tl.nextSubID
	ch := make(chan models.TrafficEntry, 64)
	tl.subscribers[id] = ch
	return id, ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (tl *TrafficLogger) Unsubscribe(id uint64) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	if ch, ok := tl.subscribers[id]; ok {
		close(ch)
		delete(tl.subscribers, id)
	}
}

