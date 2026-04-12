package pipeline

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"

	"kaliwall/internal/dpi/action"
	"kaliwall/internal/dpi/capture"
	"kaliwall/internal/dpi/decode"
	"kaliwall/internal/dpi/flow"
	"kaliwall/internal/dpi/inspect"
	"kaliwall/internal/dpi/reassembly"
	"kaliwall/internal/dpi/rules"
	"kaliwall/internal/dpi/types"
	"kaliwall/internal/logger"
)

// Config controls end-to-end DPI pipeline behavior.
type Config struct {
	Interface       string
	Promiscuous     bool
	BPF             string
	RulesPath       string
	Workers         int
	FlowTimeout     time.Duration
	CleanupInterval time.Duration
	MaxFlowBytes    int
	MaxWindowBytes  int
	RateLimitPerSec int
}

// Status provides runtime DPI health and throughput counters.
type Status struct {
	Enabled       bool    `json:"enabled"`
	Running       bool    `json:"running"`
	Interface     string  `json:"interface"`
	Workers       int     `json:"workers"`
	RulesLoaded   int     `json:"rules_loaded"`
	UptimeSec     float64 `json:"uptime_sec"`
	PacketsSeen   uint64  `json:"packets_seen"`
	DecodeErrors  uint64  `json:"decode_errors"`
	ReasmErrors   uint64  `json:"reassembly_errors"`
	Allowed       uint64  `json:"allowed"`
	Blocked       uint64  `json:"blocked"`
	Logged        uint64  `json:"logged"`
	RateLimited   uint64  `json:"rate_limited"`
}

// Pipeline wires the full DPI processing path.
type Pipeline struct {
	cfg        Config
	capturer   capture.Capturer
	decoder    decode.Decoder
	tracker    *flow.Tracker
	reassembler reassembly.Reassembler
	inspector  *inspect.Engine
	ruleEngine *rules.Engine
	actions    *action.Engine

	inputCh chan gopacket.Packet
	wg      sync.WaitGroup
	stop    context.CancelFunc

	startedAt    time.Time
	running      atomic.Bool
	packetsSeen  atomic.Uint64
	decodeErrors atomic.Uint64
	reasmErrors  atomic.Uint64
	allowed      atomic.Uint64
	blocked      atomic.Uint64
	logged       atomic.Uint64
	rateLimited  atomic.Uint64
}

func New(cfg Config, l *logger.TrafficLogger, blocker action.IPBlocker) (*Pipeline, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("dpi interface is required")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = adaptiveWorkerCount(runtime.NumCPU())
	}

	ruleEngine, err := rules.LoadFromFile(cfg.RulesPath)
	if err != nil {
		return nil, err
	}

	c := capture.New(capture.Config{
		Interface:   cfg.Interface,
		Promiscuous: cfg.Promiscuous,
		BPF:         cfg.BPF,
	})

	t := flow.New(cfg.FlowTimeout, cfg.CleanupInterval, cfg.RateLimitPerSec)
	r := reassembly.New(reassembly.Config{
		MaxBytesPerFlow: cfg.MaxFlowBytes,
		MaxWindowBytes:  cfg.MaxWindowBytes,
		FlowTimeout:     cfg.FlowTimeout,
		CleanupInterval: cfg.CleanupInterval,
	})

	return &Pipeline{
		cfg:         cfg,
		capturer:    c,
		decoder:     decode.New(),
		tracker:     t,
		reassembler: r,
		inspector:   inspect.New(),
		ruleEngine:  ruleEngine,
		actions:     action.New(l, blocker),
		inputCh:     make(chan gopacket.Packet, 8192),
	}, nil
}

func (p *Pipeline) Start(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	p.stop = cancel

	if err := p.capturer.Start(ctx); err != nil {
		cancel()
		return err
	}
	p.tracker.Start()
	p.reassembler.Start()
	p.startedAt = time.Now()
	p.running.Store(true)

	p.wg.Add(1)
	go p.captureForwarder(ctx)

	p.wg.Add(1)
	go p.captureErrors(ctx)

	for i := 0; i < p.cfg.Workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}

	log.Printf("DPI started iface=%s workers=%d rules=%d", p.cfg.Interface, p.cfg.Workers, len(p.ruleEngine.Rules()))
	return nil
}

func (p *Pipeline) Stop() {
	if p.stop != nil {
		p.stop()
	}
	p.capturer.Close()
	p.tracker.Stop()
	p.reassembler.Stop()
	p.wg.Wait()
	p.running.Store(false)
	log.Printf("DPI stopped")
}

// Status returns pipeline runtime metrics for API/dashboard.
func (p *Pipeline) Status() Status {
	if p == nil {
		return Status{Enabled: false, Running: false}
	}
	uptime := 0.0
	if !p.startedAt.IsZero() {
		uptime = time.Since(p.startedAt).Seconds()
	}
	return Status{
		Enabled:      true,
		Running:      p.running.Load(),
		Interface:    p.cfg.Interface,
		Workers:      p.cfg.Workers,
		RulesLoaded:  len(p.ruleEngine.Rules()),
		UptimeSec:    uptime,
		PacketsSeen:  p.packetsSeen.Load(),
		DecodeErrors: p.decodeErrors.Load(),
		ReasmErrors:  p.reasmErrors.Load(),
		Allowed:      p.allowed.Load(),
		Blocked:      p.blocked.Load(),
		Logged:       p.logged.Load(),
		RateLimited:  p.rateLimited.Load(),
	}
}

func (p *Pipeline) captureForwarder(ctx context.Context) {
	defer p.wg.Done()
	defer close(p.inputCh)
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-p.capturer.Packets():
			if !ok {
				return
			}
			select {
			case p.inputCh <- pkt:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (p *Pipeline) captureErrors(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-p.capturer.Errors():
			if !ok {
				return
			}
			log.Printf("DPI capture error: %v", err)
		}
	}
}

func (p *Pipeline) worker(ctx context.Context, id int) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-p.inputCh:
			if !ok {
				return
			}
			p.packetsSeen.Add(1)
			decoded, err := p.decoder.Decode(pkt)
			if err != nil {
				p.decodeErrors.Add(1)
				if err == types.ErrUnsupportedPacket || err == types.ErrMalformedPacket {
					continue
				}
				continue
			}

			if p.tracker.IsRateLimited(decoded.Tuple.SrcIP) {
				p.rateLimited.Add(1)
				res := types.InspectResult{Timestamp: decoded.Timestamp, Tuple: decoded.Tuple, Protocol: decoded.Tuple.Protocol, Detections: []string{"rate_limit"}}
				if p.actions.Handle(res, rules.Decision{Action: types.ActionBlock, Type: "rate_limit", Reason: "source rate exceeded"}) {
					p.blocked.Add(1)
				} else {
					p.logged.Add(1)
				}
				continue
			}

			p.tracker.ObserveDecoded(decoded)
			payloads, err := p.reassembler.Process(decoded)
			if err != nil {
				p.reasmErrors.Add(1)
				log.Printf("DPI worker=%d reassembly error: %v", id, err)
				continue
			}

			for _, item := range payloads {
				result := p.inspector.Inspect(item)
				p.tracker.ObserveInspection(result)
				decision := p.ruleEngine.Evaluate(result)
				switch decision.Action {
				case types.ActionBlock:
					if p.actions.Handle(result, decision) {
						p.blocked.Add(1)
					} else {
						p.logged.Add(1)
					}
				case types.ActionLog:
					p.logged.Add(1)
					p.actions.Handle(result, decision)
				default:
					p.allowed.Add(1)
					p.actions.Handle(result, decision)
				}
			}
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func adaptiveWorkerCount(cpus int) int {
	if cpus <= 1 {
		return 1
	}
	if cpus <= 4 {
		return cpus
	}
	workers := cpus / 2
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}
	return workers
}
