package lite

import (
    "context"
    "fmt"
    "log"
    "net"
    "runtime"
    "sort"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/google/gopacket"

    "kaliwall/internal/dpi/capture"
    "kaliwall/internal/dpi/decode"
    "kaliwall/internal/dpi/flow"
    "kaliwall/internal/dpi/inspect"
    "kaliwall/internal/dpi/pipeline"
    "kaliwall/internal/dpi/reassembly"
    "kaliwall/internal/dpi/types"
    "kaliwall/internal/logger"
)

type IPCount struct {
    IP    string `json:"ip"`
    Count uint64 `json:"count"`
}

// Config controls lightweight IDS/DPI runtime behavior.
type Config struct {
    Interface   string
    Promiscuous bool
    BPF         string
    Workers     int
    InputQueueSize    int
    PacketBatchSize   int
    MaxTrackedIPs     int
    DetectionLogEvery int
    EmitEventLogs     bool

    // Threat indicator hooks used by DPI for feed-based enforcement.
    MaliciousIPMatcher     func(string) bool
    MaliciousDomainMatcher func(string) bool
    IsIPBlocked            func(string) bool
    IsWebsiteBlocked       func(string) bool
    BlockIP                func(string, string) error
    BlockWebsite           func(string, string) error
}

// Stats is a lightweight REST-friendly view for protocol detections.
type Stats struct {
    Enabled      bool      `json:"enabled"`
    Running      bool      `json:"running"`
    Interface    string    `json:"interface"`
    Workers      int       `json:"workers"`
    UptimeSec    float64   `json:"uptime_sec"`
    PacketsSeen  uint64    `json:"packets_seen"`
    DecodeErrors uint64    `json:"decode_errors"`

    HTTPDetected uint64    `json:"http_detected"`
    DNSDetected  uint64    `json:"dns_detected"`
    TLSDetected  uint64    `json:"tls_detected"`
    ICMPDetected uint64    `json:"icmp_detected"`

    IPv4Packets  uint64    `json:"ipv4_packets"`
    IPv6Packets  uint64    `json:"ipv6_packets"`
    TCPPackets   uint64    `json:"tcp_packets"`
    UDPPackets   uint64    `json:"udp_packets"`
    ICMPPackets  uint64    `json:"icmp_packets"`
    UniqueSrcIPs uint64    `json:"unique_src_ips"`
    UniqueDstIPs uint64    `json:"unique_dst_ips"`
    TopSrcIPs    []IPCount `json:"top_src_ips"`
    TopDstIPs    []IPCount `json:"top_dst_ips"`

    LastHTTP     string    `json:"last_http"`
    LastDNS      string    `json:"last_dns"`
    LastTLS      string    `json:"last_tls"`
    LastSeenAt   time.Time `json:"last_seen_at"`
    QueueDepth        int    `json:"queue_depth"`
    QueueCapacity     int    `json:"queue_capacity"`
    QueueDrops        uint64 `json:"queue_drops"`
    DetectionEvents   uint64 `json:"detection_events"`
    DetectionLogEvery int    `json:"detection_log_every"`
    MaxTrackedIPs     int    `json:"max_tracked_ips"`
    PacketLogs        uint64 `json:"packet_logs"`
    ActiveFlows       uint64 `json:"active_flows"`
    FlowEvicted       uint64 `json:"flow_evicted"`
    FlowExpired       uint64 `json:"flow_expired"`
    FlowClosed        uint64 `json:"flow_closed"`
}

// Engine is a lightweight live IDS/DPI processor focused on protocol extraction.
type Engine struct {
    cfgMu  sync.RWMutex
    cfg    Config
    logger *logger.TrafficLogger

    capturer capture.Capturer
    decoder  decode.Decoder
    inspect  *inspect.Engine
    reasm    reassembly.Reassembler
    tracker  *flow.Tracker

    inputCh chan gopacket.Packet
    stop    context.CancelFunc
    wg      sync.WaitGroup

    startedAt time.Time
    running   atomic.Bool
    enabled   atomic.Bool

    packetsSeen  atomic.Uint64
    decodeErrors atomic.Uint64
    httpDetected atomic.Uint64
    dnsDetected  atomic.Uint64
    tlsDetected  atomic.Uint64
    icmpDetected atomic.Uint64

    ipv4Packets atomic.Uint64
    ipv6Packets atomic.Uint64
    tcpPackets  atomic.Uint64
    udpPackets  atomic.Uint64
    icmpPackets atomic.Uint64
    packetLogged    atomic.Uint64
    queueDrops      atomic.Uint64
    detectionEvents atomic.Uint64

    metaMu     sync.RWMutex
    lastHTTP   string
    lastDNS    string
    lastTLS    string
    lastSeenAt time.Time
    srcHits    map[string]uint64
    dstHits    map[string]uint64
}

// New creates a lightweight IDS/DPI engine.
func New(cfg Config, tl *logger.TrafficLogger) *Engine {
    if cfg.Workers <= 0 {
        cfg.Workers = defaultWorkerCount(runtime.NumCPU())
    }
    if cfg.Workers < 1 {
        cfg.Workers = 1
    }
    if cfg.Workers > 256 {
        cfg.Workers = 256
    }
    if cfg.InputQueueSize <= 0 {
        cfg.InputQueueSize = 8192
    }
    if cfg.PacketBatchSize <= 0 {
        cfg.PacketBatchSize = 32
    }
    if cfg.MaxTrackedIPs <= 0 {
        cfg.MaxTrackedIPs = 50000
    }
    if cfg.DetectionLogEvery <= 0 {
        cfg.DetectionLogEvery = 1
    }
    if cfg.DetectionLogEvery > 1 {
        cfg.DetectionLogEvery = 1
    }

    c := capture.New(capture.Config{
        Interface:   cfg.Interface,
        Promiscuous: cfg.Promiscuous,
        BPF:         cfg.BPF,
    })

    flowMax := max(cfg.MaxTrackedIPs*2, 20000)
    tracker := flow.NewWithConfig(flow.TrackerConfig{
        ShardCount:      64,
        MaxFlows:        flowMax,
        FlowTimeout:     2 * time.Minute,
        ClosedFlowTTL:   20 * time.Second,
        CleanupInterval: 30 * time.Second,
        RateLimitPerSec: 0,
    })

    return &Engine{
        cfg:     cfg,
        logger:  tl,
        capturer: c,
        decoder: decode.New(),
        inspect: inspect.New(),
        tracker: tracker,
        reasm: reassembly.New(reassembly.Config{
            MaxBytesPerFlow: 1 << 20,
            MaxWindowBytes:  8192,
            FlowTimeout:     2 * time.Minute,
            CleanupInterval: 30 * time.Second,
        }),
        inputCh: make(chan gopacket.Packet, cfg.InputQueueSize),
        srcHits: make(map[string]uint64, 4096),
        dstHits: make(map[string]uint64, 4096),
    }
}

// SetEnabled starts/stops the lightweight engine.
func (e *Engine) SetEnabled(enabled bool) error {
    if enabled {
        return e.Start(context.Background())
    }
    e.Stop()
    return nil
}

// Start begins capture + workers.
func (e *Engine) Start(parent context.Context) error {
    if e.running.Load() {
        e.enabled.Store(true)
        return nil
    }

    ctx, cancel := context.WithCancel(parent)
    if err := e.capturer.Start(ctx); err != nil {
        cancel()
        return err
    }

    e.stop = cancel
    e.startedAt = time.Now()
    e.running.Store(true)
    e.enabled.Store(true)
    e.inputCh = make(chan gopacket.Packet, e.queueCapacity())
    e.tracker.Start()
    e.reasm.Start()

    e.wg.Add(1)
    go e.forwardPackets(ctx)

    e.wg.Add(1)
    go e.captureErrors(ctx)

    workers := e.workerCount()
    for i := 0; i < workers; i++ {
        e.wg.Add(1)
        go e.worker(ctx)
    }

    log.Printf("DPI lite started iface=%s workers=%d", e.interfaceName(), workers)
    return nil
}

// SetWorkers updates worker concurrency; if engine is running it restarts capture.
func (e *Engine) SetWorkers(workers int) error {
    if workers < 1 || workers > 256 {
        return fmt.Errorf("workers must be between 1 and 256")
    }
    wasRunning := e.running.Load()

    e.cfgMu.Lock()
    e.cfg.Workers = workers
    e.cfgMu.Unlock()

    if !wasRunning {
        return nil
    }

    e.Stop()
    return e.Start(context.Background())
}

// Stop halts capture/workers.
func (e *Engine) Stop() {
    if e.stop != nil {
        e.stop()
    }
    _ = e.capturer.Close()
    e.tracker.Stop()
    e.reasm.Stop()
    e.wg.Wait()
    e.running.Store(false)
    e.enabled.Store(false)
    log.Printf("DPI lite stopped")
}

// Status returns compact status for compatibility with existing API.
func (e *Engine) Status() pipeline.Status {
    uptime := 0.0
    if !e.startedAt.IsZero() {
        uptime = time.Since(e.startedAt).Seconds()
    }
    return pipeline.Status{
        Enabled:      e.enabled.Load(),
        Running:      e.running.Load(),
        Interface:    e.interfaceName(),
        Workers:      e.workerCount(),
        RulesLoaded:  0,
        UptimeSec:    uptime,
        PacketsSeen:  e.packetsSeen.Load(),
        DecodeErrors: e.decodeErrors.Load(),
        ReasmErrors:  0,
        Allowed:      0,
        Blocked:      0,
        Logged:       e.packetLogged.Load(),
        RateLimited:  0,
    }
}

// DetailedStats returns protocol-level counters and last-seen artifacts.
func (e *Engine) DetailedStats() Stats {
    e.metaMu.RLock()
    lastHTTP := e.lastHTTP
    lastDNS := e.lastDNS
    lastTLS := e.lastTLS
    lastSeen := e.lastSeenAt
    uniqueSrc := uint64(len(e.srcHits))
    uniqueDst := uint64(len(e.dstHits))
    topSrc := topN(e.srcHits, 8)
    topDst := topN(e.dstHits, 8)
    e.metaMu.RUnlock()

    uptime := 0.0
    if !e.startedAt.IsZero() {
        uptime = time.Since(e.startedAt).Seconds()
    }
    flowStats := e.tracker.Stats()

    return Stats{
        Enabled:      e.enabled.Load(),
        Running:      e.running.Load(),
        Interface:    e.interfaceName(),
        Workers:      e.workerCount(),
        UptimeSec:    uptime,
        PacketsSeen:  e.packetsSeen.Load(),
        DecodeErrors: e.decodeErrors.Load(),
        HTTPDetected: e.httpDetected.Load(),
        DNSDetected:  e.dnsDetected.Load(),
        TLSDetected:  e.tlsDetected.Load(),
        ICMPDetected: e.icmpDetected.Load(),
        IPv4Packets:  e.ipv4Packets.Load(),
        IPv6Packets:  e.ipv6Packets.Load(),
        TCPPackets:   e.tcpPackets.Load(),
        UDPPackets:   e.udpPackets.Load(),
        ICMPPackets:  e.icmpPackets.Load(),
        UniqueSrcIPs: uniqueSrc,
        UniqueDstIPs: uniqueDst,
        TopSrcIPs:    topSrc,
        TopDstIPs:    topDst,
        LastHTTP:     lastHTTP,
        LastDNS:      lastDNS,
        LastTLS:      lastTLS,
        LastSeenAt:   lastSeen,
        QueueDepth:        e.queueDepth(),
        QueueCapacity:     e.queueCapacity(),
        QueueDrops:        e.queueDrops.Load(),
        DetectionEvents:   e.detectionEvents.Load(),
        DetectionLogEvery: e.detectionLogEvery(),
        MaxTrackedIPs:     e.maxTrackedIPs(),
        PacketLogs:        e.packetLogged.Load(),
        ActiveFlows:       uint64(flowStats.ActiveFlows),
        FlowEvicted:       flowStats.EvictedFlows,
        FlowExpired:       flowStats.ExpiredFlows,
        FlowClosed:        flowStats.ClosedFlows,
    }
}

func (e *Engine) workerCount() int {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.Workers
}

func (e *Engine) interfaceName() string {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.Interface
}

func (e *Engine) forwardPackets(ctx context.Context) {
    defer e.wg.Done()
    defer close(e.inputCh)
    for {
        select {
        case <-ctx.Done():
            return
        case pkt, ok := <-e.capturer.Packets():
            if !ok {
                return
            }
            select {
            case e.inputCh <- pkt:
            default:
                if dropped := e.queueDrops.Add(1); dropped%2000 == 0 {
                    log.Printf("DPI lite backpressure: dropped=%d queue=%d/%d", dropped, e.queueDepth(), e.queueCapacity())
                }
            case <-ctx.Done():
                return
            }
        }
    }
}

func (e *Engine) captureErrors(ctx context.Context) {
    defer e.wg.Done()
    for {
        select {
        case <-ctx.Done():
            return
        case err, ok := <-e.capturer.Errors():
            if !ok {
                return
            }
            log.Printf("DPI lite capture error: %v", err)
        }
    }
}

func (e *Engine) worker(ctx context.Context) {
    defer e.wg.Done()
    for {
        select {
        case <-ctx.Done():
            return
        case pkt, ok := <-e.inputCh:
            if !ok {
                return
            }
            e.processPacket(pkt)

            for i := 1; i < e.packetBatchSize(); i++ {
                select {
                case pkt, ok := <-e.inputCh:
                    if !ok {
                        return
                    }
                    e.processPacket(pkt)
                default:
                    i = e.packetBatchSize()
                }
            }
        }
    }
}

func (e *Engine) processPacket(pkt gopacket.Packet) {
    e.packetsSeen.Add(1)
    decoded, err := e.decoder.Decode(pkt)
    if err != nil {
        if err != types.ErrUnsupportedPacket {
            e.decodeErrors.Add(1)
        }
        return
    }

    e.logPacketBrief(decoded)
    e.recordL3(decoded)
    e.enforceIPIndicatorTuple(decoded.Tuple)
    e.tracker.ObserveDecoded(decoded)

    payloads, err := e.reasm.Process(decoded)
    if err != nil {
        e.decodeErrors.Add(1)
        return
    }
    for _, payload := range payloads {
        result := e.inspect.Inspect(payload)
        e.tracker.ObserveInspection(result)
        e.record(result)
    }
}

func (e *Engine) recordL3(decoded *types.DecodedPacket) {
    if decoded == nil {
        return
    }
    if decoded.IPVersion == 4 {
        e.ipv4Packets.Add(1)
    } else if decoded.IPVersion == 6 {
        e.ipv6Packets.Add(1)
    }
    switch decoded.Tuple.Protocol {
    case "tcp":
        e.tcpPackets.Add(1)
    case "udp":
        e.udpPackets.Add(1)
    case "icmp", "icmpv6":
        e.icmpPackets.Add(1)
        e.icmpDetected.Add(1)
    }

    e.metaMu.Lock()
    if decoded.Tuple.SrcIP != "" {
        if _, ok := e.srcHits[decoded.Tuple.SrcIP]; ok || len(e.srcHits) < e.maxTrackedIPs() {
            e.srcHits[decoded.Tuple.SrcIP]++
        }
    }
    if decoded.Tuple.DstIP != "" {
        if _, ok := e.dstHits[decoded.Tuple.DstIP]; ok || len(e.dstHits) < e.maxTrackedIPs() {
            e.dstHits[decoded.Tuple.DstIP]++
        }
    }
    e.metaMu.Unlock()
}

func (e *Engine) record(result types.InspectResult) {
	e.enforceIndicatorBlocks(result)

    seen := false

    if result.HTTPMethod != "" {
        e.httpDetected.Add(1)
        e.detectionEvents.Add(1)
        seen = true
        target := strings.TrimSpace(result.HTTPHost)
        if target == "" {
            target = strings.TrimSpace(result.HTTPURL)
        }
        msg := briefText("HTTP "+strings.ToUpper(strings.TrimSpace(result.HTTPMethod))+" "+target, 96)
        log.Println(msg)
        if e.logger != nil && e.emitEventLogs() {
            e.logger.Log("LOG", result.Tuple.SrcIP, result.Tuple.DstIP, "http", "dpi:"+msg)
        }
        e.metaMu.Lock()
        e.lastHTTP = msg
        e.lastSeenAt = time.Now()
        e.metaMu.Unlock()
    }

    if result.DNSDomain != "" {
        e.dnsDetected.Add(1)
        e.detectionEvents.Add(1)
        seen = true
        msg := briefText("DNS "+strings.TrimSpace(result.DNSDomain), 96)
        log.Println(msg)
        if e.logger != nil && e.emitEventLogs() {
            e.logger.Log("LOG", result.Tuple.SrcIP, result.Tuple.DstIP, "dns", "dpi:"+msg)
        }
        e.metaMu.Lock()
        e.lastDNS = msg
        e.lastSeenAt = time.Now()
        e.metaMu.Unlock()
    }

    if result.TLSSNI != "" {
        e.tlsDetected.Add(1)
        e.detectionEvents.Add(1)
        seen = true
        msg := briefText("TLS "+strings.TrimSpace(result.TLSSNI), 96)
        log.Println(msg)
        if e.logger != nil && e.emitEventLogs() {
            e.logger.Log("LOG", result.Tuple.SrcIP, result.Tuple.DstIP, "tls", "dpi:"+msg)
        }
        e.metaMu.Lock()
        e.lastTLS = msg
        e.lastSeenAt = time.Now()
        e.metaMu.Unlock()
    }

    if seen {
        return
    }
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

func defaultWorkerCount(cpus int) int {
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

func (e *Engine) queueDepth() int {
    if e.inputCh == nil {
        return 0
    }
    return len(e.inputCh)
}

func (e *Engine) queueCapacity() int {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.InputQueueSize
}

func (e *Engine) packetBatchSize() int {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.PacketBatchSize
}

func (e *Engine) maxTrackedIPs() int {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.MaxTrackedIPs
}

func (e *Engine) detectionLogEvery() int {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.DetectionLogEvery
}

func (e *Engine) emitEventLogs() bool {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.EmitEventLogs
}

func (e *Engine) maliciousIPMatcher() func(string) bool {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.MaliciousIPMatcher
}

func (e *Engine) maliciousDomainMatcher() func(string) bool {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.MaliciousDomainMatcher
}

func (e *Engine) isIPBlocked() func(string) bool {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.IsIPBlocked
}

func (e *Engine) isWebsiteBlocked() func(string) bool {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.IsWebsiteBlocked
}

func (e *Engine) ipBlocker() func(string, string) error {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.BlockIP
}

func (e *Engine) websiteBlocker() func(string, string) error {
    e.cfgMu.RLock()
    defer e.cfgMu.RUnlock()
    return e.cfg.BlockWebsite
}

func (e *Engine) shouldEmitSampledDetectionLog() bool {
    every := e.detectionLogEvery()
    n := e.detectionEvents.Add(1)
    if every <= 1 {
        return true
    }
    return n%uint64(every) == 0
}

func (e *Engine) logPacketBrief(decoded *types.DecodedPacket) {
    if decoded == nil || e.logger == nil {
        return
    }
    proto := strings.ToLower(strings.TrimSpace(decoded.Tuple.Protocol))
    if proto == "" {
        proto = "ip"
    }
    detail := fmt.Sprintf(
        "dpi:packet src=%s:%d dst=%s:%d proto=%s bytes=%d",
        strings.TrimSpace(decoded.Tuple.SrcIP),
        decoded.Tuple.SrcPort,
        strings.TrimSpace(decoded.Tuple.DstIP),
        decoded.Tuple.DstPort,
        proto,
        len(decoded.Payload),
    )
    if decoded.DNSQuery != "" {
        detail += " dns=" + strings.TrimSpace(decoded.DNSQuery)
    }
    e.logger.Log("LOG", decoded.Tuple.SrcIP, decoded.Tuple.DstIP, proto, briefText(detail, 180))
    e.packetLogged.Add(1)
}

func (e *Engine) enforceIndicatorBlocks(result types.InspectResult) {
    domainMatcher := e.maliciousDomainMatcher()
    if domainMatcher == nil {
        return
    }

    seenDomains := make(map[string]struct{}, 3)
    for _, raw := range []string{result.DNSDomain, result.TLSSNI, result.HTTPHost} {
        domain := normalizeIndicatorDomain(raw)
        if domain == "" {
            continue
        }
        if _, exists := seenDomains[domain]; exists {
            continue
        }
        seenDomains[domain] = struct{}{}
        if domainMatcher(domain) {
            e.maybeBlockDomainIndicator(domain, result)
        }
    }
}

func (e *Engine) enforceIPIndicatorTuple(tuple types.FiveTuple) {
    ipMatcher := e.maliciousIPMatcher()
    if ipMatcher == nil {
        return
    }

    result := types.InspectResult{Tuple: tuple}
    seenIPs := make(map[string]struct{}, 2)
    for _, candidate := range []string{strings.TrimSpace(tuple.SrcIP), strings.TrimSpace(tuple.DstIP)} {
        if candidate == "" || net.ParseIP(candidate) == nil {
            continue
        }
        if _, exists := seenIPs[candidate]; exists {
            continue
        }
        seenIPs[candidate] = struct{}{}
        if ipMatcher(candidate) {
            e.maybeBlockIPIndicator(candidate, result)
        }
    }
}

func (e *Engine) maybeBlockIPIndicator(ip string, result types.InspectResult) {
    if ip == "" {
        return
    }
    if isBlocked := e.isIPBlocked(); isBlocked != nil && isBlocked(ip) {
        return
    }
    blocker := e.ipBlocker()
    if blocker == nil {
        return
    }
    if err := blocker(ip, "DPI malicious IP indicator match"); err != nil {
        if e.logger != nil {
            e.logger.Log("ERROR", result.Tuple.SrcIP, result.Tuple.DstIP, "dpi", briefText("dpi:failed to auto-block malicious ip "+ip+": "+err.Error(), 180))
        }
        return
    }
    if e.logger != nil {
        e.logger.Log("BLOCK", result.Tuple.SrcIP, result.Tuple.DstIP, "dpi", briefText("dpi:auto-blocked malicious ip indicator "+ip, 180))
    }
}

func (e *Engine) maybeBlockDomainIndicator(domain string, result types.InspectResult) {
    if domain == "" {
        return
    }
    if isBlocked := e.isWebsiteBlocked(); isBlocked != nil && isBlocked(domain) {
        return
    }
    blocker := e.websiteBlocker()
    if blocker == nil {
        return
    }
    if err := blocker(domain, "DPI malicious domain indicator match"); err != nil {
        if e.logger != nil {
            e.logger.Log("ERROR", result.Tuple.SrcIP, result.Tuple.DstIP, "dpi", briefText("dpi:failed to auto-block malicious domain "+domain+": "+err.Error(), 180))
        }
        return
    }
    if e.logger != nil {
        e.logger.Log("BLOCK", result.Tuple.SrcIP, result.Tuple.DstIP, "dpi", briefText("dpi:auto-blocked malicious domain indicator "+domain, 180))
    }
}

func normalizeIndicatorDomain(raw string) string {
    domain := strings.TrimSpace(strings.ToLower(raw))
    domain = strings.TrimPrefix(domain, "*.")
    domain = strings.TrimPrefix(domain, "http://")
    domain = strings.TrimPrefix(domain, "https://")
    if idx := strings.IndexAny(domain, "/?#"); idx >= 0 {
        domain = domain[:idx]
    }
    if idx := strings.IndexByte(domain, ':'); idx >= 0 {
        domain = domain[:idx]
    }
    return strings.TrimSuffix(domain, ".")
}

func briefText(s string, maxLen int) string {
    s = strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
    if s == "" {
        return "dpi event"
    }
    if maxLen <= 3 || len(s) <= maxLen {
        return s
    }
    return s[:maxLen-3] + "..."
}

func topN(m map[string]uint64, n int) []IPCount {
    if len(m) == 0 || n <= 0 {
        return nil
    }
    items := make([]IPCount, 0, len(m))
    for ip, count := range m {
        items = append(items, IPCount{IP: ip, Count: count})
    }
    sort.Slice(items, func(i, j int) bool {
        if items[i].Count == items[j].Count {
            return items[i].IP < items[j].IP
        }
        return items[i].Count > items[j].Count
    })
    if len(items) > n {
        items = items[:n]
    }
    return items
}
