// KaliWall - Linux Firewall Management Daemon
// Main entry point: initializes firewall engine, logger, REST API, and web UI server.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"strings"

	"kaliwall/internal/analytics"
	"kaliwall/internal/api"
	"kaliwall/internal/database"
	"kaliwall/internal/dpi/pipeline"
	"kaliwall/internal/firewall"
	"kaliwall/internal/geoip"
	"kaliwall/internal/logger"
	"kaliwall/internal/netmon"
	"kaliwall/internal/threatintel"

	"github.com/google/gopacket/pcap"
)

const (
	listenAddr = ":8080"
	logDir     = "logs"
	logFile    = "logs/kaliwall.log"
	dbFile     = "data/kaliwall.json"
	defaultGeoDBFile = "GeoLite2-City.mmdb"
)

func main() {
	// CLI flags
	daemon := flag.Bool("daemon", false, "Run in background daemon mode")
	dpiEnable := flag.Bool("dpi", false, "Enable deep packet inspection pipeline")
	dpiIface := flag.String("dpi-interface", "", "Network interface for DPI capture (e.g. eth0)")
	dpiRules := flag.String("dpi-rules", "configs/dpi-rules.yaml", "Path to DPI rules file (yaml/json)")
	dpiWorkers := flag.Int("dpi-workers", 0, "Number of DPI workers (default: CPU cores)")
	dpiPromisc := flag.Bool("dpi-promisc", true, "Enable promiscuous capture mode for DPI")
	dpiBPF := flag.String("dpi-bpf", "", "Optional BPF filter for DPI capture")
	dpiRateLimit := flag.Int("dpi-rate", 5000, "Per-source packet rate limit per second")
	geoDBPath := flag.String("geo-db", defaultGeoDBFile, "Path to MaxMind GeoLite2 City database (.mmdb)")
	flag.Parse()

	// If --daemon, fork to background
	if *daemon {
		runDaemon()
		return
	}

	fmt.Println("===================================")
	fmt.Println("  KaliWall - Linux Firewall Daemon")
	fmt.Println("===================================")

	// Ensure directories exist
	if err := os.MkdirAll(logDir, 0750); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(dbFile), 0750); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Initialize persistent database
	db, err := database.Open(dbFile)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	// Initialize traffic logger
	trafficLogger, err := logger.New(logFile)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer trafficLogger.Close()

	// Initialize firewall engine with database
	fw := firewall.New(trafficLogger, db)

	// Initialize threat intelligence service (VirusTotal)
	ti := threatintel.New()
	// Restore API key from database
	if key, ok := db.GetSetting("vt_api_key"); ok && key != "" {
		ti.SetAPIKey(key)
		fmt.Println("[+] VirusTotal API key restored from database")
	}

	// Start real-time network monitor
	monitor := netmon.New(trafficLogger)
	monitor.Start()

	// Start analytics engine (bandwidth sampling)
	analyticsService := analytics.New(trafficLogger)
	analyticsService.Start()

	var geoSvc *geoip.Service
	if resolvedGeoDBPath, ok := resolveGeoDBPath(*geoDBPath); ok {
		if svc, err := geoip.New(resolvedGeoDBPath); err != nil {
			log.Printf("GeoIP disabled (failed to load %s): %v", resolvedGeoDBPath, err)
		} else {
			geoSvc = svc
			defer geoSvc.Close()
			fmt.Printf("[+] GeoIP enabled with DB: %s\n", resolvedGeoDBPath)
		}
	} else {
		log.Printf("GeoIP disabled: %s not found. Set --geo-db <path> or KALIWALL_GEO_DB, or place DB in project root/data/configs.", defaultGeoDBFile)
	}

	var dpiPipe *pipeline.Pipeline
	dpiProvider := api.NewDPIProvider(nil)
	resolvedIface := *dpiIface
	if resolvedIface == "" {
		resolvedIface = defaultCaptureInterface()
	}
	dpiCfg := pipeline.Config{
		Interface:       resolvedIface,
		Promiscuous:     *dpiPromisc,
		BPF:             *dpiBPF,
		RulesPath:       *dpiRules,
		Workers:         *dpiWorkers,
		FlowTimeout:     2 * time.Minute,
		CleanupInterval: 30 * time.Second,
		MaxFlowBytes:    1 << 20,
		MaxWindowBytes:  8192,
		RateLimitPerSec: *dpiRateLimit,
	}
	dpiManager := pipeline.NewManager(dpiCfg, trafficLogger)
	dpiProvider.Set(dpiManager)
	if *dpiEnable {
		if err := dpiManager.SetEnabled(true); err != nil {
			log.Printf("DPI requested but failed to start: %v", err)
		} else {
			dpiPipe = nil
			fmt.Printf("[+] DPI enabled on interface: %s\n", resolvedIface)
		}
	}

	// Initialize REST API and web server
	handler := api.NewRouter(fw, trafficLogger, ti, analyticsService, dpiProvider, geoSvc)

	// Graceful shutdown on SIGINT/SIGTERM
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		fmt.Printf("\n[+] KaliWall web UI:  http://localhost%s\n", listenAddr)
		fmt.Printf("[+] REST API base:   http://localhost%s/api/v1\n", listenAddr)
		fmt.Println("[+] Press Ctrl+C to stop the daemon.\n")

		if err := http.ListenAndServe(listenAddr, handler); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	<-stop
	fmt.Println("\n[*] Shutting down KaliWall daemon...")
	if dpiPipe != nil {
		dpiPipe.Stop()
	}
	dpiManager.Stop()
	monitor.Stop()
	analyticsService.Stop()
	// Persist VT key
	if key := ti.GetAPIKey(); key != "" {
		db.SetSetting("vt_api_key", key)
	}
	trafficLogger.Log("SYSTEM", "-", "-", "-", "Daemon stopped")
}

func defaultCaptureInterface() string {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return ""
	}
	for _, d := range devs {
		if d.Name == "" {
			continue
		}
		if strings.HasPrefix(d.Name, "lo") || strings.Contains(strings.ToLower(d.Description), "loopback") {
			continue
		}
		if len(d.Addresses) > 0 {
			return d.Name
		}
	}
	if len(devs) > 0 {
		return devs[0].Name
	}
	return ""
}

func resolveGeoDBPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	seen := make(map[string]struct{})
	candidates := make([]string, 0, 12)

	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		clean := filepath.Clean(p)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		candidates = append(candidates, clean)
	}

	if envPath := strings.TrimSpace(os.Getenv("KALIWALL_GEO_DB")); envPath != "" {
		add(envPath)
	}
	if raw != "" {
		add(raw)
	}

	if raw == "" || raw == defaultGeoDBFile {
		add(defaultGeoDBFile)
		add(filepath.Join("data", defaultGeoDBFile))
		add(filepath.Join("configs", defaultGeoDBFile))
		add(filepath.Join("geoip", defaultGeoDBFile))
		if exe, err := os.Executable(); err == nil {
			dir := filepath.Dir(exe)
			add(filepath.Join(dir, defaultGeoDBFile))
			add(filepath.Join(dir, "data", defaultGeoDBFile))
			add(filepath.Join(dir, "configs", defaultGeoDBFile))
		}
	}

	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, true
		}
	}
	return "", false
}

// runDaemon forks the process into background.
func runDaemon() {
	exe, _ := os.Executable()
	attr := &os.ProcAttr{
		Dir: filepath.Dir(exe),
		Env: os.Environ(),
		Files: []*os.File{
			os.Stdin,
			nil, // stdout to /dev/null
			nil, // stderr to /dev/null
		},
	}
	// Re-launch without --daemon flag
	args := []string{exe}
	for _, a := range os.Args[1:] {
		if a != "--daemon" && a != "-daemon" {
			args = append(args, a)
		}
	}
	proc, err := os.StartProcess(exe, args, attr)
	if err != nil {
		log.Fatalf("Failed to daemonize: %v", err)
	}
	// Write PID file
	pidFile := filepath.Join(filepath.Dir(exe), "kaliwall.pid")
	os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", proc.Pid)), 0644)
	fmt.Printf("[+] KaliWall daemon started (PID %d)\n", proc.Pid)
	fmt.Printf("[+] PID file: %s\n", pidFile)
	proc.Release()
}
