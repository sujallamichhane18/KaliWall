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
	"kaliwall/internal/dpi/lite"
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
	defaultGeoCSVFile = "IP2LOCATION-LITE-DB1.CSV"
)

func main() {
	// CLI flags
	daemon := flag.Bool("daemon", false, "Run in background daemon mode")
	dpiEnable := flag.Bool("dpi", false, "Enable deep packet inspection pipeline")
	dpiIface := flag.String("dpi-interface", "", "Network interface for DPI capture (e.g. eth0)")
	dpiRules := flag.String("dpi-rules", "configs/dpi-rules.json", "Deprecated in lite mode; kept for CLI compatibility")
	dpiWorkers := flag.Int("dpi-workers", 0, "Number of DPI workers (default: CPU cores)")
	dpiPromisc := flag.Bool("dpi-promisc", true, "Enable promiscuous capture mode for DPI")
	dpiBPF := flag.String("dpi-bpf", "", "Optional BPF filter for DPI capture")
	dpiRateLimit := flag.Int("dpi-rate", 5000, "Deprecated in lite mode; kept for CLI compatibility")
	dpiLite := flag.Bool("dpi-lite", true, "Run lightweight IDS/DPI engine (HTTP/DNS/TLS + L3/L7 stats)")
	geoDBPath := flag.String("geo-db", defaultGeoDBFile, "Path to GeoIP database (.mmdb or IP2Location CSV)")
	flag.Parse()
	_ = dpiRules
	_ = dpiRateLimit

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
	geoDBRequestedPath := strings.TrimSpace(*geoDBPath)
	if savedGeoDBPath, ok := db.GetSetting("geo_db_path"); ok {
		savedGeoDBPath = strings.TrimSpace(savedGeoDBPath)
		if savedGeoDBPath != "" && (geoDBRequestedPath == "" || geoDBRequestedPath == defaultGeoDBFile) {
			geoDBRequestedPath = savedGeoDBPath
		}
	}
	if resolvedGeoDBPath, ok := resolveGeoDBPath(geoDBRequestedPath); ok {
		if svc, err := geoip.New(resolvedGeoDBPath); err != nil {
			log.Printf("GeoIP disabled (failed to load %s): %v", resolvedGeoDBPath, err)
		} else {
			geoSvc = svc
			defer geoSvc.Close()
			db.SetSetting("geo_db_path", resolvedGeoDBPath)
			fmt.Printf("[+] GeoIP enabled with DB: %s\n", resolvedGeoDBPath)
		}
	} else {
		log.Printf("GeoIP disabled: no database found. Set --geo-db <path> or KALIWALL_GEO_DB, or place %s / %s in project root/data/configs/internal/database.", defaultGeoDBFile, defaultGeoCSVFile)
	}

	dpiProvider := api.NewDPIProvider(nil)
	resolvedIface := *dpiIface
	if resolvedIface == "" {
		resolvedIface = defaultCaptureInterface()
	}
	if !*dpiLite {
		fmt.Printf("[!] --dpi-lite=false ignored: KaliWall now runs lite DPI engine only\n")
	}
	liteEngine := lite.New(lite.Config{
		Interface:   resolvedIface,
		Promiscuous: *dpiPromisc,
		BPF:         *dpiBPF,
		Workers:     *dpiWorkers,
	}, trafficLogger)
	dpiProvider.Set(liteEngine)
	fmt.Printf("[+] DPI mode: lightweight IDS/DPI (L3 + L7)\n")
	if *dpiEnable {
		if err := liteEngine.SetEnabled(true); err != nil {
			log.Printf("DPI requested but failed to start: %v", err)
		} else {
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
	liteEngine.Stop()
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
		add(defaultGeoCSVFile)
		add(filepath.Join("data", defaultGeoCSVFile))
		add(filepath.Join("configs", defaultGeoCSVFile))
		add(filepath.Join("internal", "database", defaultGeoCSVFile))
		if exe, err := os.Executable(); err == nil {
			dir := filepath.Dir(exe)
			add(filepath.Join(dir, defaultGeoDBFile))
			add(filepath.Join(dir, "data", defaultGeoDBFile))
			add(filepath.Join(dir, "configs", defaultGeoDBFile))
			add(filepath.Join(dir, defaultGeoCSVFile))
			add(filepath.Join(dir, "data", defaultGeoCSVFile))
			add(filepath.Join(dir, "configs", defaultGeoCSVFile))
			add(filepath.Join(dir, "internal", "database", defaultGeoCSVFile))
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
