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

	"kaliwall/internal/analytics"
	"kaliwall/internal/api"
	"kaliwall/internal/database"
	"kaliwall/internal/firewall"
	"kaliwall/internal/logger"
	"kaliwall/internal/netmon"
	"kaliwall/internal/threatintel"
)

const (
	listenAddr = ":8080"
	logDir     = "logs"
	logFile    = "logs/kaliwall.log"
	dbFile     = "data/kaliwall.json"
)

func main() {
	// CLI flags
	daemon := flag.Bool("daemon", false, "Run in background daemon mode")
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

	// Initialize REST API and web server
	handler := api.NewRouter(fw, trafficLogger, ti, analyticsService)

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
	monitor.Stop()
	analyticsService.Stop()
	// Persist VT key
	if key := ti.GetAPIKey(); key != "" {
		db.SetSetting("vt_api_key", key)
	}
	trafficLogger.Log("SYSTEM", "-", "-", "-", "Daemon stopped")
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
