package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/nawasara/agent/internal/analyzer"
	"github.com/nawasara/agent/internal/collector"
	"github.com/nawasara/agent/internal/config"
	"github.com/nawasara/agent/internal/reporter"
)

var (
	cfgPath string
	debug   bool
)

func main() {
	root := &cobra.Command{
		Use:   "nawasara-agent",
		Short: "Nawasara Security Agent — lightweight VM security monitor",
	}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Start the agent daemon",
		RunE:  runAgent,
	}
	runCmd.Flags().StringVarP(&cfgPath, "config", "c", "/etc/nawasara-agent/config.yaml", "config file path")
	runCmd.Flags().BoolVar(&debug, "debug", false, "enable debug logging")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print agent version",
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("nawasara-agent", reporter.Version)
		},
	}

	root.AddCommand(runCmd, versionCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runAgent(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	if cfg.APIKey == "" {
		log.Fatal("api_key not set in config")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Shared event bus: all collectors → single channel
	eventBus := make(chan collector.Event, 10_000)

	// Incident channel: analyzer → reporter
	incidentCh := make(chan analyzer.Incident, 1_000)

	// Load rules: try rules_dir first, fall back to built-in defaults
	rules, err := analyzer.LoadRules(cfg.Analyzer.RulesDir)
	if err != nil || len(rules) == 0 {
		if debug {
			log.Printf("rules dir %s not available, using built-in defaults", cfg.Analyzer.RulesDir)
		}
		rules = analyzer.DefaultRules()
	}
	log.Printf("loaded %d rules", len(rules))

	// Analyzer engine
	engine := analyzer.NewEngine(rules, cfg.Analyzer.CorrelationWindow, incidentCh)

	// Start collectors based on config
	var collectors []interface{ Stop() }

	webServer := cfg.Collector.WebServer
	if webServer == "auto" {
		webServer = detectWebServer()
	}

	switch webServer {
	case "nginx":
		c := collector.NewNginxCollector(cfg.Collector.LogPaths.Nginx.Access, eventBus)
		c.Start()
		collectors = append(collectors, c)
		log.Printf("nginx collector started: %s", cfg.Collector.LogPaths.Nginx.Access)
	case "apache":
		c := collector.NewNginxCollector(cfg.Collector.LogPaths.Apache.Access, eventBus) // same format
		c.Start()
		collectors = append(collectors, c)
		log.Printf("apache collector started: %s", cfg.Collector.LogPaths.Apache.Access)
	}

	sshLog := cfg.Collector.SSHLog
	if sshLog == "auto" {
		sshLog = detectSSHLog()
	}
	if sshLog != "" {
		c := collector.NewSSHCollector(sshLog, eventBus)
		c.Start()
		collectors = append(collectors, c)
		log.Printf("ssh collector started: %s", sshLog)
	}

	// Reporter (with SQLite buffer)
	rep, err := reporter.New(cfg)
	if err != nil {
		return err
	}
	defer rep.Close()

	go rep.RetryLoop(ctx)

	// Main event dispatch loop
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-eventBus:
				switch ev.Type {
				case collector.EventLog:
					engine.ProcessLog(ev.Log)
				case collector.EventSSH:
					engine.ProcessSSH(ev.SSH)
				}
			}
		}
	}()

	// Incident → reporter
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case inc := <-incidentCh:
				log.Printf("[%s] incident: %s from %s (score=%d)", inc.Severity, inc.Type, inc.SourceIP, inc.Score)
				rep.Send(inc)
			}
		}
	}()

	// Heartbeat loop
	go func() {
		ticker := time.NewTicker(cfg.Reporter.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				metrics := &collector.SystemMetrics{Timestamp: time.Now()}
				rep.SendHeartbeat(metrics, cfg.Plugins.Enabled, rep.PendingCount(), 100)
			}
		}
	}()

	log.Printf("nawasara-agent %s started (agent_id=%s dashboard=%s)", reporter.Version, cfg.AgentID, cfg.DashboardURL)
	<-ctx.Done()

	log.Println("shutting down...")
	for _, c := range collectors {
		c.Stop()
	}
	return nil
}

func detectWebServer() string {
	if fileExists("/var/log/nginx/access.log") || fileExists("/etc/nginx/nginx.conf") {
		return "nginx"
	}
	if fileExists("/var/log/apache2/access.log") || fileExists("/etc/apache2/apache2.conf") {
		return "apache"
	}
	if fileExists("/var/log/httpd/access_log") || fileExists("/etc/httpd/conf/httpd.conf") {
		return "apache"
	}
	return "nginx" // default
}

func detectSSHLog() string {
	candidates := []string{"/var/log/auth.log", "/var/log/secure"}
	for _, p := range candidates {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
