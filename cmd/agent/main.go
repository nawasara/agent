package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/nawasara/agent/internal/analyzer"
	"github.com/nawasara/agent/internal/collector"
	"github.com/nawasara/agent/internal/config"
	"github.com/nawasara/agent/internal/health"
	"github.com/nawasara/agent/internal/plugin"
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

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show agent status (reads config, checks service)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			log.Printf("agent_id:      %s", cfg.AgentID)
			log.Printf("agent_name:    %s", cfg.AgentName)
			log.Printf("dashboard_url: %s", cfg.DashboardURL)
			log.Printf("plugins:       %v", cfg.Plugins.Enabled)
			return nil
		},
	}
	statusCmd.Flags().StringVarP(&cfgPath, "config", "c", "/etc/nawasara-agent/config.yaml", "config file path")

	root.AddCommand(runCmd, versionCmd, statusCmd)

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
		log.Fatal("api_key not set in config — edit /etc/nawasara-agent/config.yaml")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Plugin manager
	plugins := plugin.NewManager(cfg.Plugins.Dir, cfg.Plugins.Enabled)
	plugins.Load()

	// Shared event bus: all collectors → single buffered channel
	eventBus := make(chan collector.Event, 10_000)

	// Incident channel: analyzer → reporter
	incidentCh := make(chan analyzer.Incident, 1_000)

	// Load rules
	rules, err := analyzer.LoadRules(cfg.Analyzer.RulesDir)
	if err != nil || len(rules) == 0 {
		if debug {
			log.Printf("rules dir %s not available, using built-in defaults", cfg.Analyzer.RulesDir)
		}
		rules = analyzer.DefaultRules()
	}
	log.Printf("loaded %d detection rules", len(rules))

	engine := analyzer.NewEngine(rules, cfg.Analyzer.CorrelationWindow, incidentCh)

	// Start collectors
	var (
		stopFns []func()
		wg      sync.WaitGroup
	)

	startCollector := func(name string, start func(), stop func()) {
		start()
		stopFns = append(stopFns, stop)
		log.Printf("[collector] %s started", name)
	}

	webServer := cfg.Collector.WebServer
	if webServer == "auto" {
		webServer = detectWebServer()
	}
	switch webServer {
	case "nginx":
		c := collector.NewNginxCollector(cfg.Collector.LogPaths.Nginx.Access, eventBus)
		startCollector("nginx:"+cfg.Collector.LogPaths.Nginx.Access, c.Start, c.Stop)
	case "apache":
		c := collector.NewApacheCollector(cfg.Collector.LogPaths.Apache.Access, eventBus)
		startCollector("apache:"+cfg.Collector.LogPaths.Apache.Access, c.Start, c.Stop)
	}

	if plugins.IsEnabled("ssh") {
		sshLog := cfg.Collector.SSHLog
		if sshLog == "auto" {
			sshLog = detectSSHLog()
		}
		if sshLog != "" {
			c := collector.NewSSHCollector(sshLog, eventBus)
			startCollector("ssh:"+sshLog, c.Start, c.Stop)
		}
	}

	metricsC := collector.NewMetricsCollector(cfg.Collector.MetricsInterval, eventBus)
	startCollector("metrics", metricsC.Start, metricsC.Stop)

	// Reporter
	rep, err := reporter.New(cfg)
	if err != nil {
		return err
	}
	defer rep.Close()

	go rep.RetryLoop(ctx)

	// Latest metrics for heartbeat
	var (
		latestMetrics     = &collector.SystemMetrics{}
		latestMetricsMu   sync.Mutex
		recentCritical    int
		recentHigh        int
		recentIncidentsMu sync.Mutex
	)

	// Event dispatch
	wg.Add(1)
	go func() {
		defer wg.Done()
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
				case collector.EventMetrics:
					latestMetricsMu.Lock()
					latestMetrics = ev.Metrics
					latestMetricsMu.Unlock()
				}
			}
		}
	}()

	// Incident → reporter
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case inc := <-incidentCh:
				log.Printf("[%s] %s from %s (score=%d)", inc.Severity, inc.Type, inc.SourceIP, inc.Score)
				recentIncidentsMu.Lock()
				switch inc.Severity {
				case analyzer.SeverityCritical:
					recentCritical++
				case analyzer.SeverityHigh:
					recentHigh++
				}
				recentIncidentsMu.Unlock()
				rep.Send(inc)
			}
		}
	}()

	// Heartbeat
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(cfg.Reporter.HeartbeatInterval)
		defer ticker.Stop()
		// Reset recent incident counters every hour
		resetTicker := time.NewTicker(time.Hour)
		defer resetTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-resetTicker.C:
				recentIncidentsMu.Lock()
				recentCritical, recentHigh = 0, 0
				recentIncidentsMu.Unlock()
			case <-ticker.C:
				latestMetricsMu.Lock()
				m := latestMetrics
				latestMetricsMu.Unlock()
				recentIncidentsMu.Lock()
				rc, rh := recentCritical, recentHigh
				recentIncidentsMu.Unlock()
				score := health.Calculate(m.CPUPercent, float64(m.MemUsedMB)/float64(max(m.MemTotalMB, 1))*100, m.DiskUsedPct, rc, rh)
				rep.SendHeartbeat(m, plugins.Active(), rep.PendingCount(), score)
			}
		}
	}()

	log.Printf("nawasara-agent %s started (agent=%s dashboard=%s plugins=%v)",
		reporter.Version, cfg.AgentName, cfg.DashboardURL, plugins.Active())

	<-ctx.Done()
	log.Println("shutting down collectors...")
	for _, stop := range stopFns {
		stop()
	}
	wg.Wait()
	log.Println("stopped.")
	return nil
}

func detectWebServer() string {
	switch {
	case fileExists("/var/log/nginx/access.log") || fileExists("/etc/nginx/nginx.conf"):
		return "nginx"
	case fileExists("/var/log/apache2/access.log") || fileExists("/etc/apache2/apache2.conf"):
		return "apache"
	case fileExists("/var/log/httpd/access_log") || fileExists("/etc/httpd/conf/httpd.conf"):
		return "apache"
	default:
		return "nginx"
	}
}

func detectSSHLog() string {
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
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

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
