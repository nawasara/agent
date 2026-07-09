package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	APIKey       string          `yaml:"api_key"`
	DashboardURL string          `yaml:"dashboard_url"`
	AgentName    string          `yaml:"agent_name"`
	AgentID      string          `yaml:"agent_id"`
	Collector    CollectorConfig `yaml:"collector"`
	Analyzer     AnalyzerConfig  `yaml:"analyzer"`
	Reporter     ReporterConfig  `yaml:"reporter"`
	Executor     ExecutorConfig  `yaml:"executor"`
	Plugins      PluginsConfig   `yaml:"plugins"`
	Scanner      ScannerConfig   `yaml:"scanner"`

	filePath string // internal — path used for Save()
}

type CollectorConfig struct {
	WebServer       string            `yaml:"web_server"` // auto | nginx | apache
	LogPaths        LogPathsConfig    `yaml:"log_paths"`
	SSHLog          string            `yaml:"ssh_log"` // auto | path
	MetricsInterval time.Duration     `yaml:"metrics_interval"`
}

type LogPathsConfig struct {
	Nginx  NginxLogPaths  `yaml:"nginx"`
	Apache ApacheLogPaths `yaml:"apache"`
	Caddy  CaddyLogPaths  `yaml:"caddy"`
}

type CaddyLogPaths struct {
	Access string `yaml:"access"` // Caddy/FrankenPHP JSON access log
	VHosts string `yaml:"vhosts"` // optional glob for per-site access logs
}

type NginxLogPaths struct {
	Access string `yaml:"access"`
	Error  string `yaml:"error"`
	VHosts string `yaml:"vhosts"`
}

type ApacheLogPaths struct {
	Access string `yaml:"access"`
	Error  string `yaml:"error"`
}

type AnalyzerConfig struct {
	RulesDir          string        `yaml:"rules_dir"`
	RulesSyncInterval time.Duration `yaml:"rules_sync_interval"`
	CorrelationWindow time.Duration `yaml:"correlation_window"`
	DefaultThreshold  int           `yaml:"default_threshold"`
}

type ReporterConfig struct {
	PushTimeout       time.Duration `yaml:"push_timeout"`
	RetryInterval     time.Duration `yaml:"retry_interval"`
	BufferDB          string        `yaml:"buffer_db"`
	BufferMaxAge      time.Duration `yaml:"buffer_max_age"`
	BufferMaxSizeMB   int           `yaml:"buffer_max_size_mb"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
}

type ExecutorConfig struct {
	Enabled        bool          `yaml:"enabled"`
	PollInterval   time.Duration `yaml:"poll_interval"`
	AllowedActions []string      `yaml:"allowed_actions"`
}

type PluginsConfig struct {
	Dir     string              `yaml:"dir"`
	Enabled []string            `yaml:"enabled"`
	SSL     SSLConfig           `yaml:"ssl"`
	Laravel LaravelPluginConfig `yaml:"laravel"`
	Docker  DockerPluginConfig  `yaml:"docker"`
}

type ScannerConfig struct {
	Enabled      bool          `yaml:"enabled"`
	ScanInterval time.Duration `yaml:"scan_interval"`
	WebDirs      []string      `yaml:"web_dirs"`
	WatchPaths   []string      `yaml:"watch_paths"`
	SignaturesDB string        `yaml:"signatures_db"` // path to JSON signature file; empty = built-in defaults
	HashDB       string        `yaml:"hash_db"`       // path to SQLite hash database
}

type SSLConfig struct {
	Hosts         []string      `yaml:"hosts"`
	CheckInterval time.Duration `yaml:"check_interval"`
	WarnDays      int           `yaml:"warn_days"`
	CritDays      int           `yaml:"crit_days"`
}

type LaravelPluginConfig struct {
	LogPaths []string `yaml:"log_paths"`
}

type DockerPluginConfig struct {
	CheckInterval time.Duration `yaml:"check_interval"`
}

func Load(path string) (*Config, error) {
	cfg := defaults()

	// The config file is optional in container/env-only deployments. When it's
	// missing we start from defaults and rely on env vars (Docker compose sets
	// NAWASARA_* and the agent self-registers, persisting creds back to `path`).
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.filePath = path
	cfg.applyEnv()
	return cfg, nil
}

// applyEnv overlays a small set of environment variables on top of the config.
// Only identity/connection fields are exposed — everything else stays in YAML.
// This lets `docker compose` configure an agent with just env vars.
func (c *Config) applyEnv() {
	if v := os.Getenv("NAWASARA_URL"); v != "" {
		c.DashboardURL = v
	}
	if v := os.Getenv("NAWASARA_AGENT_NAME"); v != "" {
		c.AgentName = v
	}
	if v := os.Getenv("NAWASARA_AGENT_ID"); v != "" {
		c.AgentID = v
	}
	if v := os.Getenv("NAWASARA_API_KEY"); v != "" {
		c.APIKey = v
	}
	if v := os.Getenv("NAWASARA_WEB_SERVER"); v != "" {
		c.Collector.WebServer = v
	}
	// NAWASARA_SCANNER_ENABLED=true turns on the file scanner without a YAML edit.
	if v := os.Getenv("NAWASARA_SCANNER_ENABLED"); v != "" {
		c.Scanner.Enabled = v == "1" || v == "true" || v == "yes"
	}
}

// Save writes selected fields (agent_id, api_key) back to the config file.
// Uses simple line-by-line replacement to preserve comments and formatting.
func (c *Config) Save() error {
	if c.filePath == "" {
		return nil
	}

	data, err := os.ReadFile(c.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// Env-only deployment (no config file yet): write a minimal one so the
		// registered agent_id + api_key persist across container restarts.
		content := fmt.Sprintf(
			"# Nawasara Agent — auto-written on first registration\ndashboard_url: %s\nagent_name: %s\nagent_id: %s\napi_key: %s\n",
			c.DashboardURL, c.AgentName, c.AgentID, c.APIKey,
		)
		return os.WriteFile(c.filePath, []byte(content), 0600)
	}

	content := string(data)
	content = replaceYAMLField(content, "agent_id", c.AgentID)
	content = replaceYAMLField(content, "api_key", c.APIKey)
	return os.WriteFile(c.filePath, []byte(content), 0600)
}

func replaceYAMLField(content, key, value string) string {
	lines := strings.Split(content, "\n")
	prefix := key + ":"
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			lines[i] = key + ": " + value
		}
	}
	return strings.Join(lines, "\n")
}

func defaults() *Config {
	return &Config{
		Collector: CollectorConfig{
			WebServer: "auto",
			SSHLog:    "auto",
			LogPaths: LogPathsConfig{
				Nginx:  NginxLogPaths{Access: "/var/log/nginx/access.log", Error: "/var/log/nginx/error.log", VHosts: "/var/log/nginx/*_access.log"},
				Apache: ApacheLogPaths{Access: "/var/log/apache2/access.log", Error: "/var/log/apache2/error.log"},
				Caddy:  CaddyLogPaths{Access: "/var/log/caddy/access.log", VHosts: "/var/log/caddy/*.log"},
			},
			MetricsInterval: 30 * time.Second,
		},
		Analyzer: AnalyzerConfig{
			RulesDir:          "/etc/nawasara-agent/rules/",
			RulesSyncInterval: 6 * time.Hour,
			CorrelationWindow: 5 * time.Minute,
			DefaultThreshold:  20,
		},
		Reporter: ReporterConfig{
			PushTimeout:       10 * time.Second,
			RetryInterval:     30 * time.Second,
			BufferDB:          "/var/lib/nawasara-agent/buffer.db",
			BufferMaxAge:      168 * time.Hour,
			BufferMaxSizeMB:   100,
			HeartbeatInterval: 60 * time.Second,
		},
		Executor: ExecutorConfig{
			Enabled:      false,
			PollInterval: 30 * time.Second,
		},
		Plugins: PluginsConfig{
			Dir:     "/etc/nawasara-agent/plugins/available/",
			Enabled: []string{"nginx", "ssh"},
			SSL: SSLConfig{
				CheckInterval: 12 * time.Hour,
				WarnDays:      30,
				CritDays:      7,
			},
			Docker: DockerPluginConfig{
				CheckInterval: 5 * time.Minute,
			},
		},
		Scanner: ScannerConfig{
			Enabled:      false,
			ScanInterval: 6 * time.Hour,
			WebDirs:      []string{"/var/www", "/home/*/public_html"},
			WatchPaths: []string{
				"/var/www/html/.env",
				"/var/www/html/composer.json",
				"/etc/nawasara-agent/config.yaml",
			},
			HashDB: "/var/lib/nawasara-agent/hashes.db",
		},
	}
}
