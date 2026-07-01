package config

import (
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
	Dir     string   `yaml:"dir"`
	Enabled []string `yaml:"enabled"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.filePath = path
	return cfg, nil
}

// Save writes selected fields (agent_id, api_key) back to the config file.
// Uses simple line-by-line replacement to preserve comments and formatting.
func (c *Config) Save() error {
	if c.filePath == "" {
		return nil
	}
	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return err
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
		},
	}
}
