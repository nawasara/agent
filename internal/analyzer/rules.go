package analyzer

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadRules loads all rule YAML files from a directory.
func LoadRules(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var batch []Rule
		if err := yaml.Unmarshal(data, &batch); err != nil {
			continue
		}
		rules = append(rules, batch...)
	}
	return rules, nil
}

// DefaultRules returns the built-in Phase 1 MVP rules (no file needed).
func DefaultRules() []Rule {
	return []Rule{
		{
			ID: "rule_vuln_scan_env", Name: "Dotenv File Access", Category: "vulnerability_scan",
			Severity: "high", Score: 10, Threshold: 10,
			Conditions: Conditions{Source: "web_log", PathEquals: []string{"/.env", "/.env.bak", "/.env.old", "/.env.example"}},
		},
		{
			ID: "rule_vuln_scan_git", Name: "Git Config Access", Category: "vulnerability_scan",
			Severity: "high", Score: 10, Threshold: 10,
			Conditions: Conditions{Source: "web_log", PathEquals: []string{"/.git/config", "/.git/HEAD"}},
		},
		{
			ID: "rule_vuln_scan_phpinfo", Name: "PHPInfo Access", Category: "vulnerability_scan",
			Severity: "medium", Score: 8, Threshold: 8,
			Conditions: Conditions{Source: "web_log", PathContains: []string{"phpinfo.php", "phpinfo", "test.php"}},
		},
		{
			ID: "rule_dir_traversal", Name: "Directory Traversal", Category: "directory_traversal",
			Severity: "critical", Score: 40, Threshold: 40,
			Conditions: Conditions{Source: "web_log", PathContains: []string{"../", "..%2F", "%2e%2e%2f"}},
		},
		{
			ID: "rule_sqli_url", Name: "SQL Injection in URL", Category: "sql_injection",
			Severity: "critical", Score: 40, Threshold: 40,
			Conditions: Conditions{
				Source:     "web_log",
				QueryRegex: []string{`(?i)(UNION.{1,20}SELECT)`, `(?i)(OR.{0,5}1.?=.?1)`, `(?i)(DROP.{1,10}TABLE)`, `(?i)(INSERT.{1,10}INTO)`, `(?i)(\bSLEEP\s*\()`, `(?i)(\bBENCHMARK\s*\()`},
			},
		},
		{
			ID: "rule_xss_probe", Name: "XSS Probe", Category: "xss",
			Severity: "medium", Score: 20, Threshold: 20,
			Conditions: Conditions{Source: "web_log", QueryRegex: []string{`(?i)<script`, `(?i)javascript:`, `(?i)onerror=`, `(?i)onload=`}},
		},
		{
			ID: "rule_scanner_bot", Name: "Known Scanner Bot", Category: "scanner_bot",
			Severity: "high", Score: 30, Threshold: 30,
			Conditions: Conditions{Source: "web_log", UAContains: []string{"sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "dirsearch", "gobuster", "ffuf", "wfuzz"}},
		},
		{
			ID: "rule_brute_force_http", Name: "HTTP Login Brute Force", Category: "brute_force",
			Severity: "high", Score: 5, Threshold: 50,
			Conditions: Conditions{Source: "web_log", Method: "POST", PathContains: []string{"/login", "/wp-login.php", "/admin/login", "/auth/login"}, PerIP: true, WindowSeconds: 60},
		},
		{
			ID: "rule_4xx_storm", Name: "HTTP 4xx Storm", Category: "4xx_storm",
			Severity: "medium", Score: 2, Threshold: 100,
			Conditions: Conditions{Source: "web_log", StatusMin: 400, StatusMax: 499, PerIP: true, WindowSeconds: 30},
		},
		{
			ID: "rule_ssh_brute", Name: "SSH Brute Force", Category: "brute_force",
			Severity: "high", Score: 5, Threshold: 50,
			Conditions: Conditions{Source: "ssh_log", EventType: "failed", PerIP: true, WindowSeconds: 300},
		},
		{
			ID: "rule_ssh_root_login", Name: "SSH Root Login Accepted", Category: "ssh_root_login",
			Severity: "critical", Score: 70, Threshold: 70,
			Conditions: Conditions{Source: "ssh_log", EventType: "root_accepted"},
		},
	}
}
