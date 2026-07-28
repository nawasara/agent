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
			Severity: "high", Score: 10, Threshold: 10, Mitre: "T1595.003",
			Conditions: Conditions{Source: "web_log", PathEquals: []string{"/.env", "/.env.bak", "/.env.old", "/.env.example"}},
		},
		{
			ID: "rule_vuln_scan_git", Name: "Git Config Access", Category: "vulnerability_scan",
			Severity: "high", Score: 10, Threshold: 10, Mitre: "T1595.003",
			Conditions: Conditions{Source: "web_log", PathEquals: []string{"/.git/config", "/.git/HEAD"}},
		},
		{
			ID: "rule_vuln_scan_phpinfo", Name: "PHPInfo Access", Category: "vulnerability_scan",
			Severity: "medium", Score: 8, Threshold: 8, Mitre: "T1595.003",
			Conditions: Conditions{Source: "web_log", PathContains: []string{"phpinfo.php", "phpinfo", "test.php"}},
		},
		{
			ID: "rule_dir_traversal", Name: "Directory Traversal", Category: "directory_traversal",
			Severity: "critical", Score: 40, Threshold: 40, Mitre: "T1083",
			Conditions: Conditions{Source: "web_log", PathContains: []string{"../", "..%2F", "%2e%2e%2f"}},
		},
		{
			ID: "rule_sqli_url", Name: "SQL Injection in URL", Category: "sql_injection",
			Severity: "critical", Score: 40, Threshold: 40, Mitre: "T1190",
			Conditions: Conditions{
				Source:     "web_log",
				QueryRegex: []string{`(?i)(UNION.{1,20}SELECT)`, `(?i)(OR.{0,5}1.?=.?1)`, `(?i)(DROP.{1,10}TABLE)`, `(?i)(INSERT.{1,10}INTO)`, `(?i)(\bSLEEP\s*\()`, `(?i)(\bBENCHMARK\s*\()`},
			},
		},
		{
			ID: "rule_xss_probe", Name: "XSS Probe", Category: "xss",
			Severity: "medium", Score: 20, Threshold: 20, Mitre: "T1190",
			Conditions: Conditions{Source: "web_log", QueryRegex: []string{`(?i)<script`, `(?i)javascript:`, `(?i)onerror=`, `(?i)onload=`}},
		},
		{
			// Dua kelompok UA: pemindai kerentanan, lalu alat load-test. Yang kedua
			// jarang sah menghantam situs publik dari luar — kalau muncul, hampir
			// selalu upaya membanjiri. Ini deteksi cepat (satu request sudah cukup);
			// rule_request_flood tetap jadi jaring pengaman untuk UA yang dipalsukan.
			ID: "rule_scanner_bot", Name: "Known Scanner Bot", Category: "scanner_bot",
			Severity: "high", Score: 30, Threshold: 30, Mitre: "T1595.002",
			Conditions: Conditions{Source: "web_log", UAContains: []string{
				"sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "dirsearch", "gobuster", "ffuf", "wfuzz",
				"k6-load-tester", "k6/", "vegeta", "wrk/", "siege", "locust", "gatling", "jmeter", "hey/", "artillery",
			}},
		},
		{
			// POST to an upload directory with a .php extension in the path
			// — classic webshell drop. PathContains + PathRegex = AND (both must match).
			ID: "rule_webshell_upload", Name: "PHP Webshell Upload", Category: "webshell_upload",
			Severity: "critical", Score: 70, Threshold: 70, Mitre: "T1505.003",
			Conditions: Conditions{
				Source: "web_log", Method: "POST",
				PathContains: []string{"/upload/", "/uploads/", "/wp-content/uploads/", "/files/", "/images/", "/media/", "/tmp/"},
				PathRegex:    []string{`(?i)\.(php[0-9]?|phtml|phar|php-s)(\?|$)`},
			},
		},
		{
			ID: "rule_brute_force_http", Name: "HTTP Login Brute Force", Category: "brute_force",
			Severity: "high", Score: 5, Threshold: 50, Mitre: "T1110.001",
			Conditions: Conditions{Source: "web_log", Method: "POST", PathContains: []string{"/login", "/wp-login.php", "/admin/login", "/auth/login"}, PerIP: true, WindowSeconds: 60},
		},
		{
			ID: "rule_4xx_storm", Name: "HTTP 4xx Storm", Category: "4xx_storm",
			Severity: "medium", Score: 2, Threshold: 100, Mitre: "T1595",
			Conditions: Conditions{Source: "web_log", StatusMin: 400, StatusMax: 499, PerIP: true, WindowSeconds: 30},
		},
		{
			// Volumetrik murni: banyak request dari SATU IP dalam waktu singkat,
			// apa pun status code, path, dan User-Agent-nya.
			//
			// Ini menutup celah yang tidak tertangkap rule lain. Kasus nyata
			// (csirt.ponorogo.go.id, Juli 2026): satu IP membanjiri "GET /" yang
			// semuanya dijawab 200 OK. rule_4xx_storm tidak kena karena bukan 4xx,
			// rule_scanner_bot tidak kena karena UA-nya tidak ada di daftar, dan
			// tidak ada payload SQLi/XSS/traversal untuk dicocokkan. Semua rule
			// lain memeriksa *bentuk* request; hanya rule ini yang memeriksa
			// *volume*.
			//
			// Ambang: 300 request / 60 detik / IP (skor 1 × threshold 300). Jauh di
			// atas pemakaian manusia wajar — satu halaman berat dengan puluhan aset
			// statis masih aman, terlebih aset umumnya dilayani CDN dan tidak
			// mencapai origin. Naikkan bila ada klien sah yang memang burst tinggi
			// (mis. mesin sinkronisasi antar-OPD).
			ID: "rule_request_flood", Name: "HTTP Request Flood", Category: "request_flood",
			Severity: "high", Score: 1, Threshold: 300, Mitre: "T1498.001",
			Conditions: Conditions{Source: "web_log", PerIP: true, WindowSeconds: 60},
		},
		{
			ID: "rule_ssh_brute", Name: "SSH Brute Force", Category: "brute_force",
			Severity: "high", Score: 5, Threshold: 50, Mitre: "T1110.001",
			Conditions: Conditions{Source: "ssh_log", EventType: "failed", PerIP: true, WindowSeconds: 300},
		},
		{
			ID: "rule_ssh_root_login", Name: "SSH Root Login Accepted", Category: "ssh_root_login",
			Severity: "critical", Score: 70, Threshold: 70, Mitre: "T1078",
			Conditions: Conditions{Source: "ssh_log", EventType: "root_accepted"},
		},
	}
}
