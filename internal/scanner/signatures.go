package scanner

import (
	"encoding/json"
	"os"
	"time"
)

// SignatureDB holds all patterns used to detect malicious files.
// It is loaded from a JSON file and can be updated from the Dashboard
// without restarting or recompiling the agent.
type SignatureDB struct {
	Version    string      `json:"version"`
	UpdatedAt  time.Time   `json:"updated_at"`
	Webshells  []Signature `json:"webshells"`
	Backdoors  []Signature `json:"backdoors"`
	Exploits   []Signature `json:"exploits"`
	SeoSpam    []Signature `json:"seo_spam"`

	// compiled regex cache keyed by signature ID — populated on Load
	compiled map[string]*compiledSig
}

// Signature is a single detection pattern entry.
type Signature struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"` // webshell | backdoor | exploit | suspicious
	Severity    string   `json:"severity"` // critical | high | medium
	Score       int      `json:"score"`
	Description string   `json:"description"`
	Mitre       string   `json:"mitre"` // MITRE ATT&CK technique ID, e.g. "T1505.003"
	// Patterns are Go regular expressions (any one match → detected).
	Patterns    []string `json:"patterns"`
}

type compiledSig struct {
	sig     Signature
	regexps []*fastRe
}

// LoadSignatureDB reads a JSON signature database from disk.
// If the file does not exist, it returns the built-in defaults.
func LoadSignatureDB(path string) (*SignatureDB, error) {
	if path == "" {
		db := defaultSignatures()
		db.compile()
		return db, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			db := defaultSignatures()
			db.compile()
			return db, nil
		}
		return nil, err
	}

	var db SignatureDB
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}
	db.compile()
	return &db, nil
}

// SaveSignatureDB writes the database to disk (called after Dashboard push update).
func SaveSignatureDB(path string, db *SignatureDB) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

// AllSignatures returns a flat slice of all signatures in the database.
func (db *SignatureDB) AllSignatures() []Signature {
	out := make([]Signature, 0, len(db.Webshells)+len(db.Backdoors)+len(db.Exploits)+len(db.SeoSpam))
	out = append(out, db.Webshells...)
	out = append(out, db.Backdoors...)
	out = append(out, db.Exploits...)
	out = append(out, db.SeoSpam...)
	return out
}

func (db *SignatureDB) compile() {
	all := db.AllSignatures()
	db.compiled = make(map[string]*compiledSig, len(all))
	for _, sig := range all {
		cs := &compiledSig{sig: sig}
		for _, pat := range sig.Patterns {
			if re := compileRe(pat); re != nil {
				cs.regexps = append(cs.regexps, re)
			}
		}
		db.compiled[sig.ID] = cs
	}
}

// defaultSignatures returns the built-in signature set.
// These cover the most common PHP webshells and backdoor techniques
// found in compromised government/enterprise web servers.
func defaultSignatures() *SignatureDB {
	return &SignatureDB{
		Version:   "builtin-1.0",
		UpdatedAt: time.Now(),
		Webshells: []Signature{
			{
				ID: "ws_c99", Name: "C99 Webshell", Category: "webshell", Severity: "critical", Score: 90, Mitre: "T1505.003",
				Description: "Classic c99 PHP webshell — full feature shell used in mass defacements",
				Patterns: []string{
					`\$c99_pass\s*=`,
					`c99_buff_prepare`,
					`c99shell`,
					`\$auth_pass\s*=.*c99`,
					`FilesMan`,
				},
			},
			{
				ID: "ws_r57", Name: "r57 Webshell", Category: "webshell", Severity: "critical", Score: 90, Mitre: "T1505.003",
				Description: "r57 PHP webshell — common variant of c99",
				Patterns: []string{
					`\$r57_pass\s*=`,
					`r57shell`,
					`r57_sess_`,
				},
			},
			{
				ID: "ws_wso", Name: "WSO Webshell", Category: "webshell", Severity: "critical", Score: 90, Mitre: "T1505.003",
				Description: "Web Shell by OrganicZ (WSO) — widely used for server defacements",
				Patterns: []string{
					`WSO\s*\d+\.\d+`,
					`wso_version`,
					`\$wso_pass\s*=`,
					`bypass_cf_check`,
					`wso_auth`,
				},
			},
			{
				ID: "ws_b374k", Name: "b374k Webshell", Category: "webshell", Severity: "critical", Score: 90, Mitre: "T1505.003",
				Description: "b374k PHP webshell — Unicode obfuscated shell",
				Patterns: []string{
					`b374k`,
					`\$default_action\s*=\s*.Filesmanager`,
					`b374k_auth`,
				},
			},
			{
				ID: "ws_indoxploit", Name: "IndoXploit Webshell", Category: "webshell", Severity: "critical", Score: 90, Mitre: "T1505.003",
				Description: "IndoXploit shell — popular in Indonesia defacement scene",
				Patterns: []string{
					`IndoXploit`,
					`indoxploit`,
					`\$pass\s*=.*indo`,
				},
			},
			{
				ID: "ws_priv8", Name: "Priv8 Webshell", Category: "webshell", Severity: "critical", Score: 90, Mitre: "T1505.003",
				Description: "Priv8 shell variant",
				Patterns: []string{
					`Priv8\s*Shell`,
					`priv8_`,
				},
			},
			{
				ID: "ws_mini_shell", Name: "Mini PHP Shell", Category: "webshell", Severity: "high", Score: 70, Mitre: "T1505.003",
				Description: "Minimal PHP one-liner shell — often injected into legitimate files",
				Patterns: []string{
					`<\?php\s+@?system\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`,
					`<\?php\s+@?eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`,
					`<\?php\s+@?passthru\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`,
					`<\?php\s+@?shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`,
					`<\?php\s+@?popen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`,
				},
			},
			{
				ID: "ws_generic_upload", Name: "Generic Upload Shell", Category: "webshell", Severity: "high", Score: 70, Mitre: "T1505.003",
				Description: "Generic upload-based PHP shell pattern",
				Patterns: []string{
					`move_uploaded_file.*\.php`,
					`\$_FILES.*\.php`,
				},
			},
		},
		Backdoors: []Signature{
			{
				ID: "bd_eval_base64", Name: "Eval+Base64 Backdoor", Category: "backdoor", Severity: "critical", Score: 85, Mitre: "T1505.003",
				Description: "eval(base64_decode(...)) — most common obfuscation for PHP backdoors",
				Patterns: []string{
					`eval\s*\(\s*base64_decode\s*\(`,
					`eval\s*\(\s*str_rot13\s*\(`,
					`eval\s*\(\s*gzinflate\s*\(`,
					`eval\s*\(\s*gzuncompress\s*\(`,
					`eval\s*\(\s*rawurldecode\s*\(`,
					`assert\s*\(\s*base64_decode\s*\(`,
					`assert\s*\(\s*gzinflate\s*\(`,
				},
			},
			{
				ID: "bd_hex_eval", Name: "Hex-encoded Eval Backdoor", Category: "backdoor", Severity: "critical", Score: 85, Mitre: "T1027",
				Description: "eval(hex2bin(...)) obfuscation",
				Patterns: []string{
					`eval\s*\(\s*hex2bin\s*\(`,
					`eval\s*\(\s*pack\s*\(\s*["']H\*`,
					`preg_replace\s*\(\s*["']/.*/e["']`,
				},
			},
			{
				ID: "bd_create_function", Name: "create_function Backdoor", Category: "backdoor", Severity: "high", Score: 75, Mitre: "T1059.004",
				Description: "create_function() used to execute arbitrary PHP — deprecated but still exploited",
				Patterns: []string{
					`create_function\s*\(\s*["'].*["']\s*,\s*base64_decode`,
					`create_function\s*\(\s*["'].*["']\s*,\s*\$`,
				},
			},
			{
				ID: "bd_system_input", Name: "System/Exec from User Input", Category: "backdoor", Severity: "critical", Score: 85, Mitre: "T1059.004",
				Description: "Direct system/exec call taking user input — RCE backdoor",
				Patterns: []string{
					`system\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[`,
					`exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[`,
					`passthru\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[`,
					`shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[`,
					`popen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[`,
					`proc_open\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[`,
				},
			},
			{
				ID: "bd_file_write", Name: "Dynamic File Write Backdoor", Category: "backdoor", Severity: "high", Score: 75, Mitre: "T1105",
				Description: "PHP code writing new PHP files to disk — dropper behaviour",
				Patterns: []string{
					`file_put_contents\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)`,
					`fwrite\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)`,
					`file_put_contents\s*\(.*\.php.*\<\?php`,
				},
			},
			{
				ID: "bd_mail_spam", Name: "PHP Mail Spammer", Category: "backdoor", Severity: "high", Score: 65, Mitre: "T1566",
				Description: "Mass mail sending from user-controlled inputs — compromised account spammer",
				Patterns: []string{
					`mail\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[.*\$_(?:GET|POST|REQUEST)`,
				},
			},
			{
				ID: "bd_obfuscated_long", Name: "Long Obfuscated String", Category: "backdoor", Severity: "medium", Score: 50, Mitre: "T1027",
				Description: "Suspiciously long base64 or hex string inline in PHP — common in auto-injected backdoors",
				Patterns: []string{
					// 200+ consecutive base64 chars inside a PHP string literal
					`["'][A-Za-z0-9+/]{200,}={0,2}["']`,
				},
			},
		},
		Exploits: []Signature{
			{
				ID: "exp_wp_file_manager", Name: "WP File Manager Exploit Artifact", Category: "exploit", Severity: "critical", Score: 90, Mitre: "T1190",
				Description: "Files dropped by WP File Manager CVE-2020-25213 exploitation",
				Patterns: []string{
					`wp-content/plugins/wp-file-manager/lib/files/`,
					`hardfork\.php`,
					`actionm\.php`,
				},
			},
			{
				ID: "exp_phpmyadmin_lfi", Name: "phpMyAdmin LFI Payload", Category: "exploit", Severity: "critical", Score: 85, Mitre: "T1190",
				Description: "Local file inclusion payload artifacts from phpMyAdmin exploitation",
				Patterns: []string{
					`pmasa-2016`,
					`PMA_BYPASS_QUERY_CHECK`,
				},
			},
			{
				ID: "exp_log4shell_jndi", Name: "Log4Shell JNDI Payload in Files", Category: "exploit", Severity: "critical", Score: 90, Mitre: "T1190",
				Description: "JNDI lookup string stored in a file — possible persistence or staging artifact",
				Patterns: []string{
					`\$\{jndi:(ldap|ldaps|rmi|dns)://`,
					`\$\{j\$\{::-n\}di:`,
					`\$\{\$\{::-j\}ndi:`,
				},
			},
		},
		SeoSpam: []Signature{
			// SEO-spam content dropped as .html/.php files (or injected into
			// legit pages) selling illegal abortion drugs or gambling. Detected
			// by strong phrases that never appear in genuine government content.
			// Deliberately NOT matching bare clinical words (misoprostol/aborsi)
			// so real puskesmas health articles aren't flagged — same two-tier
			// philosophy as the dashboard's judol/pharma detectors.
			{
				ID: "spam_pharma_abortion", Name: "Illegal Abortion-Drug SEO Spam", Category: "seo_spam", Severity: "high", Score: 75, Mitre: "T1584.006",
				Description: "Page selling illegal abortion pills (Cytotec/misoprostol) — SEO spam injected into a compromised gov site",
				Patterns: []string{
					`(?i)penggugur\s+kandungan`,
					`(?i)obat\s+aborsi`,
					`(?i)jual\s+(obat\s+)?cytotec`,
					`(?i)cytotec\s+(400|200)\s*(mcg|mg)?`,
					`(?i)menggugurkan\s+kandungan`,
					`(?i)obat\s+penggugur`,
					`(?i)apotek\s+cytotec`,
				},
			},
			{
				ID: "spam_gambling", Name: "Online Gambling SEO Spam", Category: "seo_spam", Severity: "high", Score: 70, Mitre: "T1584.006",
				Description: "Page promoting online gambling (judol) — SEO spam injected into a compromised gov site",
				Patterns: []string{
					`(?i)slot\s+gacor`,
					`(?i)situs\s+(slot\s+)?gacor`,
					`(?i)rtp\s+slot`,
					`(?i)(gates\s+of\s+olympus|starlight\s+princess|sweet\s+bonanza)`,
					`(?i)maxwin`,
					`(?i)bonus\s+new\s+member`,
					`(?i)(sbobet|pragmatic\s+play|pgsoft|pg\s+soft)`,
				},
			},
		},
	}
}
