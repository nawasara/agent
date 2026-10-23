package analyzer

import (
	"testing"
	"time"

	"github.com/nawasara/agent/internal/collector"
)

// PHP2Shell (CVE-2026-109618/109619, Oktober 2026) bekerja di bawah aplikasi.
// Yang tersisa di access log hanya status: 413 saat nginx menolak kiriman
// besar, 500 saat PHP kehabisan memori, 502 saat worker PHP-FPM tumbang.

func entryStatus(ip, method string, status int) *collector.LogEntry {
	return &collector.LogEntry{
		SourceIP:   ip,
		Timestamp:  time.Now(),
		Method:     method,
		Path:       "/index.php",
		StatusCode: status,
		UserAgent:  "Mozilla/5.0 (X11; Linux x86_64)",
		Host:       "nawasara.ponorogo.go.id",
		Source:     "nginx",
	}
}

func hasType(incs []Incident, typ string) bool {
	for _, inc := range incs {
		if inc.Type == typ {
			return true
		}
	}
	return false
}

func TestOversizedBodyRepeatedTriggers(t *testing.T) {
	ch := make(chan Incident, 64)
	e := NewEngine(DefaultRules(), 5*time.Minute, ch)

	for i := 0; i < 3; i++ { // 3 × skor 10 = ambang 30
		e.ProcessLog(entryStatus("198.51.100.20", "POST", 413))
	}
	if got := drain(ch); !hasType(got, "oversized_body") {
		t.Fatalf("3 kali 413 dari satu IP tidak terdeteksi, dapat %v", got)
	}
}

func TestSingleOversizedBodyIsQuiet(t *testing.T) {
	ch := make(chan Incident, 64)
	e := NewEngine(DefaultRules(), 5*time.Minute, ch)

	// Warga yang sekali salah pilih video besar tidak boleh jadi insiden.
	e.ProcessLog(entryStatus("198.51.100.21", "POST", 413))
	if got := drain(ch); hasType(got, "oversized_body") {
		t.Fatal("satu kali 413 sudah memicu insiden, false positive")
	}
}

func TestPost500StormTriggers(t *testing.T) {
	ch := make(chan Incident, 64)
	e := NewEngine(DefaultRules(), 5*time.Minute, ch)

	for i := 0; i < 15; i++ {
		e.ProcessLog(entryStatus("198.51.100.22", "POST", 500))
	}
	if got := drain(ch); !hasType(got, "server_error_storm") {
		t.Fatalf("15 POST 500 dari satu IP tidak terdeteksi, dapat %v", got)
	}
}

func TestGet500DoesNotCountAsPostStorm(t *testing.T) {
	ch := make(chan Incident, 64)
	e := NewEngine(DefaultRules(), 5*time.Minute, ch)

	for i := 0; i < 20; i++ {
		e.ProcessLog(entryStatus("198.51.100.23", "GET", 500))
	}
	if got := drain(ch); hasType(got, "server_error_storm") {
		t.Fatal("GET 500 ikut terhitung sebagai rentetan POST")
	}
}

func TestPhpWorkerCrashTriggers(t *testing.T) {
	ch := make(chan Incident, 64)
	e := NewEngine(DefaultRules(), 5*time.Minute, ch)

	for i := 0; i < 10; i++ {
		e.ProcessLog(entryStatus("198.51.100.24", "POST", 502))
	}
	if got := drain(ch); !hasType(got, "php_worker_crash") {
		t.Fatalf("10 kali 502 dari satu IP tidak terdeteksi, dapat %v", got)
	}
}

// Deploy ulang membagi 502 ke banyak pengunjung, masing-masing sekali-dua.
func TestDeploy502SpreadAcrossIpsIsQuiet(t *testing.T) {
	ch := make(chan Incident, 64)
	e := NewEngine(DefaultRules(), 5*time.Minute, ch)

	for i := 0; i < 40; i++ {
		ip := "198.51.100." + string(rune('a'+i%20))
		e.ProcessLog(entryStatus(ip, "GET", 502))
	}
	if got := drain(ch); hasType(got, "php_worker_crash") {
		t.Fatal("502 saat deploy (tersebar ke banyak IP) memicu insiden")
	}
}
