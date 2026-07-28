package analyzer

import (
	"testing"
	"time"

	"github.com/nawasara/agent/internal/collector"
)

// Serangan nyata pada csirt.ponorogo.go.id (Juli 2026): satu IP membanjiri
// "GET /" yang semuanya dijawab 200 OK, UA "k6-Load-Tester/1.0".
// Sebelum rule_request_flood ada, pola ini lolos dari SEMUA rule: bukan 4xx,
// UA tidak terdaftar sebagai scanner, dan tidak ada payload untuk dicocokkan.

func entryFlood(ip, ua string) *collector.LogEntry {
	return &collector.LogEntry{
		SourceIP:   ip,
		Timestamp:  time.Now(),
		Method:     "GET",
		Path:       "/",
		Query:      "",
		StatusCode: 200,
		UserAgent:  ua,
		Host:       "csirt.ponorogo.go.id",
		Source:     "apache",
		Raw:        ip + ` - - "GET / HTTP/1.1" 200 8192 "-" "` + ua + `"`,
	}
}

// drain mengumpulkan insiden yang muncul di channel sampai sunyi sejenak.
func drain(ch <-chan Incident) []Incident {
	var out []Incident
	for {
		select {
		case inc := <-ch:
			out = append(out, inc)
		case <-time.After(150 * time.Millisecond):
			return out
		}
	}
}

// Flood harus terdeteksi meski UA-nya polos (dipalsukan jadi browser biasa).
func TestRequestFloodTriggers(t *testing.T) {
	ch := make(chan Incident, 64)
	e := NewEngine(DefaultRules(), 5*time.Minute, ch)

	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	for i := 0; i < 320; i++ { // ambang rule = 300
		e.ProcessLog(entryFlood("198.51.100.7", ua))
	}

	got := drain(ch)
	if len(got) == 0 {
		t.Fatal("flood TIDAK terdeteksi setelah 320 request 200 OK")
	}
	if got[0].Type != "request_flood" {
		t.Fatalf("tipe insiden = %q, harusnya request_flood", got[0].Type)
	}
	t.Logf("OK: terdeteksi sebagai %s (severity=%s, score=%d)",
		got[0].Type, got[0].Severity, got[0].Score)
}

// UA load-tester harus kena cepat lewat rule_scanner_bot (score 30 = threshold),
// tanpa menunggu ambang volumetrik.
func TestLoadTesterUADetectedEarly(t *testing.T) {
	ch := make(chan Incident, 64)
	e := NewEngine(DefaultRules(), 5*time.Minute, ch)

	e.ProcessLog(entryFlood("198.51.100.8", "k6-Load-Tester/1.0"))

	got := drain(ch)
	if len(got) == 0 {
		t.Fatal("UA k6-Load-Tester TIDAK terdeteksi")
	}
	if got[0].Type != "scanner_bot" {
		t.Fatalf("tipe insiden = %q, harusnya scanner_bot", got[0].Type)
	}
	t.Logf("OK: UA load-tester terdeteksi dari 1 request sebagai %s", got[0].Type)
}

// Trafik normal TIDAK boleh memicu flood — jaga agar tidak false positive.
func TestNormalTrafficDoesNotTrigger(t *testing.T) {
	ch := make(chan Incident, 64)
	e := NewEngine(DefaultRules(), 5*time.Minute, ch)

	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	for i := 0; i < 120; i++ { // di bawah ambang 300
		e.ProcessLog(entryFlood("198.51.100.9", ua))
	}

	if got := drain(ch); len(got) != 0 {
		t.Fatalf("trafik normal (120 req) memicu insiden %q — false positive", got[0].Type)
	}
	t.Log("OK: 120 request tidak memicu apa-apa")
}
