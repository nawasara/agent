package collector

import "testing"

func TestCaddyParse(t *testing.T) {
	c := NewCaddyCollector("/dev/null", nil)

	t.Run("real IP from X-Forwarded-For behind proxy", func(t *testing.T) {
		line := `{"level":"info","ts":1690000000.5,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"172.18.0.2","remote_port":"55000","method":"POST","host":"bale.test","uri":"/wp-login.php?redirect=1","headers":{"User-Agent":["sqlmap/1.5"],"X-Forwarded-For":["203.0.113.9, 10.0.0.1"]}},"status":403,"size":128}`
		e := c.parse(line)
		if e == nil {
			t.Fatal("expected entry, got nil")
		}
		if e.SourceIP != "203.0.113.9" {
			t.Errorf("SourceIP = %q, want 203.0.113.9 (first XFF)", e.SourceIP)
		}
		if e.Method != "POST" || e.Path != "/wp-login.php" || e.Query != "redirect=1" {
			t.Errorf("method/path/query = %q/%q/%q", e.Method, e.Path, e.Query)
		}
		if e.StatusCode != 403 {
			t.Errorf("status = %d, want 403", e.StatusCode)
		}
		if e.UserAgent != "sqlmap/1.5" {
			t.Errorf("UA = %q", e.UserAgent)
		}
		if e.Source != "caddy" {
			t.Errorf("source = %q", e.Source)
		}
	})

	t.Run("fallback to remote_ip when no XFF", func(t *testing.T) {
		line := `{"ts":1690000001,"logger":"http.log.access","request":{"remote_ip":"198.51.100.7","method":"GET","uri":"/","headers":{"User-Agent":["curl/8"]}},"status":200,"size":10}`
		e := c.parse(line)
		if e == nil {
			t.Fatal("expected entry")
		}
		if e.SourceIP != "198.51.100.7" {
			t.Errorf("SourceIP = %q, want remote_ip fallback", e.SourceIP)
		}
	})

	t.Run("case-insensitive XFF header", func(t *testing.T) {
		line := `{"ts":1,"request":{"remote_ip":"10.0.0.1","method":"GET","uri":"/a","headers":{"x-forwarded-for":["1.2.3.4"]}},"status":200}`
		e := c.parse(line)
		if e == nil || e.SourceIP != "1.2.3.4" {
			t.Errorf("case-insensitive XFF failed: %+v", e)
		}
	})

	t.Run("skip non-access log line (no request)", func(t *testing.T) {
		line := `{"level":"info","ts":1690000002,"logger":"tls","msg":"certificate obtained"}`
		if e := c.parse(line); e != nil {
			t.Errorf("expected nil for non-access line, got %+v", e)
		}
	})

	t.Run("skip non-JSON line", func(t *testing.T) {
		if e := c.parse("plain text startup message"); e != nil {
			t.Errorf("expected nil for non-JSON, got %+v", e)
		}
	})

	t.Run("skip malformed JSON", func(t *testing.T) {
		if e := c.parse(`{"request":{`); e != nil {
			t.Errorf("expected nil for broken JSON, got %+v", e)
		}
	})
}
