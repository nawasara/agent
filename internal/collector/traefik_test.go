package collector

import "testing"

func TestTraefikParse(t *testing.T) {
	c := NewTraefikCollector("/dev/null", nil)

	t.Run("real IP from X-Forwarded-For behind proxy", func(t *testing.T) {
		line := `{"ClientHost":"10.0.0.1","RequestMethod":"POST","RequestPath":"/wp-login.php?redirect=1","RequestHost":"bale-dindik.ponorogo.go.id","DownstreamStatus":403,"DownstreamContentSize":128,"request_User-Agent":"sqlmap/1.5","request_X-Forwarded-For":"203.0.113.9, 10.0.0.1","StartUTC":"2026-07-16T02:00:00Z"}`
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
		if e.BytesSent != 128 {
			t.Errorf("bytes = %d, want 128", e.BytesSent)
		}
		if e.UserAgent != "sqlmap/1.5" {
			t.Errorf("UA = %q", e.UserAgent)
		}
		if e.Source != "traefik" {
			t.Errorf("source = %q", e.Source)
		}
	})

	t.Run("fallback to ClientHost when no XFF", func(t *testing.T) {
		line := `{"ClientHost":"198.51.100.7","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"DownstreamContentSize":10}`
		e := c.parse(line)
		if e == nil {
			t.Fatal("expected entry")
		}
		if e.SourceIP != "198.51.100.7" {
			t.Errorf("SourceIP = %q, want ClientHost fallback", e.SourceIP)
		}
	})

	t.Run("path without query", func(t *testing.T) {
		line := `{"ClientHost":"1.2.3.4","RequestMethod":"GET","RequestPath":"/xmlrpc.php","DownstreamStatus":404}`
		e := c.parse(line)
		if e == nil || e.Path != "/xmlrpc.php" || e.Query != "" {
			t.Errorf("path/query = %+v", e)
		}
	})

	t.Run("StartUTC parsed into timestamp", func(t *testing.T) {
		line := `{"ClientHost":"1.2.3.4","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"StartUTC":"2026-07-16T09:15:30Z"}`
		e := c.parse(line)
		if e == nil {
			t.Fatal("expected entry")
		}
		if e.Timestamp.Year() != 2026 || e.Timestamp.Hour() != 9 || e.Timestamp.Minute() != 15 {
			t.Errorf("timestamp not parsed from StartUTC: %v", e.Timestamp)
		}
	})

	t.Run("skip non-access log line (no method/path)", func(t *testing.T) {
		line := `{"level":"info","msg":"Configuration loaded from flags."}`
		if e := c.parse(line); e != nil {
			t.Errorf("expected nil for non-access line, got %+v", e)
		}
	})

	t.Run("skip non-JSON line", func(t *testing.T) {
		if e := c.parse("time=\"2026-07-16\" level=info msg=\"Starting\""); e != nil {
			t.Errorf("expected nil for non-JSON, got %+v", e)
		}
	})

	t.Run("skip malformed JSON", func(t *testing.T) {
		if e := c.parse(`{"ClientHost":`); e != nil {
			t.Errorf("expected nil for broken JSON, got %+v", e)
		}
	})
}
