package collector

import "testing"

func TestHostFromLogPath(t *testing.T) {
	cases := map[string]string{
		// WHM/cPanel domlogs — bare domain filename.
		"/var/log/apache2/domlogs/example.com":         "example.com",
		"/var/log/apache2/domlogs/sub.example.com":     "sub.example.com",
		"/var/log/apache2/domlogs/example.com-ssl_log":   "example.com",
		"/usr/local/apache/domlogs/foo.go.id":            "foo.go.id",
		"/usr/local/apache/domlogs/babadan.ponorogo.go.id":            "babadan.ponorogo.go.id",
		"/usr/local/apache/domlogs/babadan.ponorogo.go.id-ssl_log":   "babadan.ponorogo.go.id",
		"/usr/local/apache/domlogs/babadan.ponorogo.go.id-bytes_log": "babadan.ponorogo.go.id",
		// Per-site nginx logs.
		"/var/log/nginx/example.com_access.log": "example.com",
		"/var/log/nginx/example.com-access.log": "example.com",
		"/var/log/nginx/example.com.access.log": "example.com",
		// Generic combined logs — no domain to report.
		"/var/log/nginx/access.log":   "",
		"/var/log/apache2/access.log": "",
		"/var/log/nginx/other_vhosts_access.log": "",
		// Odd / non-domain filenames — don't invent a host.
		"/var/log/nginx/mylog":  "",
		"":                      "",
	}
	for path, want := range cases {
		if got := hostFromLogPath(path); got != want {
			t.Errorf("hostFromLogPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestNginxParseVhostFormat(t *testing.T) {
	c := NewNginxCollector("/dev/null", nil)

	t.Run("vhost_combined: host from the leading $host field", func(t *testing.T) {
		line := `csirt.ponorogo.go.id 203.0.113.9 - - [16/Jul/2026:10:49:01 +0700] "GET /wp-login.php?a=1 HTTP/1.1" 404 128 "-" "sqlmap/1.5"`
		// source is the generic combined log (no host in filename) — must come from the line.
		e := c.parse(line, "/var/log/nginx/access.log")
		if e == nil {
			t.Fatal("expected entry")
		}
		if e.Host != "csirt.ponorogo.go.id" {
			t.Errorf("Host = %q, want csirt.ponorogo.go.id (from line)", e.Host)
		}
		if e.SourceIP != "203.0.113.9" || e.Method != "GET" || e.Path != "/wp-login.php" || e.StatusCode != 404 {
			t.Errorf("misparsed vhost line: %+v", e)
		}
	})

	t.Run("standard combined still parses (not misread as vhost)", func(t *testing.T) {
		line := `203.0.113.9 - - [16/Jul/2026:10:49:01 +0700] "POST /x.php HTTP/1.1" 500 10 "-" "curl/8"`
		e := c.parse(line, "/var/log/nginx/access.log")
		if e == nil {
			t.Fatal("expected entry")
		}
		if e.SourceIP != "203.0.113.9" {
			t.Errorf("SourceIP = %q, standard line misparsed as vhost", e.SourceIP)
		}
		if e.Host != "" {
			t.Errorf("Host = %q, want empty for generic access.log", e.Host)
		}
	})

	t.Run("vhost with '-' host is treated as unknown", func(t *testing.T) {
		line := `- 203.0.113.9 - - [16/Jul/2026:10:49:01 +0700] "GET / HTTP/1.1" 200 1 "-" "curl"`
		e := c.parse(line, "/var/log/nginx/access.log")
		if e == nil || e.Host != "" {
			t.Errorf("want empty host for '-' vhost, got %+v", e)
		}
	})
}

func TestNginxParseHostFromSource(t *testing.T) {
	c := NewNginxCollector("/dev/null", nil)
	line := `203.0.113.9 - - [16/Jul/2026:10:49:01 +0700] "GET /magento_version HTTP/1.1" 404 128 "-" "sqlmap/1.5"`

	// From a WHM domlog: host comes from the filename.
	e := c.parse(line, "/var/log/apache2/domlogs/shop.example.com")
	if e == nil {
		t.Fatal("expected entry")
	}
	if e.Host != "shop.example.com" {
		t.Errorf("Host = %q, want shop.example.com", e.Host)
	}
	if e.Method != "GET" || e.Path != "/magento_version" || e.StatusCode != 404 {
		t.Errorf("parsed wrong: %+v", e)
	}

	// From the generic access.log: no host.
	e2 := c.parse(line, "/var/log/nginx/access.log")
	if e2 == nil || e2.Host != "" {
		t.Errorf("expected empty host for generic access.log, got %q", e2.Host)
	}
}
