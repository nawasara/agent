package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsVolatilePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/home/pertanianponorog/public_html/wp-content/cache/supercache/x/index-https.html", true},
		{"/home/siimutponorogogo/public_html/application/user/logs/log-2026-10-16.php", true},
		{"/var/www/app/storage/framework/views/abc.php", true},
		{"/home/a/public_html/wp-content/litespeed/css/x.css", true},

		// Real content and config stay under integrity watch.
		{"/home/jambonponorogogo/public_html/hitam.html", false},
		{"/home/a/public_html/wp-config.php", false},
		{"/home/a/public_html/wp-content/themes/today/index.php", false},
		{"/home/a/public_html/catalog.php", false},
	}

	for _, c := range cases {
		if got := isVolatilePath(c.path, nil); got != c.want {
			t.Errorf("isVolatilePath(%q) = %v, want %v", c.path, got, c.want)
		}
	}

	if !isVolatilePath("/home/a/public_html/custom-tmp-dir/x.php", []string{"/custom-tmp-dir/"}) {
		t.Error("integrity_ignore from config must be honoured")
	}
}

// The SLOT777 page on umum.ponorogo.go.id (Oct 2026) and the false positive the
// brand pattern must not produce.
func TestGamblingBrandPatterns(t *testing.T) {
	db := defaultSignatures()
	db.compile()
	ws := NewWebshellScanner(db)
	dir := t.TempDir()

	scan := func(name, content string) bool {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := ws.ScanFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range res {
			if r.SignatureID == "spam_gambling" {
				return true
			}
		}
		return false
	}

	if !scan("login.html", `<title>SLOT777 LOGIN</title><p>Masuk sekarang</p>`) {
		t.Error("slot777 brand page not flagged")
	}
	if !scan("link.html", `<p>Link resmi anti blokir, deposit QRIS 10K</p>`) {
		t.Error("anti blokir page not flagged")
	}
	if scan("agenda.html", `<p>Setiap peserta mendapat slot 30 menit untuk presentasi.</p>`) {
		t.Error("agenda with 'slot 30 menit' must not be flagged")
	}
}
