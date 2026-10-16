package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Webshell-looking fixtures are assembled at runtime: written out literally,
// Windows Defender quarantines the test file itself on developer machines.
func shellLine() string {
	return "@ev" + "al(base6" + "4_decode($_PO" + "ST['x']));"
}

func TestExtractContextWindow(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 100; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	data := []byte(b.String())
	off := strings.Index(b.String(), "line 50\n")

	ctx, start, match := extractContext(data, off)
	if match != 50 || start != 35 {
		t.Fatalf("match=%d start=%d, want 50 and 35", match, start)
	}
	lines := strings.Split(ctx, "\n")
	if len(lines) != 31 || lines[0] != "line 35" || lines[30] != "line 65" {
		t.Fatalf("window wrong: %d lines, first=%q last=%q", len(lines), lines[0], lines[len(lines)-1])
	}
}

func TestExtractContextNearStartAndCaps(t *testing.T) {
	long := strings.Repeat("A", 5000)
	data := []byte("<?php\n" + long + "\n" + shellLine() + "\n" + long + "\n")
	off := strings.Index(string(data), shellLine())

	ctx, start, match := extractContext(data, off)
	if start != 1 || match != 3 {
		t.Fatalf("start=%d match=%d", start, match)
	}
	if len(ctx) > maxContextBytes {
		t.Fatalf("context %d bytes exceeds cap", len(ctx))
	}
	if !strings.Contains(ctx, shellLine()) || !strings.Contains(ctx, " …") {
		t.Fatalf("match line missing or long line not cut")
	}
}

func TestRedactCredentials(t *testing.T) {
	cases := map[string]string{
		`define( 'DB_PASSWORD', 'S3cret!' );`: `define( 'DB_PASSWORD', '***' );`,
		`define('AUTH_KEY', 'abc|def');`:      `define('AUTH_KEY', '***');`,
		"DB_PASSWORD=hunter2":                 "DB_PASSWORD=***",
		"APP_KEY=base64:xyz":                  "APP_KEY=***",
		`'password' => 'p@ss',`:               `'password' => '***',`,
		`$db_pass = "rahasia";`:               `$db_pass = "***";`,
		`define('WP_DEBUG', false);`:          `define('WP_DEBUG', false);`,
		`$x = $_POST['content'];`:             `$x = $_POST['content'];`,
	}
	for in, want := range cases {
		if got := redact(in); got != want {
			t.Errorf("redact(%q) = %q, want %q", in, got, want)
		}
	}
}

// End to end: a webshell hit inside a wp-config-like file ships context with
// the password blanked.
func TestScanFileCarriesRedactedContext(t *testing.T) {
	db := defaultSignatures()
	db.compile()
	ws := NewWebshellScanner(db)

	p := filepath.Join(t.TempDir(), "wp-config.php")
	content := "<?php\ndefine('DB_PASSWORD', 'TopSecret99');\n" + shellLine() + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ws.ScanFile(p)
	if err != nil || len(res) == 0 {
		t.Fatalf("expected a finding, got %v %v", res, err)
	}
	for _, r := range res {
		if strings.Contains(r.Context, "TopSecret99") || strings.Contains(r.MatchedLine, "TopSecret99") {
			t.Fatalf("password leaked in %s", r.SignatureID)
		}
		if r.MatchLine == 0 || r.Context == "" {
			t.Fatalf("%s: no context", r.SignatureID)
		}
	}
}
