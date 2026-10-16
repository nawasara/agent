package collector

import (
	"os"
	"path/filepath"
	"testing"
)

// A directory named like a log (Docker bind-mount artefact on Bale-Production,
// Oct 2026) must not be tailed: reading it fails instantly and used to loop.
func TestGlobSkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "access.log"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "router.log"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := make(chan Line, 10)
	g := NewGlobTailer(filepath.Join(dir, "*.log"), out)
	g.scan()
	defer g.Stop()

	if len(g.tailers) != 1 {
		t.Fatalf("want 1 tailer (router.log only), got %d", len(g.tailers))
	}
	if _, ok := g.tailers[filepath.Join(dir, "access.log")]; ok {
		t.Error("directory access.log must not be tailed")
	}
}

func TestOpenRefusesDirectory(t *testing.T) {
	tl := NewTailer(t.TempDir(), make(chan Line, 1))
	if f, err := tl.openAndSeek(); err == nil {
		f.Close()
		t.Fatal("openAndSeek on a directory must fail")
	}
}
