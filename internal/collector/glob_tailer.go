package collector

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GlobTailer watches a glob pattern (e.g. /var/log/nginx/*_access.log)
// and tails all matching files. Rescans for new files every scanInterval.
type GlobTailer struct {
	Pattern  string
	Out      chan<- Line
	stopCh   chan struct{}
	tailers  map[string]*Tailer
	mu       sync.Mutex
}

func NewGlobTailer(pattern string, out chan<- Line) *GlobTailer {
	return &GlobTailer{
		Pattern: pattern,
		Out:     out,
		stopCh:  make(chan struct{}),
		tailers: make(map[string]*Tailer),
	}
}

func (g *GlobTailer) Start() {
	go g.run()
}

func (g *GlobTailer) Stop() {
	close(g.stopCh)
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, t := range g.tailers {
		t.Stop()
	}
}

func (g *GlobTailer) run() {
	g.scan()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-g.stopCh:
			return
		case <-ticker.C:
			g.scan()
		}
	}
}

func (g *GlobTailer) scan() {
	matches, err := filepath.Glob(g.Pattern)
	if err != nil || len(matches) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	added := 0
	for _, path := range matches {
		if _, exists := g.tailers[path]; exists {
			continue
		}
		// Only regular files. A Docker bind mount to a log file that did not
		// exist yet creates a DIRECTORY with that name; on Bale-Production
		// /var/log/traefik/access.log was one, matched *.log, and the tailer
		// spun on "read: invalid argument" ~230 times a second.
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			continue
		}
		t := NewTailer(path, g.Out)
		t.Start()
		g.tailers[path] = t
		added++
	}
	if added > 0 {
		log.Printf("[glob] %s: watching %d file(s) (+%d new)", g.Pattern, len(g.tailers), added)
	}
}
