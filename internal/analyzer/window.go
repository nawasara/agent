package analyzer

import (
	"sync"
	"time"
)

// IPWindow tracks per-IP score + evidence within a sliding time window.
type IPWindow struct {
	mu        sync.Mutex
	entries   map[string]*ipState
	windowDur time.Duration
}

type ipState struct {
	score    int
	evidence []Evidence
	types    []string // incident types seen (for correlation)
	lastSeen time.Time
}

func NewIPWindow(window time.Duration) *IPWindow {
	w := &IPWindow{entries: make(map[string]*ipState), windowDur: window}
	go w.gcLoop()
	return w
}

// Add adds score + evidence for ip. Returns total score and all evidence after add.
func (w *IPWindow) Add(ip string, score int, ev Evidence, incType string) (totalScore int, allEvidence []Evidence, types []string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	s, ok := w.entries[ip]
	if !ok {
		s = &ipState{}
		w.entries[ip] = s
	}
	s.score += score
	s.evidence = append(s.evidence, ev)
	s.types = append(s.types, incType)
	s.lastSeen = time.Now()
	return s.score, s.evidence, s.types
}

// Reset clears the state for ip after an incident is generated.
func (w *IPWindow) Reset(ip string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.entries, ip)
}

func (w *IPWindow) gcLoop() {
	ticker := time.NewTicker(w.windowDur)
	for range ticker.C {
		cutoff := time.Now().Add(-w.windowDur)
		w.mu.Lock()
		for ip, s := range w.entries {
			if s.lastSeen.Before(cutoff) {
				delete(w.entries, ip)
			}
		}
		w.mu.Unlock()
	}
}
