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

// RuleWindow menghitung kecocokan satu aturan per IP dalam jendela geser
// milik aturan itu sendiri. Dipakai aturan Isolated; lihat Rule.Isolated.
type RuleWindow struct {
	mu      sync.Mutex
	entries map[string]*ruleHits
}

type ruleHits struct {
	times    []time.Time
	evidence []Evidence
	window   time.Duration
}

func NewRuleWindow() *RuleWindow {
	w := &RuleWindow{entries: make(map[string]*ruleHits)}
	go w.gcLoop()
	return w
}

// Add mencatat satu kecocokan dan mengembalikan jumlah kecocokan beserta
// buktinya yang masih berada di dalam jendela.
func (w *RuleWindow) Add(key string, window time.Duration, ev Evidence) (count int, evidence []Evidence) {
	w.mu.Lock()
	defer w.mu.Unlock()

	h, ok := w.entries[key]
	if !ok {
		h = &ruleHits{window: window}
		w.entries[key] = h
	}
	now := time.Now()
	cutoff := now.Add(-window)
	keep := 0
	for keep < len(h.times) && h.times[keep].Before(cutoff) {
		keep++
	}
	h.times = append(h.times[keep:], now)
	h.evidence = append(h.evidence[keep:], ev)
	return len(h.times), append([]Evidence(nil), h.evidence...)
}

func (w *RuleWindow) Reset(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.entries, key)
}

func (w *RuleWindow) gcLoop() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		now := time.Now()
		w.mu.Lock()
		for k, h := range w.entries {
			if len(h.times) == 0 || now.Sub(h.times[len(h.times)-1]) > h.window {
				delete(w.entries, k)
			}
		}
		w.mu.Unlock()
	}
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
