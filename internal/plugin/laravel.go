package plugin

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/nawasara/agent/internal/analyzer"
)

// LaravelPlugin tails Laravel log files and emits incidents for critical errors.
type LaravelPlugin struct {
	LogPaths  []string
	Incidents chan<- analyzer.Incident
}

var knownLaravelLogPaths = []string{
	"/var/www/html/storage/logs/laravel.log",
	"/var/www/storage/logs/laravel.log",
	"/home/forge/default/storage/logs/laravel.log",
	"/srv/app/storage/logs/laravel.log",
}

func NewLaravelPlugin(logPaths []string, incidents chan<- analyzer.Incident) *LaravelPlugin {
	paths := logPaths
	if len(paths) == 0 {
		paths = autoDetectLaravelLogs()
	}
	return &LaravelPlugin{
		LogPaths:  paths,
		Incidents: incidents,
	}
}

func autoDetectLaravelLogs() []string {
	var found []string
	for _, p := range knownLaravelLogPaths {
		if _, err := os.Stat(p); err == nil {
			found = append(found, p)
		}
	}
	return found
}

// Run tails all detected Laravel log files concurrently.
func (p *LaravelPlugin) Run(ctx context.Context) {
	if len(p.LogPaths) == 0 {
		log.Printf("[plugin:laravel] no log files found, plugin inactive")
		return
	}
	log.Printf("[plugin:laravel] tailing %d log files: %v", len(p.LogPaths), p.LogPaths)

	lineCh := make(chan string, 1000)

	for _, path := range p.LogPaths {
		go tailFile(ctx, path, lineCh)
	}

	p.processLines(ctx, lineCh)
}

// Laravel log line format (monolog):
// [2026-07-01 10:23:45] production.ERROR: message {"context":"..."}
var laravelLogRe = regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \w+\.(\w+): (.+)$`)

func (p *LaravelPlugin) processLines(ctx context.Context, lines <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case line := <-lines:
			p.parseLine(line)
		}
	}
}

func (p *LaravelPlugin) parseLine(line string) {
	m := laravelLogRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return
	}

	level := strings.ToUpper(m[2]) // ERROR, CRITICAL, ALERT, EMERGENCY, WARNING
	message := m[3]

	var (
		severity string
		score    int
		emit     bool
	)

	switch level {
	case "EMERGENCY", "ALERT", "CRITICAL":
		severity = "critical"
		score = 70
		emit = true
	case "ERROR":
		if isSignificantError(message) {
			severity = "high"
			score = 45
			emit = true
		}
	case "WARNING":
		if isQueueFailure(message) {
			severity = "medium"
			score = 25
			emit = true
		}
	}

	if !emit {
		return
	}

	p.emitIncident(severity, score, level, message)
}

func isSignificantError(msg string) bool {
	keywords := []string{
		"QueryException", "PDOException", "SQLSTATE",
		"Out of memory", "Call to undefined", "Class not found",
		"Connection refused", "No such file", "failed to open stream",
		"Unable to allocate",
	}
	upper := strings.ToUpper(msg)
	for _, kw := range keywords {
		if strings.Contains(upper, strings.ToUpper(kw)) {
			return true
		}
	}
	return false
}

func isQueueFailure(msg string) bool {
	keywords := []string{
		"max attempts exceeded", "Horizon supervisor", "queue worker failed",
	}
	upper := strings.ToUpper(msg)
	for _, kw := range keywords {
		if strings.Contains(upper, strings.ToUpper(kw)) {
			return true
		}
	}
	return false
}

func (p *LaravelPlugin) emitIncident(severity string, score int, level, message string) {
	raw := message
	if len(raw) > 500 {
		raw = raw[:500] + "..."
	}

	inc := analyzer.Incident{
		ID:         fmt.Sprintf("laravel-%s-%d", strings.ToLower(level), time.Now().UnixNano()),
		Type:       "laravel_" + strings.ToLower(level),
		Severity:   analyzer.Severity(severity),
		SourceIP:   "127.0.0.1",
		Score:      score,
		Correlated: false,
		Evidence: []analyzer.Evidence{
			{
				Timestamp:   time.Now(),
				Raw:         fmt.Sprintf("[%s] %s", level, raw),
				MatchedRule: "plugin_laravel",
			},
		},
		DetectedAt: time.Now(),
	}
	select {
	case p.Incidents <- inc:
	default:
		log.Printf("[plugin:laravel] incident channel full")
	}
}

// tailFile seeks to end of file then emits new lines until ctx done.
// Handles log rotation by reopening the file when EOF is detected after content changes.
func tailFile(ctx context.Context, path string, out chan<- string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		f, err := os.Open(path)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
				continue
			}
		}

		// Seek to end — only read new lines
		f.Seek(0, 2)

		scanner := bufio.NewScanner(f)
		for {
			select {
			case <-ctx.Done():
				f.Close()
				return
			default:
			}

			if scanner.Scan() {
				select {
				case out <- scanner.Text():
				case <-ctx.Done():
					f.Close()
					return
				}
			} else {
				// Check for rotation
				fi1, err1 := f.Stat()
				fi2, err2 := os.Stat(path)
				if err1 == nil && err2 == nil && !os.SameFile(fi1, fi2) {
					// File rotated — reopen
					break
				}
				select {
				case <-ctx.Done():
					f.Close()
					return
				case <-time.After(500 * time.Millisecond):
					scanner = bufio.NewScanner(f)
				}
			}
		}
		f.Close()
	}
}
