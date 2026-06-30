package reporter

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "modernc.org/sqlite"

	"github.com/nawasara/agent/internal/analyzer"
	"github.com/nawasara/agent/internal/collector"
	"github.com/nawasara/agent/internal/config"
	"github.com/nawasara/agent/internal/health"
)

type Reporter struct {
	cfg    *config.Config
	db     *sql.DB
	client *http.Client
}

func New(cfg *config.Config) (*Reporter, error) {
	db, err := sql.Open("sqlite", cfg.Reporter.BufferDB)
	if err != nil {
		return nil, fmt.Errorf("open buffer db: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS pending_incidents (
		id TEXT PRIMARY KEY,
		payload TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		attempts INTEGER DEFAULT 0,
		last_attempt DATETIME
	)`); err != nil {
		return nil, fmt.Errorf("create buffer table: %w", err)
	}
	return &Reporter{
		cfg:    cfg,
		db:     db,
		client: &http.Client{Timeout: cfg.Reporter.PushTimeout},
	}, nil
}

// Send tries to POST incident to Dashboard. Buffers to SQLite on failure.
func (r *Reporter) Send(inc analyzer.Incident) {
	payload, err := json.Marshal(map[string]any{
		"agent_id": r.cfg.AgentID,
		"incident": inc,
	})
	if err != nil {
		log.Printf("reporter: marshal error: %v", err)
		return
	}
	if err := r.post("/api/agent/incidents", payload); err != nil {
		log.Printf("reporter: send failed, buffering: %v", err)
		r.buffer(inc.ID, payload)
	}
}

// SendHeartbeat posts a heartbeat to the Dashboard.
func (r *Reporter) SendHeartbeat(metrics *collector.SystemMetrics, plugins []string, pendingCount int, score float64) {
	payload, _ := json.Marshal(map[string]any{
		"agent_id":          r.cfg.AgentID,
		"version":           Version,
		"uptime_seconds":    int(time.Since(startTime).Seconds()),
		"pending_incidents": pendingCount,
		"plugins_active":    plugins,
		"health_score":      score,
		"metrics": map[string]any{
			"cpu_percent":      metrics.CPUPercent,
			"mem_used_mb":      metrics.MemUsedMB,
			"disk_used_percent": metrics.DiskUsedPct,
		},
	})
	if err := r.post("/api/agent/heartbeat", payload); err != nil {
		log.Printf("reporter: heartbeat failed: %v", err)
	}
}

// RetryLoop flushes buffered incidents. Call in a goroutine.
func (r *Reporter) RetryLoop(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.Reporter.RetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.flush()
			r.pruneOld()
		}
	}
}

func (r *Reporter) flush() {
	rows, err := r.db.Query(`SELECT id, payload FROM pending_incidents ORDER BY created_at LIMIT 10`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, payload string
		if err := rows.Scan(&id, &payload); err != nil {
			continue
		}
		if err := r.post("/api/agent/incidents", []byte(payload)); err == nil {
			r.db.Exec(`DELETE FROM pending_incidents WHERE id = ?`, id)
		} else {
			r.db.Exec(`UPDATE pending_incidents SET attempts = attempts+1, last_attempt = ? WHERE id = ?`, time.Now(), id)
		}
	}
}

func (r *Reporter) pruneOld() {
	cutoff := time.Now().Add(-r.cfg.Reporter.BufferMaxAge)
	r.db.Exec(`DELETE FROM pending_incidents WHERE created_at < ?`, cutoff)
}

func (r *Reporter) buffer(id string, payload []byte) {
	r.db.Exec(
		`INSERT OR IGNORE INTO pending_incidents (id, payload, created_at) VALUES (?, ?, ?)`,
		id, string(payload), time.Now(),
	)
}

func (r *Reporter) post(path string, body []byte) error {
	url := r.cfg.DashboardURL + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (r *Reporter) PendingCount() int {
	var n int
	r.db.QueryRow(`SELECT COUNT(*) FROM pending_incidents`).Scan(&n)
	return n
}

func (r *Reporter) Close() {
	r.db.Close()
}

var (
	Version   = "0.1.0"
	startTime = time.Now()
)

// HealthScorer calculates health score from metrics.
func HealthScore(m *collector.SystemMetrics, recentCritical, recentHigh int) float64 {
	return health.Calculate(m.CPUPercent, float64(m.MemUsedMB)/float64(m.MemTotalMB)*100, m.DiskUsedPct, recentCritical, recentHigh)
}
