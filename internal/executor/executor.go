package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/nawasara/agent/internal/config"
)

// Command represents a pending command received from the Dashboard.
type Command struct {
	CommandID string         `json:"command_id"`
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	IssuedAt  time.Time      `json:"issued_at"`
}

// Result is sent back to Dashboard after execution.
type Result struct {
	CommandID string `json:"command_id"`
	Success   bool   `json:"success"`
	Output    string `json:"output"`
	Error     string `json:"error,omitempty"`
	ExecAt    string `json:"exec_at"`
}

// Executor polls Dashboard for commands and executes allowed actions.
type Executor struct {
	cfg    *config.Config
	client *http.Client
	allow  map[string]bool
}

func New(cfg *config.Config) *Executor {
	allow := make(map[string]bool, len(cfg.Executor.AllowedActions))
	for _, a := range cfg.Executor.AllowedActions {
		allow[a] = true
	}
	return &Executor{
		cfg:    cfg,
		client: &http.Client{Timeout: 15 * time.Second},
		allow:  allow,
	}
}

// Run starts the poll loop. Call in a goroutine; returns when ctx is done.
func (e *Executor) Run(ctx context.Context) {
	interval := e.cfg.Executor.PollInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("[executor] started — poll_interval=%s allowed=%v", interval, e.cfg.Executor.AllowedActions)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.poll()
		}
	}
}

func (e *Executor) poll() {
	cmds, err := e.fetchPending()
	if err != nil {
		log.Printf("[executor] poll error: %v", err)
		return
	}
	for _, cmd := range cmds {
		e.handle(cmd)
	}
}

func (e *Executor) fetchPending() ([]Command, error) {
	url := e.cfg.DashboardURL + "/api/agent/commands/pending"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Key", e.cfg.APIKey)
	req.Header.Set("X-Agent-Id", e.cfg.AgentID)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		var body struct {
			Commands []Command `json:"commands"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return nil, fmt.Errorf("decode commands: %w", err)
		}
		return body.Commands, nil
	}
	return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
}

func (e *Executor) handle(cmd Command) {
	log.Printf("[executor] received command=%s action=%s", cmd.CommandID, cmd.Action)

	res := Result{
		CommandID: cmd.CommandID,
		ExecAt:    time.Now().UTC().Format(time.RFC3339),
	}

	if !e.allow[cmd.Action] {
		res.Success = false
		res.Error = fmt.Sprintf("action %q is not in allowed_actions — refusing", cmd.Action)
		log.Printf("[executor] REFUSED command=%s action=%s (not allowlisted)", cmd.CommandID, cmd.Action)
		e.sendResult(res)
		return
	}

	output, err := dispatch(cmd.Action, cmd.Params)
	if err != nil {
		res.Success = false
		res.Error = err.Error()
		res.Output = output
		log.Printf("[executor] FAILED command=%s action=%s: %v", cmd.CommandID, cmd.Action, err)
	} else {
		res.Success = true
		res.Output = output
		log.Printf("[executor] OK command=%s action=%s", cmd.CommandID, cmd.Action)
	}

	e.sendResult(res)
}

func (e *Executor) sendResult(res Result) {
	payload, err := json.Marshal(res)
	if err != nil {
		log.Printf("[executor] marshal result: %v", err)
		return
	}

	url := e.cfg.DashboardURL + "/api/agent/command-result"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("[executor] build result request: %v", err)
		return
	}
	req.Header.Set("X-Agent-Key", e.cfg.APIKey)
	req.Header.Set("X-Agent-Id", e.cfg.AgentID)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		log.Printf("[executor] send result: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("[executor] send result: HTTP %d", resp.StatusCode)
	}
}
