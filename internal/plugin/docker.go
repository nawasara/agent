package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/nawasara/agent/internal/analyzer"
)

// DockerPlugin monitors running containers via `docker events` and container health.
type DockerPlugin struct {
	CheckInterval time.Duration
	Incidents     chan<- analyzer.Incident
}

func NewDockerPlugin(incidents chan<- analyzer.Incident) *DockerPlugin {
	return &DockerPlugin{
		CheckInterval: 5 * time.Minute,
		Incidents:     incidents,
	}
}

// Run starts both the events listener and the periodic health check.
func (p *DockerPlugin) Run(ctx context.Context) {
	if !p.dockerAvailable() {
		log.Printf("[plugin:docker] docker not found, plugin inactive")
		return
	}
	log.Printf("[plugin:docker] started")

	// Periodic container health snapshot
	go p.healthLoop(ctx)

	// Stream docker events
	p.streamEvents(ctx)
}

func (p *DockerPlugin) dockerAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// ─── Docker events stream ─────────────────────────────────────────────────────

type dockerEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time int64 `json:"time"`
}

func (p *DockerPlugin) streamEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cmd := exec.CommandContext(ctx, "docker", "events",
			"--format", "{{json .}}",
			"--filter", "type=container",
			"--filter", "event=die",
			"--filter", "event=oom",
			"--filter", "event=kill",
			"--filter", "event=health_status",
		)

		out, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("[plugin:docker] stdout pipe: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				continue
			}
		}

		if err := cmd.Start(); err != nil {
			log.Printf("[plugin:docker] start events: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				continue
			}
		}

		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			var ev dockerEvent
			if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
				continue
			}
			p.handleEvent(ev)
		}

		cmd.Wait()

		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (p *DockerPlugin) handleEvent(ev dockerEvent) {
	name := ev.Actor.Attributes["name"]
	image := ev.Actor.Attributes["image"]
	exitCode := ev.Actor.Attributes["exitCode"]

	var (
		severity string
		score    int
		msg      string
	)

	switch ev.Action {
	case "oom":
		severity = "critical"
		score = 70
		msg = fmt.Sprintf("container %s (%s) killed by OOM killer", name, image)
	case "die":
		// Only flag non-zero exit codes as incidents
		if exitCode == "0" || exitCode == "" {
			return
		}
		severity = "medium"
		score = 30
		msg = fmt.Sprintf("container %s (%s) exited with code %s", name, image, exitCode)
	case "kill":
		severity = "medium"
		score = 25
		msg = fmt.Sprintf("container %s (%s) received kill signal", name, image)
	case "health_status":
		status := ev.Actor.Attributes["health_status"]
		if status != "unhealthy" {
			return
		}
		severity = "high"
		score = 50
		msg = fmt.Sprintf("container %s (%s) health check UNHEALTHY", name, image)
	default:
		return
	}

	p.emit(severity, score, msg, ev.Action)
}

// ─── Periodic container health snapshot ──────────────────────────────────────

type containerInfo struct {
	ID     string `json:"ID"`
	Names  string `json:"Names"`
	Image  string `json:"Image"`
	Status string `json:"Status"`
	State  string `json:"State"`
}

func (p *DockerPlugin) healthLoop(ctx context.Context) {
	ticker := time.NewTicker(p.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkContainers()
		}
	}
}

func (p *DockerPlugin) checkContainers() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "ps", "-a",
		"--format", `{"ID":"{{.ID}}","Names":"{{.Names}}","Image":"{{.Image}}","Status":"{{.Status}}","State":"{{.State}}"}`).Output()
	if err != nil {
		log.Printf("[plugin:docker] ps error: %v", err)
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var c containerInfo
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}
		// Only flag containers that are exited (not stopped intentionally)
		if strings.HasPrefix(c.State, "exited") && !strings.Contains(c.Status, "Exited (0)") {
			p.emit("medium", 30,
				fmt.Sprintf("container %s (%s) is in state: %s", c.Names, c.Image, c.Status),
				"container_exited",
			)
		}
	}
}

// ─── emit ─────────────────────────────────────────────────────────────────────

func (p *DockerPlugin) emit(severity string, score int, message, action string) {
	log.Printf("[plugin:docker] %s: %s", severity, message)
	inc := analyzer.Incident{
		ID:         fmt.Sprintf("docker-%s-%d", action, time.Now().UnixNano()),
		Type:       "docker_" + action,
		Severity:   analyzer.Severity(severity),
		SourceIP:   "127.0.0.1",
		Score:      score,
		Correlated: false,
		Evidence: []analyzer.Evidence{
			{
				Timestamp:   time.Now(),
				Raw:         message,
				MatchedRule: "plugin_docker",
			},
		},
		DetectedAt: time.Now(),
	}
	select {
	case p.Incidents <- inc:
	default:
		log.Printf("[plugin:docker] incident channel full, dropping: %s", message)
	}
}
