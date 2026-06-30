package collector

import (
	"regexp"
	"strings"
	"time"
)

var (
	sshFailedRE  = regexp.MustCompile(`Failed \S+ for(?: invalid user)? (\S+) from (\S+) port (\d+)`)
	sshAcceptRE  = regexp.MustCompile(`Accepted \S+ for (\S+) from (\S+) port (\d+)`)
	sshInvalidRE = regexp.MustCompile(`Invalid user (\S+) from (\S+) port (\d+)`)
)

type SSHCollector struct {
	logPath string
	out     chan<- Event
	lineCh  chan string
	tailer  *Tailer
}

func NewSSHCollector(logPath string, out chan<- Event) *SSHCollector {
	lineCh := make(chan string, 500)
	return &SSHCollector{logPath: logPath, out: out, lineCh: lineCh, tailer: NewTailer(logPath, lineCh)}
}

func (c *SSHCollector) Start() {
	c.tailer.Start()
	go c.process()
}

func (c *SSHCollector) Stop() {
	c.tailer.Stop()
}

func (c *SSHCollector) process() {
	for line := range c.lineCh {
		ev := c.parse(strings.TrimSpace(line))
		if ev == nil {
			continue
		}
		select {
		case c.out <- Event{Type: EventSSH, SSH: ev}:
		default:
		}
	}
}

func (c *SSHCollector) parse(line string) *SSHEvent {
	now := time.Now()

	if m := sshFailedRE.FindStringSubmatch(line); m != nil {
		eventType := "failed"
		if strings.Contains(line, "invalid user") {
			eventType = "invalid_user"
		}
		return &SSHEvent{Timestamp: now, User: m[1], SourceIP: m[2], EventType: eventType, Raw: line}
	}
	if m := sshAcceptRE.FindStringSubmatch(line); m != nil {
		eventType := "accepted"
		if m[1] == "root" {
			eventType = "root_accepted"
		}
		return &SSHEvent{Timestamp: now, User: m[1], SourceIP: m[2], EventType: eventType, Raw: line}
	}
	if m := sshInvalidRE.FindStringSubmatch(line); m != nil {
		return &SSHEvent{Timestamp: now, User: m[1], SourceIP: m[2], EventType: "invalid_user", Raw: line}
	}
	return nil
}
