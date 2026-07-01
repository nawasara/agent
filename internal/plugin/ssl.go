package plugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/nawasara/agent/internal/analyzer"
)

// SSLPlugin monitors TLS certificate expiry on configured hostnames.
// Emits incidents when certs expire within the warning/critical thresholds.
type SSLPlugin struct {
	Hosts         []string
	CheckInterval time.Duration
	WarnDays      int // emit "high" incident when expiry < WarnDays
	CritDays      int // emit "critical" incident when expiry < CritDays
	Incidents     chan<- analyzer.Incident
}

func NewSSLPlugin(hosts []string, incidents chan<- analyzer.Incident) *SSLPlugin {
	return &SSLPlugin{
		Hosts:         hosts,
		CheckInterval: 12 * time.Hour,
		WarnDays:      30,
		CritDays:      7,
		Incidents:     incidents,
	}
}

// Run starts the SSL check loop. Call in a goroutine.
func (p *SSLPlugin) Run(ctx context.Context) {
	log.Printf("[plugin:ssl] started — hosts=%v check_interval=%s", p.Hosts, p.CheckInterval)
	// Initial check immediately on start
	p.checkAll()

	ticker := time.NewTicker(p.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkAll()
		}
	}
}

func (p *SSLPlugin) checkAll() {
	for _, host := range p.Hosts {
		if err := p.check(host); err != nil {
			log.Printf("[plugin:ssl] check %s: %v", host, err)
		}
	}
}

func (p *SSLPlugin) check(host string) error {
	// Add default port if absent
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: false},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		// Emit incident for connection failure
		p.emit(host, "critical", 80, fmt.Sprintf("TLS connection failed: %v", err))
		return nil
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		p.emit(host, "high", 50, "no peer certificates returned")
		return nil
	}

	cert := certs[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

	log.Printf("[plugin:ssl] %s expires %s (%d days)", host, cert.NotAfter.Format("2006-01-02"), daysLeft)

	switch {
	case daysLeft < 0:
		p.emit(host, "critical", 90, fmt.Sprintf("TLS certificate EXPIRED %d days ago (expiry: %s)", -daysLeft, cert.NotAfter.Format("2006-01-02")))
	case daysLeft < p.CritDays:
		p.emit(host, "critical", 80, fmt.Sprintf("TLS certificate expires in %d days (expiry: %s)", daysLeft, cert.NotAfter.Format("2006-01-02")))
	case daysLeft < p.WarnDays:
		p.emit(host, "high", 50, fmt.Sprintf("TLS certificate expires in %d days (expiry: %s)", daysLeft, cert.NotAfter.Format("2006-01-02")))
	}
	return nil
}

func (p *SSLPlugin) emit(host, severity string, score int, message string) {
	inc := analyzer.Incident{
		ID:         fmt.Sprintf("ssl-%s-%d", sanitizeHost(host), time.Now().UnixNano()),
		Type:       "ssl_cert_expiry",
		Severity:   analyzer.Severity(severity),
		SourceIP:   "127.0.0.1",
		Score:      score,
		Correlated: false,
		Evidence: []analyzer.Evidence{
			{
				Timestamp:   time.Now(),
				Raw:         message,
				MatchedRule: "plugin_ssl",
			},
		},
		DetectedAt: time.Now(),
	}
	select {
	case p.Incidents <- inc:
	default:
		log.Printf("[plugin:ssl] incident channel full, dropping: %s", message)
	}
}

func sanitizeHost(host string) string {
	replacer := strings.NewReplacer(":", "-", ".", "-", "/", "-")
	return replacer.Replace(host)
}
