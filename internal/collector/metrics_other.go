//go:build !linux

package collector

import "time"

// MetricsCollector polls system metrics every interval.
type MetricsCollector struct {
	interval time.Duration
	out      chan<- Event
	stopCh   chan struct{}
}

func NewMetricsCollector(interval time.Duration, out chan<- Event) *MetricsCollector {
	return &MetricsCollector{interval: interval, out: out, stopCh: make(chan struct{})}
}

func (c *MetricsCollector) Start() {
	go c.run()
}

func (c *MetricsCollector) Stop() {
	close(c.stopCh)
}

func (c *MetricsCollector) run() {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			m := &SystemMetrics{Timestamp: time.Now()}
			select {
			case c.out <- Event{Type: EventMetrics, Metrics: m}:
			default:
			}
		}
	}
}
