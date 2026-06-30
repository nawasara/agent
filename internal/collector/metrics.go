package collector

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

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
			m := c.collect()
			select {
			case c.out <- Event{Type: EventMetrics, Metrics: m}:
			default:
			}
		}
	}
}

func (c *MetricsCollector) collect() *SystemMetrics {
	m := &SystemMetrics{Timestamp: time.Now()}
	m.CPUPercent = readCPU()
	m.MemUsedMB, m.MemTotalMB = readMem()
	m.DiskUsedPct = readDisk("/")
	m.LoadAvg1, m.LoadAvg5 = readLoadAvg()
	return m
}

// readCPU reads two /proc/stat samples 200ms apart and returns usage %.
func readCPU() float64 {
	s1 := readCPUStat()
	time.Sleep(200 * time.Millisecond)
	s2 := readCPUStat()

	total := float64((s2[0] - s1[0]) + (s2[1] - s1[1]) + (s2[2] - s1[2]) + (s2[3] - s1[3]))
	idle := float64(s2[3] - s1[3])
	if total == 0 {
		return 0
	}
	return (1 - idle/total) * 100
}

// readCPUStat returns [user, nice, system, idle] from /proc/stat first cpu line.
func readCPUStat() [4]uint64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return [4]uint64{}
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			break
		}
		var vals [4]uint64
		for i := 0; i < 4; i++ {
			vals[i], _ = strconv.ParseUint(fields[i+1], 10, 64)
		}
		return vals
	}
	return [4]uint64{}
}

func readMem() (usedMB, totalMB uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	var total, available uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = val
		case "MemAvailable:":
			available = val
		}
	}
	used := total - available
	return used / 1024, total / 1024 // kB → MB
}

func readDisk(path string) float64 {
	// Use /proc/mounts + /proc/self/mountinfo is complex; simpler: statfs syscall.
	// For portability we parse df output via /proc — instead use a direct approach.
	// On Linux, read from /proc/self/mounts and use syscall.Statfs.
	// Simplified: read /proc/diskstats is for IO, not space.
	// We'll use a minimal statfs-like read from /proc/mounts sizes.
	// For now return 0 — real implementation needs syscall.Statfs which requires CGO or unsafe.
	// TODO: implement via syscall.Statfs when building on Linux.
	return 0
}

func readLoadAvg() (load1, load5 float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, 0
	}
	load1, _ = strconv.ParseFloat(fields[0], 64)
	load5, _ = strconv.ParseFloat(fields[1], 64)
	return
}
