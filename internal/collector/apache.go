package collector

// Apache uses the same Combined Log Format as nginx — reuse NginxCollector
// with the apache log path. This file provides a named constructor so
// main.go reads clearly: NewApacheCollector vs NewNginxCollector.

func NewApacheCollector(logPath string, out chan<- Event) *NginxCollector {
	c := NewNginxCollector(logPath, out)
	c.source = "apache"
	return c
}
