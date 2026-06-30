package plugin

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Plugin struct {
	ID          string      `yaml:"id"`
	Name        string      `yaml:"name"`
	Version     string      `yaml:"version"`
	Description string      `yaml:"description"`
	Collectors  []Collector `yaml:"collectors"`
}

type Collector struct {
	Type     string `yaml:"type"`
	Socket   string `yaml:"socket"`
	Interval string `yaml:"interval"`
}

// Manager loads plugins from the available dir and tracks which are enabled.
type Manager struct {
	availableDir string
	enabledNames []string
	loaded       map[string]*Plugin
}

func NewManager(availableDir string, enabled []string) *Manager {
	return &Manager{availableDir: availableDir, enabledNames: enabled, loaded: make(map[string]*Plugin)}
}

func (m *Manager) Load() error {
	for _, name := range m.enabledNames {
		path := filepath.Join(m.availableDir, name+".yaml")
		data, err := os.ReadFile(path)
		if err != nil {
			// Built-in plugins don't need a yaml file — skip silently
			continue
		}
		var p Plugin
		if err := yaml.Unmarshal(data, &p); err != nil {
			continue
		}
		m.loaded[name] = &p
	}
	return nil
}

func (m *Manager) Active() []string {
	return m.enabledNames
}

func (m *Manager) IsEnabled(name string) bool {
	for _, n := range m.enabledNames {
		if n == name {
			return true
		}
	}
	return false
}
