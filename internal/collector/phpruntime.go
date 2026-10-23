package collector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// PHPRuntime adalah satu PHP yang terpasang di host ini: biner host, ea-php
// cPanel, alt-php CloudLinux, atau PHP di dalam container Docker.
//
// Dikirim ke Nawasara bersama heartbeat (pemantau versi PHP secscan). Lahir
// dari PHP2Shell (CVE-2026-109618/109619, Oktober 2026): versi PHP di dalam
// VM Proxmox tidak terlihat dari API Proxmox (guest agent tidak terpasang),
// dan agen satu-satunya yang berada di dalamnya.
type PHPRuntime struct {
	Target  string `json:"target"`
	Handler string `json:"handler,omitempty"`
	Version string `json:"version,omitempty"`
}

var phpVersionRe = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// Container dibatasi supaya host dengan ratusan container tidak membuat
// pengumpulan ini berjalan berpuluh menit.
const maxContainers = 50

// CollectPHPRuntimes mengumpulkan semua PHP yang bisa ditemukan. Tidak ada
// yang fatal: biner yang gagal dijalankan dilewati begitu saja.
func CollectPHPRuntimes(ctx context.Context) []PHPRuntime {
	host, _ := os.Hostname()
	out := []PHPRuntime{}

	if path, err := exec.LookPath("php"); err == nil {
		if v := phpVersion(ctx, path); v != "" {
			out = append(out, PHPRuntime{Target: host, Handler: "host", Version: v})
		}
	}

	for _, pattern := range []string{"/opt/cpanel/ea-php*/root/usr/bin/php", "/opt/alt/php*/usr/bin/php"} {
		matches, _ := filepath.Glob(pattern)
		for _, bin := range matches {
			handler := handlerFromPath(bin)
			if v := phpVersion(ctx, bin); v != "" {
				out = append(out, PHPRuntime{Target: host + " " + handler, Handler: handler, Version: v})
			}
		}
	}

	return append(out, dockerPHPRuntimes(ctx, host)...)
}

func dockerPHPRuntimes(ctx context.Context, host string) []PHPRuntime {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}

	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	names, err := exec.CommandContext(listCtx, "docker", "ps", "--format", "{{.Names}}").Output()
	if err != nil {
		return nil
	}

	out := []PHPRuntime{}
	for i, name := range strings.Fields(string(names)) {
		if i >= maxContainers {
			break
		}
		cctx, ccancel := context.WithTimeout(ctx, 8*time.Second)
		raw, err := exec.CommandContext(cctx, "docker", "exec", name, "php", "-r", "echo PHP_VERSION;").Output()
		ccancel()
		if err != nil {
			continue // tidak ada PHP di container ini
		}
		if v := phpVersionRe.FindString(strings.TrimSpace(string(raw))); v != "" {
			out = append(out, PHPRuntime{Target: host + "/" + name, Handler: "docker:" + name, Version: v})
		}
	}
	return out
}

func phpVersion(ctx context.Context, bin string) string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(cctx, bin, "-n", "-r", "echo PHP_VERSION;").Output()
	if err != nil {
		return ""
	}
	return phpVersionRe.FindString(strings.TrimSpace(string(raw)))
}

// handlerFromPath: /opt/cpanel/ea-php81/root/usr/bin/php → ea-php81,
// /opt/alt/php74/usr/bin/php → alt-php74.
func handlerFromPath(bin string) string {
	for _, part := range strings.Split(filepath.ToSlash(bin), "/") {
		if strings.HasPrefix(part, "ea-php") {
			return part
		}
		if strings.HasPrefix(part, "php") && len(part) > 3 && part != "php" {
			return "alt-" + part
		}
	}
	return filepath.Base(bin)
}
