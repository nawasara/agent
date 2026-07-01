package executor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// dispatch routes an action to its handler and returns (stdout, error).
func dispatch(action string, params map[string]any) (string, error) {
	switch action {
	case "block_ip":
		return blockIP(params)
	case "unblock_ip":
		return unblockIP(params)
	case "restart_nginx":
		return systemctl("restart", "nginx")
	case "reload_nginx":
		return systemctl("reload", "nginx")
	case "restart_apache":
		return systemctlAny("restart", "apache2", "httpd")
	case "reload_apache":
		return systemctlAny("reload", "apache2", "httpd")
	case "restart_php_fpm":
		return systemctlPattern("restart", "php", "-fpm")
	case "reload_php_fpm":
		return systemctlPattern("reload", "php", "-fpm")
	case "restart_mysql":
		return systemctlAny("restart", "mysql", "mysqld", "mariadb")
	case "artisan_queue_restart":
		return artisan("queue:restart")
	case "artisan_optimize_clear":
		return artisan("optimize:clear")
	default:
		return "", fmt.Errorf("unknown action: %s", action)
	}
}

// ─── iptables helpers ────────────────────────────────────────────────────────

func blockIP(params map[string]any) (string, error) {
	ip, ok := params["ip"].(string)
	if !ok || ip == "" {
		return "", fmt.Errorf("block_ip: missing param 'ip'")
	}
	if !isValidIP(ip) {
		return "", fmt.Errorf("block_ip: invalid IP address %q", ip)
	}

	// Prefer nftables if available, fall back to iptables
	if nftAvailable() {
		return nftBlock(ip)
	}
	return iptablesBlock(ip)
}

func unblockIP(params map[string]any) (string, error) {
	ip, ok := params["ip"].(string)
	if !ok || ip == "" {
		return "", fmt.Errorf("unblock_ip: missing param 'ip'")
	}
	if !isValidIP(ip) {
		return "", fmt.Errorf("unblock_ip: invalid IP address %q", ip)
	}

	if nftAvailable() {
		return nftUnblock(ip)
	}
	return iptablesUnblock(ip)
}

func iptablesBlock(ip string) (string, error) {
	// Check if rule already exists to avoid duplicates
	check := runCmd("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
	if check == nil {
		return fmt.Sprintf("iptables: %s already blocked", ip), nil
	}
	if err := runCmd("iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"); err != nil {
		return "", fmt.Errorf("iptables block: %w", err)
	}
	// Persist via iptables-save if available
	_ = runCmd("iptables-save")
	return fmt.Sprintf("iptables: blocked %s (INPUT DROP)", ip), nil
}

func iptablesUnblock(ip string) (string, error) {
	if err := runCmd("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"); err != nil {
		return "", fmt.Errorf("iptables unblock: %w", err)
	}
	_ = runCmd("iptables-save")
	return fmt.Sprintf("iptables: unblocked %s", ip), nil
}

func nftAvailable() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

func nftBlock(ip string) (string, error) {
	// Add to a nawasara blocklist set; create if absent
	_ = runCmd("nft", "add", "table", "ip", "nawasara")
	_ = runCmd("nft", "add", "set", "ip", "nawasara", "blocklist", "{", "type", "ipv4_addr;", "}")
	_ = runCmd("nft", "add", "chain", "ip", "nawasara", "input", "{", "type", "filter", "hook", "input", "priority", "0;", "}")
	_ = runCmd("nft", "add", "rule", "ip", "nawasara", "input", "ip", "saddr", "@blocklist", "drop")
	if err := runCmd("nft", "add", "element", "ip", "nawasara", "blocklist", "{", ip, "}"); err != nil {
		return "", fmt.Errorf("nft block: %w", err)
	}
	return fmt.Sprintf("nft: blocked %s (nawasara/blocklist)", ip), nil
}

func nftUnblock(ip string) (string, error) {
	if err := runCmd("nft", "delete", "element", "ip", "nawasara", "blocklist", "{", ip, "}"); err != nil {
		return "", fmt.Errorf("nft unblock: %w", err)
	}
	return fmt.Sprintf("nft: unblocked %s", ip), nil
}

// ─── systemctl helpers ───────────────────────────────────────────────────────

func systemctl(verb, unit string) (string, error) {
	out, err := runCmdOutput("systemctl", verb, unit)
	if err != nil {
		return out, fmt.Errorf("systemctl %s %s: %w", verb, unit, err)
	}
	return fmt.Sprintf("systemctl %s %s: OK\n%s", verb, unit, out), nil
}

// systemctlAny tries units in order and succeeds on first match.
func systemctlAny(verb string, units ...string) (string, error) {
	for _, unit := range units {
		// Check if unit exists
		if runCmd("systemctl", "list-units", "--all", unit) == nil {
			return systemctl(verb, unit)
		}
	}
	return "", fmt.Errorf("none of the units found: %v", units)
}

// systemctlPattern finds the first active unit whose name starts with prefix and ends with suffix.
func systemctlPattern(verb, prefix, suffix string) (string, error) {
	out, err := runCmdOutput("systemctl", "list-units", "--all", "--no-pager", "--plain", "--no-legend", "--type=service")
	if err != nil {
		return "", fmt.Errorf("list-units: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := fields[0]
		if strings.HasPrefix(unit, prefix) && strings.HasSuffix(unit, suffix+".service") {
			return systemctl(verb, unit)
		}
	}
	return "", fmt.Errorf("no active unit matching %s*%s found", prefix, suffix)
}

// ─── artisan helpers ─────────────────────────────────────────────────────────

// artisanDirs lists known Laravel app root directories to try in order.
var artisanDirs = []string{
	"/var/www/html",
	"/var/www",
	"/home/forge/default",
	"/srv/app",
}

func artisan(cmd string) (string, error) {
	// Find artisan in known locations
	for _, dir := range artisanDirs {
		artisanPath := dir + "/artisan"
		if fileExist(artisanPath) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			c := exec.CommandContext(ctx, "php", artisanPath, cmd)
			c.Dir = dir
			var out bytes.Buffer
			c.Stdout = &out
			c.Stderr = &out
			err := c.Run()
			output := strings.TrimSpace(out.String())
			if err != nil {
				return output, fmt.Errorf("artisan %s: %w", cmd, err)
			}
			return fmt.Sprintf("artisan %s: OK\n%s", cmd, output), nil
		}
	}
	return "", fmt.Errorf("artisan not found in %v", artisanDirs)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func runCmd(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

func runCmdOutput(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	c := exec.CommandContext(ctx, name, args...)
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	return strings.TrimSpace(out.String()), err
}

func isValidIP(ip string) bool {
	// Very basic check — must contain only digits, dots, colons (IPv4/IPv6)
	for _, c := range ip {
		if !((c >= '0' && c <= '9') || c == '.' || c == ':' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	// Must not be empty or loopback
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return false
	}
	return true
}

func fileExist(path string) bool {
	c := exec.Command("test", "-f", path)
	return c.Run() == nil
}
