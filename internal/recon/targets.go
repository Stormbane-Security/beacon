package recon

import (
	"bufio"
	"io"
	"net/url"
	"os"
	"strings"
)

// LoadTargets reads a target list from a file, one target per line.
// Blank lines and lines starting with '#' are ignored.
// Each line can be a domain, URL, host:port, or IP.
func LoadTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readTargets(f)
}

// ReadTargetsFromStdin reads targets from stdin, one per line.
// Supports the same formats as LoadTargets.
func ReadTargetsFromStdin() ([]string, error) {
	return readTargets(os.Stdin)
}

// readTargets reads targets from any reader, normalizing each line.
func readTargets(r io.Reader) ([]string, error) {
	var targets []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host := NormalizeTarget(line)
		if host != "" {
			targets = append(targets, host)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

// NormalizeTarget extracts a hostname from various input formats:
//   - "example.com" -> "example.com"
//   - "https://example.com/path" -> "example.com"
//   - "https://example.com:8443/path" -> "example.com:8443"
//   - "example.com:8080" -> "example.com:8080"
//   - "192.168.1.1" -> "192.168.1.1"
//   - "http://192.168.1.1:9200" -> "192.168.1.1:9200"
//
// Standard ports (80, 443) are stripped. Non-standard ports are preserved
// so beacon scans the right port.
func NormalizeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// If it looks like a URL (has scheme), parse it.
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		host := u.Hostname()
		port := u.Port()
		if port != "" && port != "80" && port != "443" {
			return host + ":" + port
		}
		return host
	}

	// Handle host:port without scheme.
	// If there's exactly one colon and the part after is numeric, it's host:port.
	if idx := strings.LastIndex(raw, ":"); idx > 0 {
		host := raw[:idx]
		port := raw[idx+1:]
		// Verify it's a port (all digits, reasonable range).
		isPort := true
		for _, c := range port {
			if c < '0' || c > '9' {
				isPort = false
				break
			}
		}
		if isPort && port != "80" && port != "443" {
			return host + ":" + port
		}
		if isPort {
			return host
		}
	}

	// Strip trailing path/query if someone pastes a bare domain with path.
	if idx := strings.Index(raw, "/"); idx > 0 {
		raw = raw[:idx]
	}

	return raw
}

// DeduplicateTargets removes duplicate entries from a target list,
// preserving the original order. Comparison is case-insensitive.
func DeduplicateTargets(targets []string) []string {
	seen := make(map[string]bool, len(targets))
	var out []string
	for _, t := range targets {
		key := strings.ToLower(t)
		if !seen[key] {
			seen[key] = true
			out = append(out, t)
		}
	}
	return out
}
