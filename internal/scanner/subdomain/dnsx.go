package subdomain

import (
	"bytes"
	"context"
	"net"
	"os/exec"
	"strings"
)

// ResolveBatch resolves a list of hostnames using dnsx (when available) or
// stdlib DNS. Returns only the hostnames that successfully resolve to an IP.
// dnsx is dramatically faster for large hostname lists due to parallel resolution.
//
// When dnsx is not available (bin == ""), falls back to parallel net.LookupHost
// with up to 50 concurrent goroutines.
func ResolveBatch(ctx context.Context, hostnames []string, dnsxBin string) []string {
	if len(hostnames) == 0 {
		return nil
	}

	// Try dnsx when a bin path is provided and the binary actually exists.
	if dnsxBin != "" {
		if _, err := exec.LookPath(dnsxBin); err == nil {
			if results := resolveBatchDNSX(ctx, hostnames, dnsxBin); results != nil {
				return results
			}
		}
	}

	// Fallback: parallel net.LookupHost with 50-goroutine semaphore.
	type result struct {
		hostname string
		ok       bool
	}
	results := make(chan result, len(hostnames))
	sem := make(chan struct{}, 50)

	for _, h := range hostnames {
		h := h
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			addrs, err := net.DefaultResolver.LookupHost(ctx, h)
			results <- result{hostname: h, ok: err == nil && len(addrs) > 0}
		}()
	}

	var resolved []string
	for range hostnames {
		r := <-results
		if r.ok {
			resolved = append(resolved, r.hostname)
		}
	}
	return resolved
}

// resolveBatchDNSX runs dnsx to batch-resolve hostnames and returns only the
// ones that resolved. Returns nil on any execution error so the caller falls back.
func resolveBatchDNSX(ctx context.Context, hostnames []string, dnsxBin string) []string {
	input := strings.Join(hostnames, "\n")

	cmd := exec.CommandContext(ctx, dnsxBin,
		"-silent", "-r", "8.8.8.8,1.1.1.1", "-threads", "100",
	)
	cmd.Stdin = bytes.NewBufferString(input)

	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var resolved []string

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		if _, ok := seen[line]; !ok {
			seen[line] = struct{}{}
			resolved = append(resolved, line)
		}
	}
	return resolved
}
