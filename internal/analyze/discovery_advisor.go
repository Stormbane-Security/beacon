// Package analyze — DiscoveryAdvisor uses Claude to suggest additional hostnames
// to probe based on already-discovered assets and their lightweight fingerprints.
//
// This runs between Phase 1 (subdomain discovery) and Phase 2 (vulnerability scan),
// deep mode only. It gives the AI a compact picture of what was found and asks it to
// suggest patterns it recognises from the tech stack / naming / ASN context.
//
// Design constraints:
//   - Uses claude-haiku for speed and cost (this runs during an active scan)
//   - 512 max output tokens — enough for a list of ~25 hostnames + reasoning
//   - Hard cap: 2 expansion rounds, 20 suggestions per round
//   - Only adds assets that respond to a live HTTP/DNS probe
//   - Skips silently if apiKey is empty (advisory is opt-in)
package analyze

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

const (
	advisorModel     = "claude-haiku-4-5-20251001"
	advisorMaxTokens = 512
	// AdvisorMaxRounds is the maximum number of AI-guided discovery expansion rounds.
	AdvisorMaxRounds = 2
	advisorMaxSugg   = 20
)

// AssetHint is a compact fingerprint of a discovered asset used by the advisor.
// Populated from classify evidence and actual scan findings after a full scan
// round completes — giving the AI the richest possible signal before it suggests
// new hostnames to probe.
type AssetHint struct {
	Hostname    string
	StatusCode  int      // 0 = no HTTP response (DNS-only or unreachable)
	Title       string   // page title or X-Powered-By hint
	Server      string   // Server response header
	CNAMEChain  []string
	TechStack   []string // detected technologies (e.g. "WordPress 6.4", "nginx/1.25")
	OpenPorts   []string // e.g. ["6379/redis", "9200/elasticsearch"]
	KeyFindings []string // compact finding summaries, e.g. "Jenkins exposed at /jenkins"
}

// DiscoveryAdvisor uses Claude to expand the asset surface during deep scans.
type DiscoveryAdvisor struct {
	apiKey     string
	apiURL     string
	model      string
	httpClient *http.Client
}

// NewDiscoveryAdvisor creates a DiscoveryAdvisor.
// Returns nil if apiKey is empty — callers must nil-check before use.
func NewDiscoveryAdvisor(apiKey string) *DiscoveryAdvisor {
	if apiKey == "" {
		return nil
	}
	return &DiscoveryAdvisor{
		apiKey:     apiKey,
		apiURL:     apiURL,
		model:      advisorModel,
		httpClient: &http.Client{Timeout: 90 * time.Second},
	}
}

// Suggest asks Claude to suggest additional hostnames based on fingerprinted assets.
// rootDomain scopes the suggestions to the target domain.
// Returns up to advisorMaxSugg deduplicated hostnames that are subdomains of rootDomain.
func (a *DiscoveryAdvisor) Suggest(ctx context.Context, rootDomain string, hints []AssetHint) ([]string, error) {
	if len(hints) == 0 {
		return nil, nil
	}

	prompt := buildAdvisorPrompt(rootDomain, hints)

	text, err := a.callAdvisor(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return parseAdvisorResponse(ctx, text, rootDomain), nil
}

// buildAdvisorPrompt constructs the minimal prompt for the advisor.
func buildAdvisorPrompt(rootDomain string, hints []AssetHint) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf(
		"You are a network discovery assistant. The target domain is %q.\n\n",
		rootDomain,
	))

	b.WriteString("## Already discovered and scanned assets\n\n")
	for _, h := range hints {
		b.WriteString(fmt.Sprintf("  hostname=%q  status=%d  server=%q  title=%q",
			h.Hostname, h.StatusCode, h.Server, h.Title))
		if len(h.CNAMEChain) > 0 {
			b.WriteString(fmt.Sprintf("  cname=%v", h.CNAMEChain))
		}
		if len(h.TechStack) > 0 {
			b.WriteString(fmt.Sprintf("  tech=%v", h.TechStack))
		}
		if len(h.OpenPorts) > 0 {
			b.WriteString(fmt.Sprintf("  ports=%v", h.OpenPorts))
		}
		if len(h.KeyFindings) > 0 {
			b.WriteString(fmt.Sprintf("  findings=%v", h.KeyFindings))
		}
		b.WriteString("\n")
	}

	b.WriteString(fmt.Sprintf(`
## Task

Based on the naming patterns, tech stack, and infrastructure above, suggest up to %d additional
hostnames that likely exist for this target but were NOT discovered by passive DNS.

Focus on:
- Environment patterns: if you see "api" → suggest "api-staging", "api-v2", "api-internal"
- Service patterns: if you see a payments service → suggest "checkout", "billing", "invoices"
- Admin patterns: "admin", "dashboard", "portal", "console", "staff"
- Developer patterns: "jenkins", "gitlab", "grafana", "prometheus" (only if infra signals suggest them)
- Cloud patterns: based on CNAME targets (e.g. ELB → suggest load-balancer-named variants)

Rules:
- Only suggest subdomains of %q
- Do NOT suggest hostnames already in the discovered list above
- Return a JSON array of strings ONLY, no explanation text
- If no confident suggestions, return an empty array []

Example output: ["api-v2.example.com", "admin.example.com", "staging-api.example.com"]
`, advisorMaxSugg, rootDomain))

	return b.String()
}

// parseAdvisorResponse extracts valid subdomains from Claude's JSON array response.
func parseAdvisorResponse(ctx context.Context, text, rootDomain string) []string {
	// Extract JSON array from response (Claude may wrap it in markdown fences).
	start := strings.Index(text, "[")
	end := strings.LastIndex(text, "]")
	if start == -1 || end <= start {
		return nil
	}

	var candidates []string
	if err := json.Unmarshal([]byte(text[start:end+1]), &candidates); err != nil {
		return nil
	}

	suffix := "." + rootDomain
	seen := make(map[string]bool)
	var result []string

	for _, h := range candidates {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		// Only accept subdomains of rootDomain.
		if h != rootDomain && !strings.HasSuffix(h, suffix) {
			continue
		}
		// SSRF guard: reject if the hostname resolves to a private, loopback,
		// or link-local address. A crafted AI suggestion like
		// "169.254.169.254.example.com" could pass the suffix check above but
		// resolve to the cloud metadata IP if the attacker controls DNS.
		if resolveToPrivate(ctx, h) {
			continue
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		result = append(result, h)

		if len(result) >= advisorMaxSugg {
			break
		}
	}

	return result
}

// resolveToPrivate returns true if hostname resolves to any RFC 1918, loopback,
// or link-local address. Used to guard against SSRF via AI-suggested hostnames.
func resolveToPrivate(ctx context.Context, hostname string) bool {
	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil {
		return false // can't resolve — not a private IP risk
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		// RFC 1918 private ranges
		private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
		for _, cidr := range private {
			_, network, _ := net.ParseCIDR(cidr)
			if network != nil && network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// callAdvisor sends the prompt to Claude using Haiku for speed/cost.
func (a *DiscoveryAdvisor) callAdvisor(ctx context.Context, prompt string) (string, error) {
	body, err := json.Marshal(claudeRequest{
		Model:     a.model,
		MaxTokens: advisorMaxTokens,
		Messages:  []claudeMessage{{Role: "user", Content: prompt}},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.apiURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", apiVersion)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Claude API HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var cr claudeResponse
	if err := json.Unmarshal(data, &cr); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("API error: %s", cr.Error.Message)
	}
	if len(cr.Content) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return cr.Content[0].Text, nil
}

// QuickFingerprint runs lightweight HEAD probes on a list of hostnames concurrently
// and returns AssetHints. Assets that don't resolve or respond get a zero StatusCode.
// This is intentionally much cheaper than classify.Collect — it's only used to give
// the advisor enough signal to suggest patterns.
func QuickFingerprint(ctx context.Context, hostnames []string) []AssetHint {
	type result struct {
		idx  int
		hint AssetHint
	}

	results := make(chan result, len(hostnames))
	sem := make(chan struct{}, 20) // max 20 concurrent probes

	for i, h := range hostnames {
		i, h := i, h
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			results <- result{idx: i, hint: probeHint(ctx, h)}
		}()
	}

	hints := make([]AssetHint, len(hostnames))
	for range hostnames {
		r := <-results
		hints[r.idx] = r.hint
	}

	return hints
}

// probeHint does a lightweight HTTP HEAD probe for the advisor.
func probeHint(ctx context.Context, hostname string) AssetHint {
	hint := AssetHint{Hostname: hostname}

	// DNS CNAME chain.
	hint.CNAMEChain = resolveCNAME(ctx, hostname)

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, scheme+"://"+hostname, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		hint.StatusCode = resp.StatusCode
		hint.Server = resp.Header.Get("Server")
		hint.Title = resp.Header.Get("X-Powered-By") // quick tech signal
		return hint
	}

	return hint
}

// resolveCNAME follows the CNAME chain for a hostname, returning the chain up to 5 hops.
func resolveCNAME(ctx context.Context, hostname string) []string {
	var chain []string
	current := hostname
	for i := 0; i < 5; i++ {
		cname, err := net.DefaultResolver.LookupCNAME(ctx, current)
		if err != nil || cname == current || cname == current+"." {
			break
		}
		cname = strings.TrimSuffix(cname, ".")
		chain = append(chain, cname)
		current = cname
	}
	return chain
}

// ProbeAliveBatch probes multiple hostnames concurrently and returns the live ones.
// When httpxBin is non-empty and the binary exists, delegates to httpx for faster
// batch probing. Falls back to sequential ProbeAlive calls when httpx is unavailable.
func ProbeAliveBatch(ctx context.Context, hostnames []string, httpxBin string) []string {
	if len(hostnames) == 0 {
		return nil
	}

	// Try httpx when a bin path is provided and the binary actually exists.
	if httpxBin != "" {
		if _, err := exec.LookPath(httpxBin); err == nil {
			if results := probeAliveBatchHTTPX(ctx, hostnames, httpxBin); results != nil {
				return results
			}
		}
	}

	// Fallback: concurrent ProbeAlive with a 20-goroutine semaphore.
	type result struct {
		hostname string
		alive    bool
	}
	results := make(chan result, len(hostnames))
	sem := make(chan struct{}, 20)

	for _, h := range hostnames {
		h := h
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			results <- result{hostname: h, alive: ProbeAlive(ctx, h)}
		}()
	}

	var live []string
	for range hostnames {
		r := <-results
		if r.alive {
			live = append(live, r.hostname)
		}
	}
	return live
}

// probeAliveBatchHTTPX runs httpx to batch-probe hostnames and returns live ones.
// Returns nil on any execution error so the caller can fall back.
func probeAliveBatchHTTPX(ctx context.Context, hostnames []string, httpxBin string) []string {
	input := strings.Join(hostnames, "\n")

	cmd := exec.CommandContext(ctx, httpxBin,
		"-silent", "-no-color", "-timeout", "5", "-threads", "50",
	)
	cmd.Stdin = strings.NewReader(input)

	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var live []string

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// httpx outputs full URLs like https://api.example.com — extract hostname.
		// Strip scheme prefix.
		host := line
		if idx := strings.Index(host, "://"); idx != -1 {
			host = host[idx+3:]
		}
		// Strip any trailing path, port, or slash.
		if idx := strings.IndexAny(host, "/:"); idx != -1 {
			host = host[:idx]
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			live = append(live, host)
		}
	}
	return live
}

// ProbeAlive returns true if the hostname resolves and serves HTTP on port 80 or 443.
func ProbeAlive(ctx context.Context, hostname string) bool {
	// DNS check first.
	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil || len(addrs) == 0 {
		return false
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, scheme+"://"+hostname, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		return true
	}

	return false
}
