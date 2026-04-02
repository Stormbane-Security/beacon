package portscan

import (
	"context"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

// findingMaker creates a finding with common fields pre-populated.
// buildFindings passes this into each probe so probes don't need to know
// about the asset, module name, or timestamp.
type findingMaker func(
	checkID finding.CheckID,
	severity finding.Severity,
	title, description string,
	evidence map[string]any,
) finding.Finding

// ProbeCategory classifies how a probe detects a service. Used for
// pre-filtering so we don't waste time running HTTP probes against a
// service that sent a Redis banner.
type ProbeCategory int

const (
	// ProbeCatBanner identifies services by examining the passive banner only.
	ProbeCatBanner ProbeCategory = iota
	// ProbeCatProtocol sends protocol-specific bytes and checks the response.
	ProbeCatProtocol
	// ProbeCatHTTP makes HTTP requests (GET/POST to known paths).
	ProbeCatHTTP
	// ProbeCatTLS inspects TLS certificates, ALPN, or probes inside a TLS tunnel.
	ProbeCatTLS
)

// ServiceProbe defines a single service detection probe. Each probe knows
// how to identify one service regardless of which port it's running on.
type ServiceProbe struct {
	// Name is a human-readable identifier (e.g. "redis", "clickhouse").
	Name string

	// Category controls pre-filtering. An HTTP probe won't run against a
	// port that sent a Redis banner, and vice versa.
	Category ProbeCategory

	// DefaultPorts lists the well-known ports for this service. Used for
	// port list construction — these ports are always scanned during
	// discovery even when the target doesn't specify a port.
	DefaultPorts []int

	// Detect runs the probe against host:port and returns any findings.
	// banner is the passive banner read on connect (may be empty).
	// makeF creates findings with common fields pre-populated.
	// Returns nil if the service is not detected.
	Detect func(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding
}

// probeRegistry holds all registered service probes. buildFindings iterates
// this list for every open port.
var probeRegistry []ServiceProbe

// registerProbe adds a probe to the global registry. Called from init()
// functions in probe implementation files.
func registerProbe(p ServiceProbe) {
	probeRegistry = append(probeRegistry, p)
}

// bannerProtocol returns a short protocol label when the banner clearly
// identifies a well-known service. Returns "" when unrecognised.
// This lets runProbes skip protocol probes (e.g. Redis) when the port
// already announced itself as a different service (e.g. SMTP).
func bannerProtocol(banner string) string {
	if banner == "" {
		return ""
	}
	upper := strings.ToUpper(banner)
	switch {
	case strings.HasPrefix(upper, "220 ") && strings.Contains(upper, "SMTP"):
		return "smtp"
	case strings.HasPrefix(upper, "+OK"):
		return "pop3"
	case strings.HasPrefix(upper, "* OK") && strings.Contains(upper, "IMAP"):
		return "imap"
	case strings.HasPrefix(banner, "SSH-"):
		return "ssh"
	case strings.HasPrefix(banner, "+REDIS") || strings.HasPrefix(banner, "-ERR") || strings.HasPrefix(banner, "$"):
		return "redis"
	case strings.HasPrefix(upper, "220 ") && strings.Contains(upper, "FTP"):
		return "ftp"
	case strings.Contains(upper, "MYSQL") || (len(banner) > 4 && banner[0] < 32):
		// MySQL protocol greeting starts with a length-encoded packet
		return "mysql"
	}
	return ""
}

// runProbes iterates all registered probes against an open port and returns
// the combined findings. Pre-filters by category to avoid pointless work.
func runProbes(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	bannerHTTP := looksLikeHTTP(banner)
	hasBanner := banner != ""
	bannerProto := bannerProtocol(banner)

	var findings []finding.Finding
	for _, probe := range probeRegistry {
		if hasBanner {
			// Skip HTTP probes when the banner is clearly non-HTTP.
			if probe.Category == ProbeCatHTTP && !bannerHTTP {
				continue
			}
			// Skip protocol probes when the banner is clearly HTTP.
			if probe.Category == ProbeCatProtocol && bannerHTTP {
				continue
			}
			// Skip protocol probes when the banner identifies a different
			// protocol (e.g. don't try Redis probe on an SMTP port).
			if probe.Category == ProbeCatProtocol && bannerProto != "" && bannerProto != probe.Name {
				continue
			}
		}

		if fs := probe.Detect(ctx, host, port, banner, makeF); len(fs) > 0 {
			findings = append(findings, fs...)
		}
	}
	return findings
}
