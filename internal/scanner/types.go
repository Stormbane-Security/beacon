package scanner

import (
	"context"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

// Scanner is implemented by every individual scan module (nuclei, email, subdomain, testssl).
// Scanners are pure functions: they receive a target and return findings.
// They never touch the database or know about visibility/pricing.
//
// This is a type alias for scan.Scanner — the canonical definition lives in
// internal/scan to avoid import cycles between scanner packages and the registry.
type Scanner = scan.Scanner

// OriginScanner is an optional extension of Scanner for scanners that can
// target a specific IP directly rather than resolving the asset via DNS.
// Used by the vhost scanner to probe a known origin IP behind a CDN instead
// of the shared CDN edge IP that asset's DNS would normally return.
type OriginScanner interface {
	Scanner
	RunWithOriginIP(ctx context.Context, asset, originIP string, scanType module.ScanType) ([]finding.Finding, error)
}
