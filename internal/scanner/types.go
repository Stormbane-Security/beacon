package scanner

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// Scanner is implemented by every individual scan module (nuclei, email, subdomain, testssl).
// Scanners are pure functions: they receive a target and return findings.
// They never touch the database or know about visibility/pricing.
type Scanner interface {
	// Name returns a stable identifier for this scanner (e.g. "nuclei", "email").
	Name() string

	// Run executes the scanner against the given asset (usually a domain or subdomain).
	// asset is the specific host being scanned (may differ from the root domain).
	// scanType controls whether active/deep checks are enabled.
	Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error)
}

// OriginScanner is an optional extension of Scanner for scanners that can
// target a specific IP directly rather than resolving the asset via DNS.
// Used by the vhost scanner to probe a known origin IP behind a CDN instead
// of the shared CDN edge IP that asset's DNS would normally return.
type OriginScanner interface {
	Scanner
	RunWithOriginIP(ctx context.Context, asset, originIP string, scanType module.ScanType) ([]finding.Finding, error)
}
