package module

import (
	"context"

	"github.com/stormbane/beacon/internal/finding"
)

// InputType declares what kind of input a module requires.
type InputType string

const (
	InputDomain     InputType = "domain"
	InputGitHub     InputType = "github"
	InputIaC        InputType = "iac"
	InputCloud      InputType = "cloud"
	InputKubernetes InputType = "kubernetes"
)

// ScanType controls depth: surface is passive-only, deep adds active probing.
type ScanType string

const (
	ScanSurface ScanType = "surface"
	ScanDeep    ScanType = "deep"
	// ScanAuthorized enables active exploitation probes — payload injection,
	// real session creation, file upload, state mutation. Requires --authorized
	// and interactive legal acknowledgment in addition to --deep and --permission-confirmed.
	ScanAuthorized ScanType = "authorized"
)

// crawlFeedKeyType is an unexported type used as a context key to prevent
// collisions with keys from other packages.
type crawlFeedKeyType struct{}

// CrawlFeedKey is the context key under which the surface module places a
// per-asset chan string that the crawler sends discovered URLs into.
// DLP and other scanners can read from this channel to process pages in
// real time without waiting for the full crawl to complete.
// The channel is closed by the crawler (or by the module as a safety net)
// when the crawl finishes.
var CrawlFeedKey = crawlFeedKeyType{}

// Module is the interface every scan module must implement.
type Module interface {
	// Name returns the stable module identifier (e.g., "surface", "github").
	Name() string

	// RequiredInputs returns the input types this module needs populated.
	RequiredInputs() []InputType

	// Run executes the module against the given input and returns findings.
	// Scanners within a module run concurrently. The module is responsible
	// for respecting ctx cancellation and scan type constraints.
	Run(ctx context.Context, input Input, scanType ScanType) ([]finding.Finding, error)
}
