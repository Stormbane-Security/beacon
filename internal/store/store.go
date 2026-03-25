// Package store defines the storage interface for scan data.
// The SQLite implementation is used by the CLI. The same interface
// will be satisfied by a Postgres implementation when the SaaS layer is added.
package store

import (
	"context"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/playbook"
)

// ScanStatus tracks the lifecycle of a scan run.
type ScanStatus string

const (
	StatusPending   ScanStatus = "pending"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
	StatusStopped   ScanStatus = "stopped" // user-initiated graceful stop via q
)

// Target is a domain or asset that has been scanned.
type Target struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	CreatedAt time.Time `json:"created_at"`
}

// ScanRun records a single scan execution.
type ScanRun struct {
	ID          string            `json:"id"`
	TargetID    string            `json:"target_id"`
	Domain      string            `json:"domain"` // denormalized for convenience
	ScanType    module.ScanType   `json:"scan_type"`
	Modules     []string          `json:"modules"`
	Status      ScanStatus        `json:"status"`
	StartedAt   time.Time         `json:"started_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	FindingCount int              `json:"finding_count"`
	Error       string            `json:"error,omitempty"`
	DiscoveryDurationMs int64            `json:"discovery_duration_ms,omitempty"`
	ScanDurationMs      int64            `json:"scan_duration_ms,omitempty"`
	AssetCount          int              `json:"asset_count,omitempty"`
	DiscoverySources    map[string]int   `json:"discovery_sources,omitempty"` // source → unique asset count
}

// Report is the final deliverable for a scan run.
type Report struct {
	ID          string    `json:"id"`
	ScanRunID   string    `json:"scan_run_id"`
	Domain      string    `json:"domain"`
	HTMLContent string    `json:"html_content"`
	Summary     string    `json:"summary"`
	EmailedTo   string    `json:"emailed_to,omitempty"`
	EmailedAt   *time.Time `json:"emailed_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// AssetExecution records what was attempted and found for a single asset
// during a scan. Used by the batch analysis job to compute hit rates,
// detect near-misses, and improve playbooks over time.
type AssetExecution struct {
	ID               string    `json:"id"`
	ScanRunID        string    `json:"scan_run_id"`
	Asset            string    `json:"asset"`            // hostname
	Evidence         playbook.Evidence `json:"evidence"` // what we observed
	MatchedPlaybooks []string  `json:"matched_playbooks"` // playbook names that matched
	ScannersRun      []string  `json:"scanners_run"`      // scanner names from RunPlan
	NucleiTagsRun     []string  `json:"nuclei_tags_run"`      // Nuclei tags from RunPlan
	DirbustPathsRun   []string  `json:"dirbust_paths_run"`    // paths attempted in deep dirbust
	DirbustPathsFound []string  `json:"dirbust_paths_found"`  // paths that returned interesting responses
	FindingsCount     int       `json:"findings_count"`
	ClassifyDurationMs int64  `json:"classify_duration_ms,omitempty"`
	ExpandedFrom       string `json:"expanded_from,omitempty"` // parent asset if playbook/AI-expanded
	CreatedAt         time.Time `json:"created_at"`
}

// UnmatchedAsset records an asset for which no targeted playbook matched.
// The fingerprint deduplicates similar-looking assets across scans.
type UnmatchedAsset struct {
	ID          string    `json:"id"`
	ScanRunID   string    `json:"scan_run_id"`
	Fingerprint string    `json:"fingerprint"` // hash of key evidence fields
	Asset       string    `json:"asset"`
	Evidence    playbook.Evidence `json:"evidence"`
	CreatedAt   time.Time `json:"created_at"`
}

// CorrelationFinding is an AI-generated cross-asset attack chain finding.
// Unlike scanner findings (single asset), correlations span multiple assets
// and represent compound risks only visible when the full domain picture is considered.
type CorrelationFinding struct {
	ID                 string           `json:"id"`
	ScanRunID          string           `json:"scan_run_id"`
	Domain             string           `json:"domain"`
	Title              string           `json:"title"`
	Severity           finding.Severity `json:"severity"`
	Description        string           `json:"description"`   // the attack chain narrative
	AffectedAssets     []string         `json:"affected_assets"`
	ContributingChecks []string         `json:"contributing_checks"` // CheckIDs that triggered this
	Remediation        string           `json:"remediation"`
	CreatedAt          time.Time        `json:"created_at"`
}

// PlaybookSuggestion is an AI-generated playbook improvement or new playbook.
type PlaybookSuggestion struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"`            // "new" | "improve" | "remove_check"
	TargetPlaybook string    `json:"target_playbook"` // existing name or proposed name
	SuggestedYAML  string    `json:"suggested_yaml"`
	Reasoning      string    `json:"reasoning"`
	PRURL          string    `json:"pr_url,omitempty"`
	Status         string    `json:"status"` // pending | pr_opened | merged | dismissed
	SuggestionKind  string   `json:"suggestion_kind,omitempty"`  // "playbook" | "code_pr" | "scanner_config" | "scan_schedule"
	CodeSnippet     string   `json:"code_snippet,omitempty"`     // Go code for code_pr type
	Priority        string   `json:"priority,omitempty"`         // "high" | "medium" | "low"
	AffectedDomains []string `json:"affected_domains,omitempty"` // domains this applies to
	CreatedAt      time.Time `json:"created_at"`
}

// DiscoveryAudit records which discovery source found each asset.
// Accumulated across scans to measure source effectiveness per domain.
type DiscoveryAudit struct {
	ID        string    `json:"id"`
	ScanRunID string    `json:"scan_run_id"`
	Asset     string    `json:"asset"`
	Source    string    `json:"source"` // "subdomain", "passivedns", "ai_advisor", "playbook", "root"
	CreatedAt time.Time `json:"created_at"`
}

// DiscoverySourceSummary aggregates how many unique assets each source found per domain.
type DiscoverySourceSummary struct {
	Source      string `json:"source"`
	AssetCount  int    `json:"asset_count"`
	UniqueCount int    `json:"unique_count"` // found by this source only
}

// SanitizedScannerMetric stores scanner performance data with all identifying
// information removed — no domain names, hostnames, or IP addresses.
// Used for cross-domain learning: comparing scanner effectiveness across
// different customers/domains without exposing any PII.
// Fields retained: scanner name, tech category, playbook matched,
// timing, severity counts, error flag.
type SanitizedScannerMetric struct {
	ID               string    `json:"id"`
	ScannerName      string    `json:"scanner_name"`
	TechCategory     string    `json:"tech_category"`  // e.g. "nginx", "Cloudflare", "web", "host"
	PlaybookName     string    `json:"playbook_name"`  // matched playbook (or "none")
	DurationMs       int64     `json:"duration_ms"`
	FindingsCritical int       `json:"findings_critical"`
	FindingsHigh     int       `json:"findings_high"`
	FindingsMedium   int       `json:"findings_medium"`
	FindingsLow      int       `json:"findings_low"`
	FindingsInfo     int       `json:"findings_info"`
	ErrorCount       int       `json:"error_count"`
	Skipped          bool      `json:"skipped"`
	CreatedAt        time.Time `json:"created_at"`
}

// FingerprintRule defines a data-driven pattern for technology fingerprinting.
// Rules map observed HTTP signals to structured Evidence fields.
// They are applied after the deterministic fingerprintTech() pass to fill gaps.
type FingerprintRule struct {
	ID          int64     `json:"id"`
	SignalType  string    `json:"signal_type"`  // "header", "body", "path", "cookie", "cname", "title", "dns_suffix", "asn_org"
	SignalKey   string    `json:"signal_key"`   // header name (for type=header); empty for others
	SignalValue string    `json:"signal_value"` // case-insensitive substring to match
	Field       string    `json:"field"`        // "framework", "proxy_type", "auth_system", "backend_services", "cloud_provider", "infra_layer"
	Value       string    `json:"value"`        // the value to assign when matched
	Source      string    `json:"source"`       // "builtin", "ai", "user"
	Status      string    `json:"status"`       // "active", "pending", "rejected"
	Confidence  float64   `json:"confidence"`   // 0.0–1.0, AI-estimated confidence
	SeenCount   int       `json:"seen_count"`   // incremented each time pattern is observed
	CreatedAt   time.Time `json:"created_at"`
}

// CrossDomainScannerSummary aggregates sanitized scanner metrics across all
// domains and scans. Used in analyze prompts to surface cross-customer patterns.
type CrossDomainScannerSummary struct {
	ScannerName      string  `json:"scanner_name"`
	TechCategory     string  `json:"tech_category"`
	RunCount         int     `json:"run_count"`
	AvgDurationMs    int64   `json:"avg_duration_ms"`
	TotalFindings    int     `json:"total_findings"`
	CriticalFindings int     `json:"critical_findings"`
	HighFindings     int     `json:"high_findings"`
	ErrorRate        float64 `json:"error_rate"`
	SkipRate         float64 `json:"skip_rate"`
	FindingsPerMin   float64 `json:"findings_per_min"`
}

// SuppressionStatus indicates why a finding was suppressed.
type SuppressionStatus string

const (
	SuppressionAcceptedRisk SuppressionStatus = "accepted_risk"
	SuppressionFalsePositive SuppressionStatus = "false_positive"
	SuppressionWontFix       SuppressionStatus = "wont_fix"
)

// ScannerMetric records timing and output statistics for a single scanner run
// on a single asset. Accumulated over many scans, these let the analyze job
// compute ROI per scanner (findings per minute), detect scanners that always
// error on certain asset types, and produce cost-vs-value recommendations.
type ScannerMetric struct {
	ID               string    `json:"id"`
	ScanRunID        string    `json:"scan_run_id"`
	Asset            string    `json:"asset"`
	ScannerName      string    `json:"scanner_name"`
	DurationMs       int64     `json:"duration_ms"`
	FindingsCritical int       `json:"findings_critical"`
	FindingsHigh     int       `json:"findings_high"`
	FindingsMedium   int       `json:"findings_medium"`
	FindingsLow      int       `json:"findings_low"`
	FindingsInfo     int       `json:"findings_info"`
	ErrorCount       int       `json:"error_count"`
	ErrorMessage     string    `json:"error_message,omitempty"` // first error string, if any
	Skipped          bool      `json:"skipped"`
	SkipReason       string    `json:"skip_reason,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// ScannerROISummary aggregates scanner metrics across all runs for a domain,
// providing per-scanner ROI analysis for the AI batch job.
type ScannerROISummary struct {
	ScannerName      string  `json:"scanner_name"`
	RunCount         int     `json:"run_count"`
	AvgDurationMs    int64   `json:"avg_duration_ms"`
	TotalFindings    int     `json:"total_findings"`
	CriticalFindings int     `json:"critical_findings"`
	HighFindings     int     `json:"high_findings"`
	ErrorRate        float64 `json:"error_rate"`   // 0.0–1.0
	SkipRate         float64 `json:"skip_rate"`    // 0.0–1.0
	FindingsPerMin   float64 `json:"findings_per_min"`
}

// FindingSuppression marks a specific check on a specific asset as suppressed.
// Suppressions are keyed by (domain, check_id, asset) — suppressing
// "email.spf_missing" on "example.com" only affects that domain+check combination.
type FindingSuppression struct {
	ID        string            `json:"id"`
	Domain    string            `json:"domain"`
	CheckID   finding.CheckID   `json:"check_id"`
	Asset     string            `json:"asset"`    // hostname the finding was on; empty = all assets
	Status    SuppressionStatus `json:"status"`   // accepted_risk | false_positive | wont_fix
	Note      string            `json:"note"`     // optional free-text reason
	CreatedAt time.Time         `json:"created_at"`
}

// Store is the storage interface. All methods accept a context for cancellation.
type Store interface {
	// Targets
	UpsertTarget(ctx context.Context, domain string) (*Target, error)
	GetTarget(ctx context.Context, domain string) (*Target, error)
	ListTargets(ctx context.Context) ([]Target, error)

	// Scan runs
	CreateScanRun(ctx context.Context, run *ScanRun) error
	UpdateScanRun(ctx context.Context, run *ScanRun) error
	GetScanRun(ctx context.Context, id string) (*ScanRun, error)
	ListScanRuns(ctx context.Context, domain string) ([]ScanRun, error)
	// DeleteScanRun removes a scan run and all associated data (findings, reports, asset
	// executions, scanner metrics, discovery audit, correlation findings).
	DeleteScanRun(ctx context.Context, id string) error
	// PurgeOrphanedRuns deletes all scan runs whose status is not completed and whose
	// started_at is older than the given threshold. Used to clean up runs that were
	// killed without a graceful shutdown.
	PurgeOrphanedRuns(ctx context.Context, olderThan time.Time) (int, error)

	// Raw findings
	SaveFindings(ctx context.Context, scanRunID string, findings []finding.Finding) error
	GetFindings(ctx context.Context, scanRunID string) ([]finding.Finding, error)

	// Enriched findings
	SaveEnrichedFindings(ctx context.Context, scanRunID string, enriched []enrichment.EnrichedFinding) error
	GetEnrichedFindings(ctx context.Context, scanRunID string) ([]enrichment.EnrichedFinding, error)
	// GetPreviousEnrichedFindings returns enriched findings from the most recently
	// completed scan for the given domain before the current scan run.
	// Returns nil, nil if no previous scan exists.
	GetPreviousEnrichedFindings(ctx context.Context, domain, currentScanRunID string) ([]enrichment.EnrichedFinding, error)

	// Reports
	SaveReport(ctx context.Context, report *Report) error
	GetReport(ctx context.Context, scanRunID string) (*Report, error)

	// Asset executions — scan audit log for AI analysis
	SaveAssetExecution(ctx context.Context, exec *AssetExecution) error
	ListAssetExecutions(ctx context.Context, scanRunID string) ([]AssetExecution, error)

	// Unmatched assets — feed for batch analysis job
	SaveUnmatchedAsset(ctx context.Context, u *UnmatchedAsset) error
	// FingerprintExists returns true if an unmatched asset with this fingerprint
	// already exists — prevents queuing duplicate analysis work.
	FingerprintExists(ctx context.Context, fingerprint string) (bool, error)
	ListUnmatchedAssets(ctx context.Context) ([]UnmatchedAsset, error)

	// Playbook suggestions — output of batch analysis job
	SavePlaybookSuggestion(ctx context.Context, s *PlaybookSuggestion) error
	ListPlaybookSuggestions(ctx context.Context, status string) ([]PlaybookSuggestion, error)
	UpdatePlaybookSuggestion(ctx context.Context, s *PlaybookSuggestion) error

	// Correlation findings — cross-asset attack chains from batch analysis
	SaveCorrelationFindings(ctx context.Context, findings []CorrelationFinding) error
	ListCorrelationFindings(ctx context.Context, domain string) ([]CorrelationFinding, error)

	// ListRecentScanRuns returns the N most recently completed scan runs across all domains.
	ListRecentScanRuns(ctx context.Context, limit int) ([]ScanRun, error)

	// Enrichment cache — avoid re-calling Claude for known check types
	GetEnrichmentCache(ctx context.Context, checkID finding.CheckID) (explanation, impact, remediation string, found bool)
	SaveEnrichmentCache(ctx context.Context, checkID finding.CheckID, explanation, impact, remediation string) error

	// Finding suppressions — false-positive / accepted-risk management
	UpsertSuppression(ctx context.Context, s *FindingSuppression) error
	ListSuppressions(ctx context.Context, domain string) ([]FindingSuppression, error)
	DeleteSuppression(ctx context.Context, id string) error

	// Scanner metrics — per-scanner timing and findings for ROI analysis
	SaveScannerMetric(ctx context.Context, m *ScannerMetric) error
	ListScannerMetrics(ctx context.Context, scanRunID string) ([]ScannerMetric, error)
	// GetScannerROI returns aggregated per-scanner statistics across all completed
	// scan runs for a domain. Used by the AI batch job to recommend optimizations.
	GetScannerROI(ctx context.Context, domain string) ([]ScannerROISummary, error)

	// Discovery audit — track which source found each asset
	SaveDiscoveryAudit(ctx context.Context, audits []DiscoveryAudit) error
	GetDiscoverySourceSummary(ctx context.Context, domain string) ([]DiscoverySourceSummary, error)
	// GetDiscoverySourcesByRun returns the per-asset discovery source for a specific scan run.
	GetDiscoverySourcesByRun(ctx context.Context, scanRunID string) (map[string]string, error)
	// GetFalsePositivePatterns returns check IDs that are frequently enriched as "no actionable value"
	GetFalsePositivePatterns(ctx context.Context, domain string) ([]string, error)

	// Sanitized cross-domain metrics — PII-free scanner performance data for
	// cross-customer learning. Domain names, hostnames, and IPs are never stored.
	SaveSanitizedMetrics(ctx context.Context, metrics []SanitizedScannerMetric) error
	// GetCrossDomainScannerSummary aggregates sanitized metrics across all scans
	// and domains, grouped by (scanner_name, tech_category).
	GetCrossDomainScannerSummary(ctx context.Context) ([]CrossDomainScannerSummary, error)

	// Fingerprint rules — data-driven tech detection patterns
	GetFingerprintRules(ctx context.Context, status string) ([]FingerprintRule, error) // status="" means all active
	UpsertFingerprintRule(ctx context.Context, r *FingerprintRule) error
	DeleteFingerprintRule(ctx context.Context, id int64) error
	IncrementFingerprintRuleSeen(ctx context.Context, id int64) error

	// Lifecycle
	Close() error
}
