package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/store"
)

// findingItem is the wire representation sent to the web UI.
// Severity is a string ("critical", "high", etc.) to avoid clients
// having to know the int→string mapping.
type findingItem struct {
	CheckID        string   `json:"check_id"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	Asset          string   `json:"asset"`
	Description    string   `json:"description"`
	ProofCommand   string   `json:"proof_command"`
	Scanner        string   `json:"scanner"`
	Explanation    string   `json:"explanation,omitempty"`
	Impact         string   `json:"impact,omitempty"`
	Remediation    string   `json:"remediation,omitempty"`
	ComplianceTags []string `json:"compliance_tags"`
}

func enrichedToItem(ef enrichment.EnrichedFinding) findingItem {
	f := ef.Finding
	tags := ef.ComplianceTags
	if len(tags) == 0 {
		tags = finding.ComplianceTags(f.CheckID)
	}
	if tags == nil {
		tags = []string{}
	}
	return findingItem{
		CheckID:        string(f.CheckID),
		Title:          f.Title,
		Severity:       f.Severity.String(),
		Asset:          f.Asset,
		Description:    f.Description,
		ProofCommand:   f.ProofCommand,
		Scanner:        f.Scanner,
		Explanation:    ef.Explanation,
		Impact:         ef.Impact,
		Remediation:    ef.Remediation,
		ComplianceTags: tags,
	}
}

func rawToItem(f finding.Finding) findingItem {
	tags := finding.ComplianceTags(f.CheckID)
	if tags == nil {
		tags = []string{}
	}
	return findingItem{
		CheckID:        string(f.CheckID),
		Title:          f.Title,
		Severity:       f.Severity.String(),
		Asset:          f.Asset,
		Description:    f.Description,
		ProofCommand:   f.ProofCommand,
		Scanner:        f.Scanner,
		ComplianceTags: tags,
	}
}

// mostRecentCompleted returns the most recently completed scan run from
// a slice sorted newest-first, or nil if none are completed.
func mostRecentCompleted(runs []store.ScanRun) *store.ScanRun {
	for i := range runs {
		if runs[i].Status == store.StatusCompleted {
			return &runs[i]
		}
	}
	return nil
}

// ── GET /v1/dashboard ────────────────────────────────────────────────────────

type dashboardResponse struct {
	Targets       int              `json:"targets"`
	TotalFindings int              `json:"total_findings"`
	Critical      int              `json:"critical"`
	High          int              `json:"high"`
	Medium        int              `json:"medium"`
	Low           int              `json:"low"`
	Info          int              `json:"info"`
	RecentScans   []scanListItem   `json:"recent_scans"`
}

type scanListItem struct {
	ID           string  `json:"id"`
	Domain       string  `json:"domain"`
	ScanType     string  `json:"scan_type"`
	Status       string  `json:"status"`
	FindingCount int     `json:"finding_count"`
	StartedAt    string  `json:"started_at"`
	CompletedAt  *string `json:"completed_at,omitempty"`
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	targets, err := s.st.ListTargets(ctx)
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}

	recent, err := s.st.ListRecentScanRuns(ctx, 20)
	if err != nil {
		recent = nil
	}

	// Build severity totals from the most recent completed run overall.
	var crit, high, med, low, info, total int
	if len(recent) > 0 {
		for i := range recent {
			if recent[i].Status == store.StatusCompleted {
				efs, err := s.st.GetEnrichedFindings(ctx, recent[i].ID)
				if err == nil && len(efs) > 0 {
					for _, ef := range efs {
						total++
						switch ef.Finding.Severity {
						case finding.SeverityCritical:
							crit++
						case finding.SeverityHigh:
							high++
						case finding.SeverityMedium:
							med++
						case finding.SeverityLow:
							low++
						default:
							info++
						}
					}
				} else {
					// Fall back to raw findings
					raws, err := s.st.GetFindings(ctx, recent[i].ID)
					if err == nil {
						for _, f := range raws {
							total++
							switch f.Severity {
							case finding.SeverityCritical:
								crit++
							case finding.SeverityHigh:
								high++
							case finding.SeverityMedium:
								med++
							case finding.SeverityLow:
								low++
							default:
								info++
							}
						}
					}
				}
				break // only the single most recent completed run
			}
		}
	}

	// Build recent scan list (limit 10 for the dashboard table).
	limit := 10
	if len(recent) < limit {
		limit = len(recent)
	}
	items := make([]scanListItem, limit)
	for i, run := range recent[:limit] {
		item := scanListItem{
			ID:           run.ID,
			Domain:       run.Domain,
			ScanType:     string(run.ScanType),
			Status:       string(run.Status),
			FindingCount: run.FindingCount,
			StartedAt:    run.StartedAt.Format("2006-01-02T15:04:05Z"),
		}
		if run.CompletedAt != nil {
			s := run.CompletedAt.Format("2006-01-02T15:04:05Z")
			item.CompletedAt = &s
		}
		items[i] = item
	}

	jsonOK(w, http.StatusOK, dashboardResponse{
		Targets:       len(targets),
		TotalFindings: total,
		Critical:      crit,
		High:          high,
		Medium:        med,
		Low:           low,
		Info:          info,
		RecentScans:   items,
	})
}

// ── GET /v1/targets/{domain}/findings ───────────────────────────────────────

func (s *Server) handleDomainFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	domain := r.PathValue("domain")
	if domain == "" {
		jsonError(w, "domain required", http.StatusBadRequest)
		return
	}

	runs, err := s.st.ListScanRuns(ctx, domain)
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}

	run := mostRecentCompleted(runs)
	if run == nil {
		// No completed scan; return empty.
		jsonOK(w, http.StatusOK, map[string]any{
			"domain":   domain,
			"scan_id":  "",
			"findings": []findingItem{},
		})
		return
	}

	items := loadFindingItems(s, r, run.ID)
	// Sort: critical → high → medium → low → info
	sort.Slice(items, func(i, j int) bool {
		return sevWeight(items[i].Severity) > sevWeight(items[j].Severity)
	})

	jsonOK(w, http.StatusOK, map[string]any{
		"domain":   domain,
		"scan_id":  run.ID,
		"findings": items,
	})
}

// ── GET /v1/targets/{domain}/trend ──────────────────────────────────────────

type trendPoint struct {
	Date      string `json:"date"`
	Total     int    `json:"total"`
	ScanType  string `json:"scan_type"`
	Status    string `json:"status"`
}

func (s *Server) handleDomainTrend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	domain := r.PathValue("domain")
	if domain == "" {
		jsonError(w, "domain required", http.StatusBadRequest)
		return
	}

	runs, err := s.st.ListScanRuns(ctx, domain)
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}

	// Runs come newest-first from ListScanRuns; reverse for chronological trend.
	for i, j := 0, len(runs)-1; i < j; i, j = i+1, j-1 {
		runs[i], runs[j] = runs[j], runs[i]
	}

	points := make([]trendPoint, 0, len(runs))
	for _, run := range runs {
		if run.Status != store.StatusCompleted && run.Status != store.StatusFailed {
			continue // skip pending/running
		}
		date := run.StartedAt.Format("2006-01-02")
		if run.CompletedAt != nil {
			date = run.CompletedAt.Format("2006-01-02")
		}
		points = append(points, trendPoint{
			Date:     date,
			Total:    run.FindingCount,
			ScanType: string(run.ScanType),
			Status:   string(run.Status),
		})
	}

	jsonOK(w, http.StatusOK, map[string]any{
		"domain": domain,
		"points": points,
	})
}

// ── GET /v1/targets/{domain}/compliance ─────────────────────────────────────

// complianceControl holds findings grouped under a single control ID.
type complianceControl map[string][]findingItem

// complianceFramework maps control IDs to their findings.
type complianceFramework map[string]complianceControl

func (s *Server) handleDomainCompliance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	domain := r.PathValue("domain")
	if domain == "" {
		jsonError(w, "domain required", http.StatusBadRequest)
		return
	}

	runs, err := s.st.ListScanRuns(ctx, domain)
	if err != nil {
		jsonError(w, "store error", http.StatusInternalServerError)
		return
	}

	run := mostRecentCompleted(runs)
	if run == nil {
		jsonOK(w, http.StatusOK, map[string]any{
			"domain":     domain,
			"scan_id":    "",
			"frameworks": map[string]any{},
		})
		return
	}

	items := loadFindingItems(s, r, run.ID)

	// Group findings by compliance framework → control → []finding
	frameworks := map[string]map[string][]findingItem{}
	for _, item := range items {
		for _, tag := range item.ComplianceTags {
			// Tag format: "PCI-4.2.1", "SOC2-CC6.7", "NIST-PR.DS", etc.
			// Framework = everything before the first dash.
			fw, ctrl, found := strings.Cut(tag, "-")
			if !found {
				fw = tag
				ctrl = tag
			}
			_ = ctrl
			if frameworks[fw] == nil {
				frameworks[fw] = map[string][]findingItem{}
			}
			frameworks[fw][tag] = append(frameworks[fw][tag], item)
		}
	}

	// Sort findings within each control by severity.
	for fw := range frameworks {
		for ctrl := range frameworks[fw] {
			items := frameworks[fw][ctrl]
			sort.Slice(items, func(i, j int) bool {
				return sevWeight(items[i].Severity) > sevWeight(items[j].Severity)
			})
			frameworks[fw][ctrl] = items
		}
	}

	jsonOK(w, http.StatusOK, map[string]any{
		"domain":     domain,
		"scan_id":    run.ID,
		"frameworks": frameworks,
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

// loadFindingItems loads enriched findings for a scan run (falling back to
// raw findings if the enrichment pass did not run).
func loadFindingItems(s *Server, r *http.Request, scanRunID string) []findingItem {
	ctx := r.Context()

	efs, err := s.st.GetEnrichedFindings(ctx, scanRunID)
	if err == nil && len(efs) > 0 {
		items := make([]findingItem, len(efs))
		for i, ef := range efs {
			items[i] = enrichedToItem(ef)
		}
		return items
	}

	// Fall back to raw findings.
	raws, err := s.st.GetFindings(ctx, scanRunID)
	if err != nil {
		return []findingItem{}
	}
	items := make([]findingItem, len(raws))
	for i, f := range raws {
		items[i] = rawToItem(f)
	}
	return items
}

func sevWeight(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
