package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/finding"
)

// ExecutiveSummary is a structured executive summary suitable for JSON
// serialization or rendering in any report format.
type ExecutiveSummary struct {
	// RiskScore is a 0-100 composite score based on finding severity counts.
	RiskScore int `json:"risk_score"`
	// RiskLevel is a human-readable label: Critical, High, Medium, Low, or Clean.
	RiskLevel string `json:"risk_level"`
	// TotalFindings is the count of actionable (non-omitted) findings.
	TotalFindings int `json:"total_findings"`
	// BySeverity breaks down findings by severity level.
	BySeverity map[string]int `json:"by_severity"`
	// ByCategory groups findings by their check namespace (e.g. "tls", "web", "email").
	ByCategory map[string]int `json:"by_category"`
	// TopFindings are the up-to-5 most critical findings with one-line descriptions.
	TopFindings []TopFinding `json:"top_findings"`
	// AttackChains is the number of chain/correlation findings discovered.
	AttackChains int `json:"attack_chains"`
	// Recommendations are the top actionable items ordered by priority.
	Recommendations []string `json:"recommendations"`
	// Narrative is a prose executive summary paragraph.
	Narrative string `json:"narrative"`
}

// TopFinding is a one-line summary of a high-priority finding.
type TopFinding struct {
	CheckID  string `json:"check_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Asset    string `json:"asset"`
}

// GenerateExecutiveSummary produces a structured executive summary from
// enriched findings. It filters omitted findings, computes severity
// distributions, identifies attack chains, and generates actionable
// recommendations.
func GenerateExecutiveSummary(enriched []enrichment.EnrichedFinding) ExecutiveSummary {
	// Filter omitted findings.
	var active []enrichment.EnrichedFinding
	for _, ef := range enriched {
		if !ef.Omit {
			active = append(active, ef)
		}
	}

	// Severity counts.
	bySev := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, ef := range active {
		switch ef.Finding.Severity {
		case finding.SeverityCritical:
			bySev["critical"]++
		case finding.SeverityHigh:
			bySev["high"]++
		case finding.SeverityMedium:
			bySev["medium"]++
		case finding.SeverityLow:
			bySev["low"]++
		default:
			bySev["info"]++
		}
	}

	// Category counts (namespace before first dot in check ID).
	byCat := make(map[string]int)
	for _, ef := range active {
		cat := categoryFromCheckID(ef.Finding.CheckID)
		byCat[cat]++
	}

	// Risk score: critical=25, high=10, medium=3, low=1, capped at 100.
	score := bySev["critical"]*25 + bySev["high"]*10 + bySev["medium"]*3 + bySev["low"]*1
	if score > 100 {
		score = 100
	}
	level := riskLevelFromScore(score)

	// Top findings: sort by severity descending, take up to 5.
	sorted := make([]enrichment.EnrichedFinding, len(active))
	copy(sorted, active)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Finding.Severity > sorted[j].Finding.Severity
	})
	var top []TopFinding
	for i, ef := range sorted {
		if i >= 5 {
			break
		}
		top = append(top, TopFinding{
			CheckID:  ef.Finding.CheckID,
			Severity: SeverityLabel(ef.Finding.Severity),
			Title:    ef.Finding.Title,
			Asset:    ef.Finding.Asset,
		})
	}

	// Attack chains.
	chainCount := 0
	for _, ef := range active {
		id := string(ef.Finding.CheckID)
		if strings.HasPrefix(id, "chain.") || strings.HasPrefix(id, "correlation.") {
			chainCount++
		}
	}

	// Recommendations.
	recs := generateRecommendations(active)

	// Narrative paragraph.
	narrative := buildNarrativeParagraph(len(active), bySev, chainCount, level)

	return ExecutiveSummary{
		RiskScore:       score,
		RiskLevel:       level,
		TotalFindings:   len(active),
		BySeverity:      bySev,
		ByCategory:      byCat,
		TopFindings:     top,
		AttackChains:    chainCount,
		Recommendations: recs,
		Narrative:       narrative,
	}
}

// categoryFromCheckID extracts the category namespace from a check ID.
// "tls.cert_expiry_7d" -> "tls", "chain.ssrf_to_cloud_creds" -> "chain".
func categoryFromCheckID(id string) string {
	if i := strings.Index(id, "."); i > 0 {
		return id[:i]
	}
	return "other"
}

func riskLevelFromScore(score int) string {
	switch {
	case score >= 75:
		return "Critical"
	case score >= 50:
		return "High"
	case score >= 25:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "Clean"
	}
}

func buildNarrativeParagraph(total int, bySev map[string]int, chains int, level string) string {
	if total == 0 {
		return "No actionable security findings were identified during this scan. The target's external attack surface appears well-maintained."
	}

	var parts []string
	parts = append(parts, fmt.Sprintf(
		"The scan identified %d security finding(s) with an overall risk level of %s.",
		total, level,
	))

	// Severity breakdown.
	var sevParts []string
	if n := bySev["critical"]; n > 0 {
		sevParts = append(sevParts, fmt.Sprintf("%d critical", n))
	}
	if n := bySev["high"]; n > 0 {
		sevParts = append(sevParts, fmt.Sprintf("%d high", n))
	}
	if n := bySev["medium"]; n > 0 {
		sevParts = append(sevParts, fmt.Sprintf("%d medium", n))
	}
	if n := bySev["low"]; n > 0 {
		sevParts = append(sevParts, fmt.Sprintf("%d low", n))
	}
	if len(sevParts) > 0 {
		parts = append(parts, fmt.Sprintf("Breakdown: %s.", strings.Join(sevParts, ", ")))
	}

	if chains > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d attack chain(s) were discovered where multiple vulnerabilities combine to create a more severe exploit path.",
			chains,
		))
	}

	if bySev["critical"] > 0 {
		parts = append(parts, "Immediate action is required to address critical findings before they can be exploited.")
	} else if bySev["high"] > 0 {
		parts = append(parts, "High-severity findings should be prioritized for remediation in the next development cycle.")
	}

	return strings.Join(parts, " ")
}
