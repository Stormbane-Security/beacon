package report

// RenderOCSF returns scan findings as NDJSON (newline-delimited JSON) where each
// line is a standalone OCSF 1.3.0 Vulnerability Finding event (class_uid 5001).
//
// OCSF (Open Cybersecurity Schema Framework) is the standard schema used by
// AWS Security Lake, Splunk Enterprise Security, Microsoft Sentinel, OpenSearch
// Security Analytics, Panther, Chronicle, and most modern SIEMs. NDJSON output
// makes it trivial to pipe findings into any of these platforms:
//
//	beacon scan --domain example.com --format ocsf | aws s3 cp - s3://security-lake-bucket/beacon/
//	beacon scan --domain example.com --format ocsf | curl -H "Content-Type: application/x-ndjson" --data-binary @- http://splunk:8088/services/collector
//
// Each event contains:
//   - finding_info: check ID (uid), title, description, created_time, src_url (proof command)
//   - vulnerabilities[]: CVE ID (parsed from title/desc), title, severity
//   - resource: affected asset (name, uid, type)
//   - remediation: step-by-step fix (from AI enrichment when available)
//   - unmapped: beacon-specific fields (scanner, module, evidence, compliance_tags)
//
// Feeding this into an intelligence brain / LLM pipeline: each OCSF event is
// self-contained and machine-readable. A downstream LLM can consume the stream
// to build a live attack surface model, correlate cross-asset findings via
// cross_asset_note, and generate prioritized remediation plans from compliance_tags.

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/store"
)

// ocsfVersion is the OCSF schema version this output conforms to.
const ocsfVersion = "1.3.0"

// cvePattern matches CVE identifiers in text (e.g. "CVE-2023-3519").
var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// ocsfEvent is the OCSF 1.3.0 Vulnerability Finding event (class_uid 5001).
// Fields follow the OCSF spec: https://schema.ocsf.io/1.3.0/classes/vulnerability_finding
type ocsfEvent struct {
	ClassUID     int    `json:"class_uid"`
	ClassName    string `json:"class_name"`
	CategoryUID  int    `json:"category_uid"`
	CategoryName string `json:"category_name"`
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name"`
	SeverityID   int    `json:"severity_id"`
	Severity     string `json:"severity"`
	StatusID     int    `json:"status_id"`
	Status       string `json:"status"`
	Time         int64  `json:"time"` // Unix milliseconds
	Message      string `json:"message"`

	Metadata    ocsfMetadata    `json:"metadata"`
	FindingInfo ocsfFindingInfo `json:"finding_info"`

	Vulnerabilities []ocsfVulnerability `json:"vulnerabilities,omitempty"`
	Resource        ocsfResource        `json:"resource"`
	Remediation     *ocsfRemediation    `json:"remediation,omitempty"`
	Evidences       []ocsfEvidence      `json:"evidences,omitempty"`

	// Unmapped carries Beacon-specific fields not present in the OCSF schema.
	// SIEMs that support OCSF extensions will preserve these; others will ignore them.
	Unmapped map[string]any `json:"unmapped,omitempty"`
}

type ocsfMetadata struct {
	Version    string      `json:"version"`
	Product    ocsfProduct `json:"product"`
	UID        string      `json:"uid"`         // check_id
	LoggedTime int64       `json:"logged_time"` // Unix milliseconds
}

type ocsfProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
}

type ocsfFindingInfo struct {
	UID         string `json:"uid"`          // check_id
	Title       string `json:"title"`
	Desc        string `json:"desc"`
	CreatedTime int64  `json:"created_time"` // Unix milliseconds
	SrcURL      string `json:"src_url"`      // proof command or verification URL
}

type ocsfVulnerability struct {
	CVE      *ocsfCVE `json:"cve,omitempty"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
}

type ocsfCVE struct {
	UID string `json:"uid"` // "CVE-YYYY-NNNNN"
}

type ocsfResource struct {
	Type string `json:"type"`
	Name string `json:"name"` // asset hostname or identifier
	UID  string `json:"uid"`
}

type ocsfRemediation struct {
	Desc string `json:"desc"`
}

type ocsfEvidence struct {
	Data any `json:"data"`
}

// ocsfSeverity maps a Beacon severity to OCSF severity_id and severity string.
// OCSF severity_id values: 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical, 99=Other
func ocsfSeverity(s finding.Severity) (int, string) {
	switch s {
	case finding.SeverityCritical:
		return 5, "Critical"
	case finding.SeverityHigh:
		return 4, "High"
	case finding.SeverityMedium:
		return 3, "Medium"
	case finding.SeverityLow:
		return 2, "Low"
	default:
		return 1, "Informational"
	}
}

// ocsfFindingTypes infers the OCSF finding type from a Beacon check ID.
// Used to classify resources in the OCSF event.
func ocsfResourceType(checkID string) string {
	switch {
	case strings.HasPrefix(checkID, "port."):
		return "Network"
	case strings.HasPrefix(checkID, "tls."):
		return "Web Server"
	case strings.HasPrefix(checkID, "email."):
		return "DNS"
	case strings.HasPrefix(checkID, "iam."):
		return "Cloud Account"
	case strings.HasPrefix(checkID, "cloud."):
		return "Cloud Resource"
	case strings.HasPrefix(checkID, "secret."), strings.HasPrefix(checkID, "dlp."):
		return "Data Store"
	default:
		return "Web Server"
	}
}

// extractCVEs parses all CVE identifiers from a text string.
func extractCVEs(text string) []string {
	matches := cvePattern.FindAllString(text, -1)
	seen := make(map[string]bool)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// toOCSFEvent converts one enriched finding to an OCSF 1.3.0 Vulnerability
// Finding event (class_uid 5001, category_uid 5 "Discovery").
func toOCSFEvent(ef enrichment.EnrichedFinding, now int64) ocsfEvent {
	f := ef.Finding
	ts := f.DiscoveredAt.UnixMilli()
	if ts <= 0 {
		ts = now
	}
	sevID, sevStr := ocsfSeverity(f.Severity)

	// Combine title and description to search for CVE IDs.
	combined := f.Title + " " + f.Description
	cves := extractCVEs(combined)

	var vulns []ocsfVulnerability
	if len(cves) > 0 {
		for _, cid := range cves {
			vulns = append(vulns, ocsfVulnerability{
				CVE:      &ocsfCVE{UID: cid},
				Title:    f.Title,
				Severity: sevStr,
			})
		}
	} else if strings.HasPrefix(string(f.CheckID), "cve.") {
		// check_id starts with "cve." but we couldn't parse the ID from text.
		vulns = append(vulns, ocsfVulnerability{
			Title:    f.Title,
			Severity: sevStr,
		})
	}

	// Build resource entry from asset.
	resource := ocsfResource{
		Type: ocsfResourceType(string(f.CheckID)),
		Name: f.Asset,
		UID:  f.Asset,
	}

	// src_url: use proof command as the verification source.
	srcURL := f.ProofCommand

	// Remediation from AI enrichment when available.
	var remediation *ocsfRemediation
	if ef.Remediation != "" {
		remediation = &ocsfRemediation{Desc: ef.Remediation}
	}

	// Evidence as structured data.
	var evidences []ocsfEvidence
	if len(f.Evidence) > 0 {
		evidences = append(evidences, ocsfEvidence{Data: f.Evidence})
	}

	// Unmapped: Beacon-specific fields that don't fit OCSF.
	unmapped := map[string]any{
		"check_id": string(f.CheckID),
		"module":   f.Module,
		"scanner":  f.Scanner,
	}
	if ef.Impact != "" {
		unmapped["impact"] = ef.Impact
	}
	if ef.MitigatedBy != "" {
		unmapped["mitigated_by"] = ef.MitigatedBy
	}
	if ef.CrossAssetNote != "" {
		unmapped["cross_asset_note"] = ef.CrossAssetNote
	}
	if len(ef.ComplianceTags) > 0 {
		unmapped["compliance_tags"] = ef.ComplianceTags
	}
	if ef.TerraformFix != "" {
		unmapped["terraform_fix"] = ef.TerraformFix
	}
	if ef.DeltaStatus != "" {
		unmapped["delta_status"] = ef.DeltaStatus
	}

	return ocsfEvent{
		ClassUID:     5001,
		ClassName:    "Vulnerability Finding",
		CategoryUID:  5,
		CategoryName: "Discovery",
		ActivityID:   1,
		ActivityName: "Create",
		SeverityID:   sevID,
		Severity:     sevStr,
		StatusID:     1,
		Status:       "New",
		Time:         ts,
		Message:      f.Title,
		Metadata: ocsfMetadata{
			Version: ocsfVersion,
			Product: ocsfProduct{
				Name:       "Beacon",
				VendorName: "Stormbane",
			},
			UID:        string(f.CheckID),
			LoggedTime: now,
		},
		FindingInfo: ocsfFindingInfo{
			UID:         string(f.CheckID),
			Title:       f.Title,
			Desc:        f.Description,
			CreatedTime: ts,
			SrcURL:      srcURL,
		},
		Vulnerabilities: vulns,
		Resource:        resource,
		Remediation:     remediation,
		Evidences:       evidences,
		Unmapped:        unmapped,
	}
}

// RenderOCSF returns scan findings as NDJSON where each line is a valid
// OCSF 1.3.0 Vulnerability Finding event (class_uid 5001). The output can be
// piped directly into any OCSF-compatible SIEM or security data lake.
//
// The first line is always a scan metadata event (class_uid 5001) describing
// the scan run itself so consumers can correlate all finding events back to
// a single scan execution.
func RenderOCSF(run store.ScanRun, enriched []enrichment.EnrichedFinding) (string, error) {
	now := time.Now().UnixMilli()
	var sb strings.Builder

	// Emit a scan-start envelope event so consumers can correlate all findings
	// back to a single scan execution.
	type scanEnvelope struct {
		ClassUID     int            `json:"class_uid"`
		ClassName    string         `json:"class_name"`
		CategoryUID  int            `json:"category_uid"`
		CategoryName string         `json:"category_name"`
		ActivityID   int            `json:"activity_id"`
		ActivityName string         `json:"activity_name"`
		SeverityID   int            `json:"severity_id"`
		Severity     string         `json:"severity"`
		Time         int64          `json:"time"`
		Message      string         `json:"message"`
		Metadata     ocsfMetadata   `json:"metadata"`
		Unmapped     map[string]any `json:"unmapped"`
	}
	startTime := run.StartedAt.UnixMilli()
	var endTime int64
	if run.CompletedAt != nil {
		endTime = run.CompletedAt.UnixMilli()
	}
	envelope := scanEnvelope{
		ClassUID:     5001,
		ClassName:    "Vulnerability Finding",
		CategoryUID:  5,
		CategoryName: "Discovery",
		ActivityID:   1,
		ActivityName: "Create",
		SeverityID:   1,
		Severity:     "Informational",
		Time:         startTime,
		Message:      "Beacon scan completed for " + run.Domain,
		Metadata: ocsfMetadata{
			Version: ocsfVersion,
			Product: ocsfProduct{
				Name:       "Beacon",
				VendorName: "Stormbane",
			},
			UID:        "beacon.scan",
			LoggedTime: now,
		},
		Unmapped: map[string]any{
			"domain":        run.Domain,
			"scan_type":     string(run.ScanType),
			"modules":       run.Modules,
			"started_at":    run.StartedAt.Format(time.RFC3339),
			"completed_at":  endTime,
			"finding_count": len(enriched),
		},
	}
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	sb.Write(envelopeBytes)
	sb.WriteByte('\n')

	// Emit one OCSF Vulnerability Finding event per enriched finding.
	for _, ef := range enriched {
		if ef.Omit {
			continue
		}
		evt := toOCSFEvent(ef, now)
		b, err := json.Marshal(evt)
		if err != nil {
			return "", err
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}

	return sb.String(), nil
}
