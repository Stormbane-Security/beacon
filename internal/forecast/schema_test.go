package forecast

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/asset"
	"github.com/stormbane-security/beacon/internal/finding"
)

func TestNewScanReport_Version(t *testing.T) {
	r := NewScanReport()
	if r.Version != CurrentSchemaVersion {
		t.Errorf("NewScanReport().Version = %q, want %q", r.Version, CurrentSchemaVersion)
	}
}

func TestFindingFromBeacon_Surface(t *testing.T) {
	bf := finding.Finding{
		CheckID:      "tls.cert_expiry_7d",
		Module:       "surface",
		Scanner:      "tls",
		Severity:     finding.SeverityHigh,
		Title:        "Certificate Expires in 7 Days",
		Description:  "The TLS certificate expires soon.",
		Asset:        "api.example.com",
		ProofCommand: "echo | openssl s_client -connect api.example.com:443 2>/dev/null | openssl x509 -noout -dates",
		DeepOnly:     false,
		DiscoveredAt: time.Now(),
		Evidence: map[string]any{
			"expiry_date": "2026-04-07",
		},
		DuplicateOf:         "tls.cert_expiry_7d|*.example.com|Certificate Expires in 7 Days",
		DuplicateConfidence: 0.9,
	}

	ff := FindingFromBeacon(bf)

	if ff.CheckID != "tls.cert_expiry_7d" {
		t.Errorf("CheckID = %q", ff.CheckID)
	}
	if ff.Severity != "high" {
		t.Errorf("Severity = %q, want 'high'", ff.Severity)
	}
	if ff.ScanMode != "surface" {
		t.Errorf("ScanMode = %q, want 'surface'", ff.ScanMode)
	}
	if ff.DeepOnly {
		t.Error("DeepOnly should be false")
	}
	if ff.DuplicateOf == "" {
		t.Error("DuplicateOf should be preserved")
	}
	if ff.DuplicateConfidence != 0.9 {
		t.Errorf("DuplicateConfidence = %v, want 0.9", ff.DuplicateConfidence)
	}
	if ff.Evidence["expiry_date"] != "2026-04-07" {
		t.Error("Evidence not preserved")
	}
}

func TestFindingFromBeacon_Deep(t *testing.T) {
	bf := finding.Finding{
		CheckID:      "web.cors_misconfiguration",
		Module:       "surface",
		Scanner:      "cors",
		Severity:     finding.SeverityHigh,
		Title:        "CORS Misconfiguration",
		Asset:        "api.example.com",
		DeepOnly:     true,
		DiscoveredAt: time.Now(),
	}

	ff := FindingFromBeacon(bf)

	if ff.ScanMode != "deep" {
		t.Errorf("ScanMode = %q, want 'deep'", ff.ScanMode)
	}
	if !ff.DeepOnly {
		t.Error("DeepOnly should be true")
	}
}

func TestScanReport_JSON_Roundtrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	report := &ScanReport{
		Version: CurrentSchemaVersion,
		Scan: ScanMeta{
			RunID:         "run-123",
			Domain:        "example.com",
			Targets:       []string{"example.com", "api.example.com"},
			Mode:          "surface",
			Modules:       []string{"surface", "cloud"},
			StartedAt:     now,
			CompletedAt:   now.Add(5 * time.Minute),
			DurationMs:    300000,
			BeaconVersion: "0.15.0",
			TotalFindings: 42,
			TotalAssets:   15,
		},
		Findings: []Finding{
			{
				CheckID:     "tls.cert_expiry_7d",
				Module:      "surface",
				Scanner:     "tls",
				Severity:    "high",
				Title:       "Certificate Expires in 7 Days",
				Description: "The TLS certificate expires soon.",
				Asset:       "api.example.com",
				ScanMode:    "surface",
				ComplianceTags: []string{"SOC2-CC6.1", "PCI-4.2.1"},
				DeltaStatus:    "new",
				DiscoveredAt:   now,
			},
			{
				CheckID:             "nuclei.misconfigured_cors",
				Module:              "surface",
				Scanner:             "nuclei",
				Severity:            "medium",
				Title:               "CORS Misconfigured",
				Asset:               "api.example.com",
				ScanMode:            "deep",
				DuplicateOf:         "web.cors_misconfiguration|api.example.com|CORS Misconfiguration",
				DuplicateConfidence: 0.95,
				DiscoveredAt:        now,
			},
		},
		Assets: AssetSnapshot{
			Assets: []asset.Asset{
				{
					ID:       "domain:example.com",
					Type:     asset.AssetTypeDomain,
					Provider: "web",
					Name:     "example.com",
				},
				{
					ID:       "subdomain:api.example.com",
					Type:     asset.AssetTypeSubdomain,
					Provider: "web",
					Name:     "api.example.com",
				},
			},
			Relationships: []asset.Relationship{
				{
					FromID:     "subdomain:api.example.com",
					ToID:       "domain:example.com",
					Type:       asset.RelBelongsTo,
					Confidence: 1.0,
				},
			},
		},
		ScannerMetrics: []ScannerMetric{
			{
				ScannerName:      "tls",
				Asset:            "api.example.com",
				DurationMs:       1500,
				FindingsHigh:     1,
			},
		},
		DiscoverySources: []DiscoverySource{
			{Asset: "api.example.com", Source: "subdomain"},
		},
	}

	// Marshal
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Unmarshal
	var decoded ScanReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify key fields survive roundtrip
	if decoded.Version != CurrentSchemaVersion {
		t.Errorf("Version = %q", decoded.Version)
	}
	if decoded.Scan.RunID != "run-123" {
		t.Errorf("Scan.RunID = %q", decoded.Scan.RunID)
	}
	if decoded.Scan.Domain != "example.com" {
		t.Errorf("Scan.Domain = %q", decoded.Scan.Domain)
	}
	if len(decoded.Scan.Targets) != 2 {
		t.Errorf("Scan.Targets = %v", decoded.Scan.Targets)
	}
	if len(decoded.Findings) != 2 {
		t.Errorf("len(Findings) = %d", len(decoded.Findings))
	}
	if decoded.Findings[0].CheckID != "tls.cert_expiry_7d" {
		t.Errorf("Findings[0].CheckID = %q", decoded.Findings[0].CheckID)
	}
	if decoded.Findings[0].DeltaStatus != "new" {
		t.Errorf("Findings[0].DeltaStatus = %q", decoded.Findings[0].DeltaStatus)
	}
	if len(decoded.Findings[0].ComplianceTags) != 2 {
		t.Errorf("Findings[0].ComplianceTags = %v", decoded.Findings[0].ComplianceTags)
	}
	if decoded.Findings[1].DuplicateOf == "" {
		t.Error("Findings[1].DuplicateOf should be set")
	}
	if decoded.Findings[1].DuplicateConfidence != 0.95 {
		t.Errorf("Findings[1].DuplicateConfidence = %v", decoded.Findings[1].DuplicateConfidence)
	}
	if len(decoded.Assets.Assets) != 2 {
		t.Errorf("len(Assets.Assets) = %d", len(decoded.Assets.Assets))
	}
	if len(decoded.Assets.Relationships) != 1 {
		t.Errorf("len(Assets.Relationships) = %d", len(decoded.Assets.Relationships))
	}
	if decoded.Assets.Relationships[0].Type != asset.RelBelongsTo {
		t.Errorf("Relationships[0].Type = %q", decoded.Assets.Relationships[0].Type)
	}
	if len(decoded.ScannerMetrics) != 1 {
		t.Errorf("len(ScannerMetrics) = %d", len(decoded.ScannerMetrics))
	}
	if len(decoded.DiscoverySources) != 1 {
		t.Errorf("len(DiscoverySources) = %d", len(decoded.DiscoverySources))
	}
}

func TestScanReport_EmptyOptionalFields(t *testing.T) {
	// A minimal scan report should marshal without errors.
	report := &ScanReport{
		Version: CurrentSchemaVersion,
		Scan: ScanMeta{
			RunID:     "run-456",
			Domain:    "minimal.com",
			Mode:      "surface",
			StartedAt: time.Now().UTC(),
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal minimal report: %v", err)
	}

	var decoded ScanReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal minimal report: %v", err)
	}

	if decoded.Scan.RunID != "run-456" {
		t.Errorf("RunID = %q", decoded.Scan.RunID)
	}
	if decoded.Findings != nil {
		t.Errorf("Findings should be nil, got %v", decoded.Findings)
	}
	if decoded.ScannerMetrics != nil {
		t.Errorf("ScannerMetrics should be nil, got %v", decoded.ScannerMetrics)
	}
}

func TestFinding_DuplicateFields_OmittedWhenEmpty(t *testing.T) {
	f := Finding{
		CheckID:  "tls.cert_expiry_7d",
		Severity: "high",
		Title:    "Cert Expiry",
		Asset:    "example.com",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)
	if contains(s, "duplicate_of") {
		t.Error("duplicate_of should be omitted when empty")
	}
	if contains(s, "duplicate_confidence") {
		t.Error("duplicate_confidence should be omitted when zero")
	}
	if contains(s, "delta_status") {
		t.Error("delta_status should be omitted when empty")
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && jsonContains(s, substr)
}

func jsonContains(s, key string) bool {
	// Check if the JSON key appears in the serialized string.
	return len(s) > 0 && len(key) > 0 && stringContains(s, "\""+key+"\"")
}

func stringContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
