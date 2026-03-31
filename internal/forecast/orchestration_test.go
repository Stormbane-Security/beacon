package forecast

import (
	"encoding/json"
	"testing"
	"time"
)

func TestScanRequest_JSON_Roundtrip(t *testing.T) {
	deadline := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	complianceDeadline := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	changeTime := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)

	req := ScanRequest{
		RequestID: "req-001",
		ProjectID: "proj-abc",
		Priority:  PriorityCritical,
		Reason:    "Critical finding drift detected on api.example.com",
		Targets: []ScanTarget{
			{
				Asset:            "api.example.com",
				Type:             "subdomain",
				PreviousFindings: []string{"tls.cert_expiry_7d", "web.cors_misconfiguration"},
				ExpectedTech:     []string{"nginx", "django"},
			},
			{
				Asset: "db.example.com",
				Type:  "subdomain",
			},
		},
		Mode:        "deep",
		Modules:     []string{"surface"},
		FocusChecks: []string{"tls.cert_expiry_7d"},
		Deadline:    &deadline,
		CallbackURL: "https://forecast.internal/v1/scan-results",
		Context: &ScanContext{
			KnownAssets:         []string{"api.example.com", "www.example.com", "db.example.com"},
			ComplianceDeadline:  &complianceDeadline,
			ComplianceFramework: "SOC2",
			RecentChanges: []Change{
				{
					Type:        ChangeConfigDrift,
					Asset:       "api.example.com",
					Description: "TLS certificate renewed but HSTS max-age reduced",
					DetectedAt:  changeTime,
				},
			},
		},
	}

	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ScanRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.RequestID != "req-001" {
		t.Errorf("RequestID = %q", decoded.RequestID)
	}
	if decoded.Priority != PriorityCritical {
		t.Errorf("Priority = %q", decoded.Priority)
	}
	if len(decoded.Targets) != 2 {
		t.Fatalf("len(Targets) = %d", len(decoded.Targets))
	}
	if decoded.Targets[0].Asset != "api.example.com" {
		t.Errorf("Targets[0].Asset = %q", decoded.Targets[0].Asset)
	}
	if len(decoded.Targets[0].PreviousFindings) != 2 {
		t.Errorf("Targets[0].PreviousFindings = %v", decoded.Targets[0].PreviousFindings)
	}
	if len(decoded.Targets[0].ExpectedTech) != 2 {
		t.Errorf("Targets[0].ExpectedTech = %v", decoded.Targets[0].ExpectedTech)
	}
	if decoded.Mode != "deep" {
		t.Errorf("Mode = %q", decoded.Mode)
	}
	if len(decoded.FocusChecks) != 1 {
		t.Errorf("FocusChecks = %v", decoded.FocusChecks)
	}
	if decoded.Deadline == nil {
		t.Error("Deadline should be set")
	}
	if decoded.Context == nil {
		t.Fatal("Context should be set")
	}
	if len(decoded.Context.KnownAssets) != 3 {
		t.Errorf("Context.KnownAssets = %v", decoded.Context.KnownAssets)
	}
	if decoded.Context.ComplianceFramework != "SOC2" {
		t.Errorf("Context.ComplianceFramework = %q", decoded.Context.ComplianceFramework)
	}
	if len(decoded.Context.RecentChanges) != 1 {
		t.Fatalf("Context.RecentChanges = %v", decoded.Context.RecentChanges)
	}
	if decoded.Context.RecentChanges[0].Type != ChangeConfigDrift {
		t.Errorf("RecentChanges[0].Type = %q", decoded.Context.RecentChanges[0].Type)
	}
}

func TestScanRequest_Minimal(t *testing.T) {
	req := ScanRequest{
		RequestID: "req-min",
		ProjectID: "proj-xyz",
		Priority:  PriorityNormal,
		Reason:    "Scheduled weekly scan",
		Targets: []ScanTarget{
			{Asset: "example.com"},
		},
		Mode: "surface",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	s := string(data)
	// Optional fields should be omitted.
	if stringContains(s, "\"deadline\"") {
		t.Error("deadline should be omitted when nil")
	}
	if stringContains(s, "\"context\"") {
		t.Error("context should be omitted when nil")
	}
	if stringContains(s, "\"focus_checks\"") {
		t.Error("focus_checks should be omitted when nil")
	}
}

func TestScanAcknowledgment_Accepted(t *testing.T) {
	est := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	ack := ScanAcknowledgment{
		RequestID:             "req-001",
		Status:                AckAccepted,
		ScanRunID:             "run-789",
		EstimatedCompletionAt: &est,
	}

	data, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ScanAcknowledgment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Status != AckAccepted {
		t.Errorf("Status = %q", decoded.Status)
	}
	if decoded.ScanRunID != "run-789" {
		t.Errorf("ScanRunID = %q", decoded.ScanRunID)
	}
}

func TestScanAcknowledgment_Rejected(t *testing.T) {
	ack := ScanAcknowledgment{
		RequestID: "req-002",
		Status:    AckRejected,
		Reason:    "deep mode requires --permission-confirmed which is not configured",
	}

	data, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ScanAcknowledgment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Status != AckRejected {
		t.Errorf("Status = %q", decoded.Status)
	}
	if decoded.Reason == "" {
		t.Error("Reason should be set")
	}
	if decoded.ScanRunID != "" {
		t.Error("ScanRunID should be empty for rejected")
	}
}

func TestChangeTypes(t *testing.T) {
	// Verify all change types are distinct and non-empty.
	types := []ChangeType{
		ChangeNewAsset,
		ChangeConfigDrift,
		ChangeFindingResolved,
		ChangeFindingNew,
		ChangeCertExpiry,
		ChangeDependencyUpdate,
		ChangeOwnershipChange,
	}

	seen := make(map[ChangeType]bool)
	for _, ct := range types {
		if ct == "" {
			t.Error("change type should not be empty")
		}
		if seen[ct] {
			t.Errorf("duplicate change type: %q", ct)
		}
		seen[ct] = true
	}
}

func TestPriorityValues(t *testing.T) {
	priorities := []ScanPriority{PriorityCritical, PriorityHigh, PriorityNormal, PriorityLow}
	seen := make(map[ScanPriority]bool)
	for _, p := range priorities {
		if p == "" {
			t.Error("priority should not be empty")
		}
		if seen[p] {
			t.Errorf("duplicate priority: %q", p)
		}
		seen[p] = true
	}
}
