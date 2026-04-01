package forecast

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/asset"
)

// ── Drift Detection ──────────────────────────────────────────────────────

func TestDriftReport_JSON_Roundtrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first := now.Add(-7 * 24 * time.Hour)

	report := DriftReport{
		ProjectID:      "proj-001",
		Domain:         "example.com",
		BaselineScanID: "run-100",
		CurrentScanID:  "run-101",
		GeneratedAt:    now,
		Findings: FindingDrift{
			New: []DriftFinding{
				{
					CheckID:   "tls.cert_expiry_7d",
					Asset:     "api.example.com",
					Severity:  "high",
					Title:     "Certificate Expires in 7 Days",
					FirstSeen: now,
					ScanCount: 1,
				},
			},
			Resolved: []DriftFinding{
				{
					CheckID:   "web.cors_misconfiguration",
					Asset:     "api.example.com",
					Severity:  "high",
					Title:     "CORS Misconfiguration",
					FirstSeen: first,
					ScanCount: 3,
				},
			},
			Recurring: []DriftFinding{
				{
					CheckID:   "headers.missing_hsts",
					Asset:     "www.example.com",
					Severity:  "medium",
					Title:     "Missing HSTS Header",
					FirstSeen: first,
					ScanCount: 4,
				},
			},
			Regressed: []DriftFinding{
				{
					CheckID:   "tls.weak_cipher",
					Asset:     "mail.example.com",
					Severity:  "medium",
					Title:     "Weak Cipher Suite",
					FirstSeen: first,
					ScanCount: 2,
				},
			},
			SeverityShifts: []SeverityShift{
				{
					CheckID:      "port.ssh_exposed",
					Asset:        "db.example.com",
					PrevSeverity: "medium",
					CurrSeverity: "high",
					Reason:       "asset criticality upgraded to P0",
				},
			},
		},
		Assets: AssetDrift{
			Added: []DriftAsset{
				{ID: "subdomain:staging.example.com", Type: asset.AssetTypeSubdomain, Name: "staging.example.com", Provider: "web"},
			},
			Removed: []DriftAsset{
				{ID: "ip:10.0.0.5", Type: asset.AssetTypeIP, Name: "10.0.0.5", Provider: "dns"},
			},
			Changed: []AssetChange{
				{
					AssetID: "subdomain:api.example.com",
					FieldChanges: []FieldChange{
						{Field: "services", OldValue: "443/tcp", NewValue: "443/tcp,8080/tcp"},
					},
				},
			},
		},
		RiskDelta: 12.5,
		Summary:   "New TLS certificate expiry finding on api.example.com; CORS issue resolved.",
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded DriftReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ProjectID != "proj-001" {
		t.Errorf("ProjectID = %q", decoded.ProjectID)
	}
	if decoded.BaselineScanID != "run-100" {
		t.Errorf("BaselineScanID = %q", decoded.BaselineScanID)
	}
	if len(decoded.Findings.New) != 1 {
		t.Fatalf("len(New) = %d", len(decoded.Findings.New))
	}
	if decoded.Findings.New[0].CheckID != "tls.cert_expiry_7d" {
		t.Errorf("New[0].CheckID = %q", decoded.Findings.New[0].CheckID)
	}
	if decoded.Findings.New[0].ScanCount != 1 {
		t.Errorf("New[0].ScanCount = %d", decoded.Findings.New[0].ScanCount)
	}
	if len(decoded.Findings.Resolved) != 1 {
		t.Errorf("len(Resolved) = %d", len(decoded.Findings.Resolved))
	}
	if len(decoded.Findings.Recurring) != 1 {
		t.Errorf("len(Recurring) = %d", len(decoded.Findings.Recurring))
	}
	if len(decoded.Findings.Regressed) != 1 {
		t.Errorf("len(Regressed) = %d", len(decoded.Findings.Regressed))
	}
	if len(decoded.Findings.SeverityShifts) != 1 {
		t.Fatalf("len(SeverityShifts) = %d", len(decoded.Findings.SeverityShifts))
	}
	if decoded.Findings.SeverityShifts[0].PrevSeverity != "medium" {
		t.Errorf("SeverityShifts[0].PrevSeverity = %q", decoded.Findings.SeverityShifts[0].PrevSeverity)
	}
	if len(decoded.Assets.Added) != 1 {
		t.Errorf("len(Assets.Added) = %d", len(decoded.Assets.Added))
	}
	if len(decoded.Assets.Removed) != 1 {
		t.Errorf("len(Assets.Removed) = %d", len(decoded.Assets.Removed))
	}
	if len(decoded.Assets.Changed) != 1 {
		t.Fatalf("len(Assets.Changed) = %d", len(decoded.Assets.Changed))
	}
	if len(decoded.Assets.Changed[0].FieldChanges) != 1 {
		t.Errorf("len(FieldChanges) = %d", len(decoded.Assets.Changed[0].FieldChanges))
	}
	if decoded.RiskDelta != 12.5 {
		t.Errorf("RiskDelta = %f", decoded.RiskDelta)
	}
	if decoded.Summary == "" {
		t.Error("Summary should be set")
	}
}

func TestDriftReport_EmptyDrift(t *testing.T) {
	report := DriftReport{
		ProjectID:      "proj-001",
		Domain:         "stable.com",
		BaselineScanID: "run-50",
		CurrentScanID:  "run-51",
		GeneratedAt:    time.Now().UTC(),
		Findings:       FindingDrift{},
		Assets:         AssetDrift{},
		RiskDelta:      0,
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	s := string(data)
	// Empty slices should be omitted.
	for _, field := range []string{"new", "resolved", "recurring", "regressed", "severity_shifts", "added", "removed", "changed"} {
		if stringContains(s, "\""+field+"\"") {
			t.Errorf("JSON should omit %q when empty", field)
		}
	}
}

// ── Attack Path Analysis ─────────────────────────────────────────────────

func TestAttackPath_JSON_Roundtrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	path := AttackPath{
		ID:          "ap-001",
		ProjectID:   "proj-001",
		GeneratedAt: now,
		Severity:    "critical",
		Title:       "SSRF to Cloud Admin via IMDSv1",
		Description: "SSRF on api.example.com allows reading IMDSv1 metadata, which exposes an IAM role with admin privileges.",
		Steps: []AttackStep{
			{
				Order:      1,
				AssetID:    "subdomain:api.example.com",
				FindingID:  "f-001",
				CheckID:    "web.ssrf_internal",
				Technique:  "exploit SSRF to reach 169.254.169.254",
				Privilege:  PrivRead,
				Confidence: 0.95,
			},
			{
				Order:      2,
				AssetID:    "aws_ec2_instance:i-0abc123",
				CheckID:    "cloud.aws.imdsv1_enabled",
				Technique:  "read IAM credentials from IMDSv1",
				Privilege:  PrivExecute,
				Confidence: 0.90,
			},
			{
				Order:      3,
				AssetID:    "aws_iam_role:admin-role",
				CheckID:    "iam.overprivileged_role",
				Technique:  "assume admin IAM role",
				Privilege:  PrivCloudAdmin,
				Confidence: 0.85,
			},
		},
		EntryPoint:        "subdomain:api.example.com",
		Target:            "aws_iam_role:admin-role",
		TargetCriticality: asset.CriticalityP0,
		BlastRadius:       []string{"aws_s3_bucket:prod-data", "aws_ec2_instance:i-0abc123", "aws_iam_role:admin-role"},
		RiskScore:         92.5,
		Mitigations: []Mitigation{
			{
				Step:     2,
				Action:   "Enable IMDSv2 on all EC2 instances",
				Priority: MitigationCritical,
				Effort:   EffortTrivial,
			},
			{
				Step:     3,
				Action:   "Reduce IAM role permissions to least privilege",
				Priority: MitigationHigh,
				Effort:   EffortMedium,
			},
			{
				Step:     1,
				Action:   "Fix SSRF vulnerability in API endpoint",
				Priority: MitigationCritical,
				Effort:   EffortLow,
			},
		},
	}

	data, err := json.MarshalIndent(path, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded AttackPath
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != "ap-001" {
		t.Errorf("ID = %q", decoded.ID)
	}
	if decoded.Severity != "critical" {
		t.Errorf("Severity = %q", decoded.Severity)
	}
	if len(decoded.Steps) != 3 {
		t.Fatalf("len(Steps) = %d", len(decoded.Steps))
	}
	if decoded.Steps[0].Privilege != PrivRead {
		t.Errorf("Steps[0].Privilege = %q", decoded.Steps[0].Privilege)
	}
	if decoded.Steps[1].Privilege != PrivExecute {
		t.Errorf("Steps[1].Privilege = %q", decoded.Steps[1].Privilege)
	}
	if decoded.Steps[2].Privilege != PrivCloudAdmin {
		t.Errorf("Steps[2].Privilege = %q", decoded.Steps[2].Privilege)
	}
	if decoded.TargetCriticality != asset.CriticalityP0 {
		t.Errorf("TargetCriticality = %q", decoded.TargetCriticality)
	}
	if len(decoded.BlastRadius) != 3 {
		t.Errorf("len(BlastRadius) = %d", len(decoded.BlastRadius))
	}
	if decoded.RiskScore != 92.5 {
		t.Errorf("RiskScore = %f", decoded.RiskScore)
	}
	if len(decoded.Mitigations) != 3 {
		t.Fatalf("len(Mitigations) = %d", len(decoded.Mitigations))
	}
	if decoded.Mitigations[0].Priority != MitigationCritical {
		t.Errorf("Mitigations[0].Priority = %q", decoded.Mitigations[0].Priority)
	}
	if decoded.Mitigations[0].Effort != EffortTrivial {
		t.Errorf("Mitigations[0].Effort = %q", decoded.Mitigations[0].Effort)
	}
}

func TestPrivilegeLevel_Values(t *testing.T) {
	levels := []PrivilegeLevel{PrivNone, PrivRead, PrivWrite, PrivExecute, PrivAdmin, PrivRoot, PrivCloudAdmin}
	seen := make(map[PrivilegeLevel]bool)
	for _, p := range levels {
		if p == "" {
			t.Error("privilege level should not be empty")
		}
		if seen[p] {
			t.Errorf("duplicate privilege level: %q", p)
		}
		seen[p] = true
	}
}

func TestMitigationPriority_Values(t *testing.T) {
	priorities := []MitigationPriority{MitigationCritical, MitigationHigh, MitigationMedium, MitigationLow}
	seen := make(map[MitigationPriority]bool)
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

func TestMitigationEffort_Values(t *testing.T) {
	efforts := []MitigationEffort{EffortTrivial, EffortLow, EffortMedium, EffortHigh}
	seen := make(map[MitigationEffort]bool)
	for _, e := range efforts {
		if e == "" {
			t.Error("effort should not be empty")
		}
		if seen[e] {
			t.Errorf("duplicate effort: %q", e)
		}
		seen[e] = true
	}
}

// ── Ownership Mapping ────────────────────────────────────────────────────

func TestOwnershipMap_JSON_Roundtrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	om := OwnershipMap{
		ProjectID:   "proj-001",
		GeneratedAt: now,
		Owners: []ResolvedOwner{
			{
				Identity:   "@platform-team",
				Type:       asset.OwnerCodeowners,
				Assets:     []string{"subdomain:api.example.com", "subdomain:auth.example.com"},
				Confidence: 0.95,
				Sources:    []string{"CODEOWNERS", "cloud_tag"},
				FindingCounts: SeverityCounts{
					Critical: 1,
					High:     3,
					Medium:   5,
					Low:      2,
					Info:     0,
				},
			},
			{
				Identity:   "sa-api@project.iam.gserviceaccount.com",
				Type:       asset.OwnerIAMBinding,
				Assets:     []string{"gcp_compute_instance:api-prod-1"},
				Confidence: 1.0,
				Sources:    []string{"gcp_iam_policy"},
				FindingCounts: SeverityCounts{
					High: 1,
				},
			},
		},
		UnownedAssets: []string{"ip:10.0.0.99", "subdomain:legacy.example.com"},
		ConflictingOwnership: []OwnershipConflict{
			{
				AssetID: "subdomain:shared.example.com",
				Candidates: []OwnerCandidate{
					{Identity: "@platform-team", Type: asset.OwnerCodeowners, Source: "CODEOWNERS", Confidence: 0.8},
					{Identity: "@frontend-team", Type: asset.OwnerCommitFreq, Source: "git_log_90d", Confidence: 0.7},
				},
			},
		},
	}

	data, err := json.MarshalIndent(om, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded OwnershipMap
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ProjectID != "proj-001" {
		t.Errorf("ProjectID = %q", decoded.ProjectID)
	}
	if len(decoded.Owners) != 2 {
		t.Fatalf("len(Owners) = %d", len(decoded.Owners))
	}
	if decoded.Owners[0].Identity != "@platform-team" {
		t.Errorf("Owners[0].Identity = %q", decoded.Owners[0].Identity)
	}
	if len(decoded.Owners[0].Assets) != 2 {
		t.Errorf("len(Owners[0].Assets) = %d", len(decoded.Owners[0].Assets))
	}
	if decoded.Owners[0].FindingCounts.Critical != 1 {
		t.Errorf("FindingCounts.Critical = %d", decoded.Owners[0].FindingCounts.Critical)
	}
	if decoded.Owners[0].FindingCounts.High != 3 {
		t.Errorf("FindingCounts.High = %d", decoded.Owners[0].FindingCounts.High)
	}
	if len(decoded.Owners[0].Sources) != 2 {
		t.Errorf("len(Sources) = %d", len(decoded.Owners[0].Sources))
	}
	if decoded.Owners[1].Confidence != 1.0 {
		t.Errorf("Owners[1].Confidence = %f", decoded.Owners[1].Confidence)
	}
	if len(decoded.UnownedAssets) != 2 {
		t.Errorf("len(UnownedAssets) = %d", len(decoded.UnownedAssets))
	}
	if len(decoded.ConflictingOwnership) != 1 {
		t.Fatalf("len(ConflictingOwnership) = %d", len(decoded.ConflictingOwnership))
	}
	if len(decoded.ConflictingOwnership[0].Candidates) != 2 {
		t.Errorf("len(Candidates) = %d", len(decoded.ConflictingOwnership[0].Candidates))
	}
}

func TestOwnershipMap_NoConflicts(t *testing.T) {
	om := OwnershipMap{
		ProjectID:   "proj-clean",
		GeneratedAt: time.Now().UTC(),
		Owners: []ResolvedOwner{
			{Identity: "@team-a", Type: asset.OwnerCloudTag, Assets: []string{"ip:10.0.0.1"}, Confidence: 1.0},
		},
	}

	data, err := json.Marshal(om)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)
	if stringContains(s, "\"unowned_assets\"") {
		t.Error("unowned_assets should be omitted when empty")
	}
	if stringContains(s, "\"conflicting_ownership\"") {
		t.Error("conflicting_ownership should be omitted when empty")
	}
}

// ── Change Impact Simulation ─────────────────────────────────────────────

func TestImpactSimulation_JSON_Roundtrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	sim := ImpactSimulation{
		ID:          "sim-001",
		ProjectID:   "proj-001",
		GeneratedAt: now,
		Change: ProposedChange{
			Type:           ChangeTypeFirewallRule,
			Source:         "https://github.com/acme/infra/pull/42",
			Description:    "Open port 8080 on api-prod security group",
			AffectedAssets: []string{"aws_ec2_instance:i-0abc123"},
			Changes: []FieldChange{
				{Field: "security_group.ingress", OldValue: "443/tcp", NewValue: "443/tcp,8080/tcp"},
			},
		},
		Impact: ImpactSummary{
			RiskDelta: 15.0,
			NewExposures: []ExposureChange{
				{
					AssetID:     "aws_ec2_instance:i-0abc123",
					Description: "Port 8080 (HTTP) now publicly accessible",
					Severity:    "high",
				},
			},
			AffectedAssetCount: 1,
			AffectedOwners:     []string{"@platform-team"},
		},
		AffectedAttackPaths: []AttackPathImpact{
			{
				AttackPathID: "ap-001",
				Effect:       PathShortened,
				Description:  "Direct HTTP access eliminates need for SSRF pivot",
			},
		},
		ComplianceImpact: []ComplianceImpact{
			{
				Framework:   "PCI",
				Control:     "PCI-1.3",
				Effect:      ComplianceDegraded,
				Description: "New public port increases external exposure surface",
			},
			{
				Framework:   "SOC2",
				Control:     "SOC2-CC6.6",
				Effect:      ComplianceDegraded,
				Description: "Additional unencrypted service endpoint exposed",
			},
		},
		Recommendation: RecommendReview,
	}

	data, err := json.MarshalIndent(sim, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ImpactSimulation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != "sim-001" {
		t.Errorf("ID = %q", decoded.ID)
	}
	if decoded.Change.Type != ChangeTypeFirewallRule {
		t.Errorf("Change.Type = %q", decoded.Change.Type)
	}
	if decoded.Change.Source != "https://github.com/acme/infra/pull/42" {
		t.Errorf("Change.Source = %q", decoded.Change.Source)
	}
	if len(decoded.Change.AffectedAssets) != 1 {
		t.Errorf("len(AffectedAssets) = %d", len(decoded.Change.AffectedAssets))
	}
	if len(decoded.Change.Changes) != 1 {
		t.Errorf("len(Changes) = %d", len(decoded.Change.Changes))
	}
	if decoded.Impact.RiskDelta != 15.0 {
		t.Errorf("RiskDelta = %f", decoded.Impact.RiskDelta)
	}
	if len(decoded.Impact.NewExposures) != 1 {
		t.Fatalf("len(NewExposures) = %d", len(decoded.Impact.NewExposures))
	}
	if decoded.Impact.NewExposures[0].Severity != "high" {
		t.Errorf("NewExposures[0].Severity = %q", decoded.Impact.NewExposures[0].Severity)
	}
	if decoded.Impact.AffectedAssetCount != 1 {
		t.Errorf("AffectedAssetCount = %d", decoded.Impact.AffectedAssetCount)
	}
	if len(decoded.AffectedAttackPaths) != 1 {
		t.Fatalf("len(AffectedAttackPaths) = %d", len(decoded.AffectedAttackPaths))
	}
	if decoded.AffectedAttackPaths[0].Effect != PathShortened {
		t.Errorf("Effect = %q", decoded.AffectedAttackPaths[0].Effect)
	}
	if len(decoded.ComplianceImpact) != 2 {
		t.Fatalf("len(ComplianceImpact) = %d", len(decoded.ComplianceImpact))
	}
	if decoded.ComplianceImpact[0].Effect != ComplianceDegraded {
		t.Errorf("ComplianceImpact[0].Effect = %q", decoded.ComplianceImpact[0].Effect)
	}
	if decoded.Recommendation != RecommendReview {
		t.Errorf("Recommendation = %q", decoded.Recommendation)
	}
}

func TestImpactSimulation_SafeChange(t *testing.T) {
	sim := ImpactSimulation{
		ID:          "sim-002",
		ProjectID:   "proj-001",
		GeneratedAt: time.Now().UTC(),
		Change: ProposedChange{
			Type:           ChangeTypeTLSConfig,
			Source:         "manual",
			Description:    "Upgrade minimum TLS version from 1.0 to 1.2",
			AffectedAssets: []string{"subdomain:api.example.com"},
		},
		Impact: ImpactSummary{
			RiskDelta:          -8.0,
			AffectedAssetCount: 1,
		},
		ComplianceImpact: []ComplianceImpact{
			{Framework: "PCI", Control: "PCI-4.2.1", Effect: ComplianceImproved, Description: "Meets PCI requirement for TLS 1.2+"},
		},
		Recommendation: RecommendProceed,
	}

	data, err := json.Marshal(sim)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ImpactSimulation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Impact.RiskDelta >= 0 {
		t.Errorf("RiskDelta should be negative for security improvement, got %f", decoded.Impact.RiskDelta)
	}
	if decoded.Recommendation != RecommendProceed {
		t.Errorf("Recommendation = %q, want %q", decoded.Recommendation, RecommendProceed)
	}
	if decoded.ComplianceImpact[0].Effect != ComplianceImproved {
		t.Errorf("ComplianceEffect = %q", decoded.ComplianceImpact[0].Effect)
	}
}

// ── Enum Constants ───────────────────────────────────────────────────────

func TestProposedChangeType_Values(t *testing.T) {
	types := []ProposedChangeType{
		ChangeTypeTerraformPlan, ChangeTypeFirewallRule, ChangeTypeIAMPolicy,
		ChangeTypeDNSRecord, ChangeTypeTLSConfig, ChangeTypeServiceDeploy,
		ChangeTypeNetworkChange, ChangeTypeAccessControl,
	}
	seen := make(map[ProposedChangeType]bool)
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

func TestAttackPathEffect_Values(t *testing.T) {
	effects := []AttackPathEffect{PathCreated, PathBroken, PathShortened, PathLengthened, PathUnchanged}
	seen := make(map[AttackPathEffect]bool)
	for _, e := range effects {
		if e == "" {
			t.Error("effect should not be empty")
		}
		if seen[e] {
			t.Errorf("duplicate effect: %q", e)
		}
		seen[e] = true
	}
}

func TestComplianceEffect_Values(t *testing.T) {
	effects := []ComplianceEffect{ComplianceImproved, ComplianceDegraded, ComplianceNeutral}
	seen := make(map[ComplianceEffect]bool)
	for _, e := range effects {
		if e == "" {
			t.Error("effect should not be empty")
		}
		if seen[e] {
			t.Errorf("duplicate effect: %q", e)
		}
		seen[e] = true
	}
}

func TestImpactRecommendation_Values(t *testing.T) {
	recs := []ImpactRecommendation{RecommendProceed, RecommendProceedCaution, RecommendReview, RecommendBlock}
	seen := make(map[ImpactRecommendation]bool)
	for _, r := range recs {
		if r == "" {
			t.Error("recommendation should not be empty")
		}
		if seen[r] {
			t.Errorf("duplicate recommendation: %q", r)
		}
		seen[r] = true
	}
}
