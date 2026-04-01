package asset

import (
	"encoding/json"
	"testing"
	"time"
)

// ── AssetStatus ────────────────────────────────────────────────────────

func TestAssetStatus_Values(t *testing.T) {
	statuses := []AssetStatus{
		AssetStatusActive,
		AssetStatusInactive,
		AssetStatusDecommission,
		AssetStatusNew,
	}
	seen := make(map[AssetStatus]bool)
	for _, s := range statuses {
		if s == "" {
			t.Error("status should not be empty")
		}
		if seen[s] {
			t.Errorf("duplicate status: %q", s)
		}
		seen[s] = true
	}
}

// ── AssetCriticality ───────────────────────────────────────────────────

func TestAssetCriticality_Values(t *testing.T) {
	levels := []AssetCriticality{CriticalityP0, CriticalityP1, CriticalityP2, CriticalityP3}
	seen := make(map[AssetCriticality]bool)
	for _, c := range levels {
		if c == "" {
			t.Error("criticality should not be empty")
		}
		if seen[c] {
			t.Errorf("duplicate criticality: %q", c)
		}
		seen[c] = true
	}
}

// ── OwnerType ──────────────────────────────────────────────────────────

func TestOwnerType_Values(t *testing.T) {
	types := []OwnerType{
		OwnerCodeowners,
		OwnerCloudTag,
		OwnerCommitFreq,
		OwnerIAMBinding,
		OwnerManual,
	}
	seen := make(map[OwnerType]bool)
	for _, ot := range types {
		if ot == "" {
			t.Error("owner type should not be empty")
		}
		if seen[ot] {
			t.Errorf("duplicate owner type: %q", ot)
		}
		seen[ot] = true
	}
}

// ── Asset JSON roundtrip with lifecycle fields ─────────────────────────

func TestAsset_JSON_Lifecycle(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a := Asset{
		ID:           "subdomain:api.example.com",
		Type:         AssetTypeSubdomain,
		Provider:     "web",
		Name:         "api.example.com",
		DiscoveredBy: "subdomain",
		Confidence:   0.95,
		DiscoveredAt: now,
		FirstSeen:    now.Add(-72 * time.Hour),
		LastSeen:     now,
		Status:       AssetStatusActive,
		Criticality:  CriticalityP0,
		Owners: []OwnerRef{
			{
				Type:       OwnerCodeowners,
				Identity:   "@platform-team",
				Source:     "CODEOWNERS",
				Confidence: 0.9,
			},
		},
		Services: []Service{
			{
				Port:        443,
				Protocol:    "tcp",
				ServiceName: "https",
				TLS:         true,
				State:       "open",
			},
			{
				Port:        22,
				Protocol:    "tcp",
				ServiceName: "ssh",
				Version:     "OpenSSH_9.2",
				State:       "open",
			},
		},
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Asset
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Status != AssetStatusActive {
		t.Errorf("Status = %q, want %q", decoded.Status, AssetStatusActive)
	}
	if decoded.Criticality != CriticalityP0 {
		t.Errorf("Criticality = %q, want %q", decoded.Criticality, CriticalityP0)
	}
	if len(decoded.Owners) != 1 {
		t.Fatalf("len(Owners) = %d, want 1", len(decoded.Owners))
	}
	if decoded.Owners[0].Type != OwnerCodeowners {
		t.Errorf("Owners[0].Type = %q", decoded.Owners[0].Type)
	}
	if decoded.Owners[0].Identity != "@platform-team" {
		t.Errorf("Owners[0].Identity = %q", decoded.Owners[0].Identity)
	}
	if len(decoded.Services) != 2 {
		t.Fatalf("len(Services) = %d, want 2", len(decoded.Services))
	}
	if decoded.Services[0].Port != 443 {
		t.Errorf("Services[0].Port = %d", decoded.Services[0].Port)
	}
	if !decoded.Services[0].TLS {
		t.Error("Services[0].TLS should be true")
	}
	if decoded.Services[1].Version != "OpenSSH_9.2" {
		t.Errorf("Services[1].Version = %q", decoded.Services[1].Version)
	}
	if !decoded.FirstSeen.Equal(now.Add(-72 * time.Hour)) {
		t.Errorf("FirstSeen = %v", decoded.FirstSeen)
	}
	if !decoded.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v", decoded.LastSeen)
	}
}

// ── Asset JSON omitempty ───────────────────────────────────────────────

func TestAsset_JSON_OmitEmpty(t *testing.T) {
	a := Asset{
		ID:           "ip:10.0.0.1",
		Type:         AssetTypeIP,
		Provider:     "web",
		Name:         "10.0.0.1",
		DiscoveredBy: "portscan",
		Confidence:   1.0,
		DiscoveredAt: time.Now().UTC(),
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	s := string(data)
	// Note: time.Time zero values are NOT omitted by encoding/json omitempty
	// (they're structs, not pointers), so first_seen and last_seen will always appear.
	for _, field := range []string{
		`"status"`, `"criticality"`,
		`"owners"`, `"services"`, `"aliases"`, `"labels"`,
		`"fingerprint"`, `"iam_context"`,
	} {
		if contains(s, field) {
			t.Errorf("JSON should omit %s when empty, got: ...%s...", field, truncate(s, 200))
		}
	}
}

// ── Service JSON roundtrip ─────────────────────────────────────────────

func TestService_JSON_Roundtrip(t *testing.T) {
	svc := Service{
		Port:        8080,
		Protocol:    "tcp",
		ServiceName: "http",
		Version:     "nginx/1.25.3",
		Banner:      "HTTP/1.1 200 OK\r\nServer: nginx",
		TLS:         false,
		State:       "open",
	}

	data, err := json.Marshal(svc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Service
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Port != 8080 {
		t.Errorf("Port = %d", decoded.Port)
	}
	if decoded.ServiceName != "http" {
		t.Errorf("ServiceName = %q", decoded.ServiceName)
	}
	if decoded.Version != "nginx/1.25.3" {
		t.Errorf("Version = %q", decoded.Version)
	}
	if decoded.Banner == "" {
		t.Error("Banner should not be empty")
	}
	if decoded.State != "open" {
		t.Errorf("State = %q", decoded.State)
	}
}

// ── OwnerRef JSON roundtrip ────────────────────────────────────────────

func TestOwnerRef_JSON_Roundtrip(t *testing.T) {
	ref := OwnerRef{
		Type:       OwnerIAMBinding,
		Identity:   "sa-api@project.iam.gserviceaccount.com",
		Source:     "gcp_iam_policy",
		Confidence: 1.0,
	}

	data, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded OwnerRef
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != OwnerIAMBinding {
		t.Errorf("Type = %q", decoded.Type)
	}
	if decoded.Identity != "sa-api@project.iam.gserviceaccount.com" {
		t.Errorf("Identity = %q", decoded.Identity)
	}
	if decoded.Confidence != 1.0 {
		t.Errorf("Confidence = %f", decoded.Confidence)
	}
}

// ── AssetGraph with lifecycle fields ───────────────────────────────────

func TestAssetGraph_JSON_WithLifecycle(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	graph := AssetGraph{
		ScanRunID:   "run-001",
		Domain:      "example.com",
		GeneratedAt: now,
		Assets: []Asset{
			{
				ID:           "domain:example.com",
				Type:         AssetTypeDomain,
				Provider:     "dns",
				Name:         "example.com",
				DiscoveredBy: "root",
				Confidence:   1.0,
				DiscoveredAt: now,
				Status:       AssetStatusNew,
				Criticality:  CriticalityP1,
				Services: []Service{
					{Port: 80, Protocol: "tcp", ServiceName: "http", State: "open"},
					{Port: 443, Protocol: "tcp", ServiceName: "https", TLS: true, State: "open"},
				},
			},
			{
				ID:           "ip:93.184.216.34",
				Type:         AssetTypeIP,
				Provider:     "dns",
				Name:         "93.184.216.34",
				DiscoveredBy: "dns_resolve",
				Confidence:   1.0,
				DiscoveredAt: now,
				Status:       AssetStatusActive,
				FirstSeen:    now.Add(-30 * 24 * time.Hour),
				LastSeen:     now,
			},
		},
		Relationships: []Relationship{
			{
				FromID:     "domain:example.com",
				ToID:       "ip:93.184.216.34",
				Type:       RelPointsTo,
				Confidence: 1.0,
			},
		},
	}

	data, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded AssetGraph
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Assets) != 2 {
		t.Fatalf("len(Assets) = %d", len(decoded.Assets))
	}
	if decoded.Assets[0].Status != AssetStatusNew {
		t.Errorf("Assets[0].Status = %q", decoded.Assets[0].Status)
	}
	if decoded.Assets[0].Criticality != CriticalityP1 {
		t.Errorf("Assets[0].Criticality = %q", decoded.Assets[0].Criticality)
	}
	if len(decoded.Assets[0].Services) != 2 {
		t.Errorf("len(Assets[0].Services) = %d", len(decoded.Assets[0].Services))
	}
	if decoded.Assets[1].Status != AssetStatusActive {
		t.Errorf("Assets[1].Status = %q", decoded.Assets[1].Status)
	}
	if decoded.Assets[1].FirstSeen.IsZero() {
		t.Error("Assets[1].FirstSeen should be set")
	}
}

// ── AssetType constants ────────────────────────────────────────────────

func TestAssetType_AllNonEmpty(t *testing.T) {
	types := []AssetType{
		AssetTypeDomain, AssetTypeSubdomain, AssetTypeIP, AssetTypeAPIEndpoint,
		AssetTypeGCPProject, AssetTypeGCPInstance, AssetTypeGCPBucket,
		AssetTypeAWSAccount, AssetTypeAWSEC2, AssetTypeAWSS3,
		AssetTypeAzureSubscription, AssetTypeAzureVM, AssetTypeAzureBlobContainer,
		AssetTypeGitHubRepo, AssetTypeGitHubWorkflow,
		AssetTypeK8sCluster, AssetTypeK8sNamespace, AssetTypeK8sWorkload,
		AssetTypeProxmoxNode, AssetTypeProxmoxVM,
		AssetTypeDockerHost, AssetTypeDockerContainer,
		AssetTypeNetworkDevice, AssetTypeNASAppliance,
	}
	seen := make(map[AssetType]bool)
	for _, at := range types {
		if at == "" {
			t.Error("AssetType should not be empty")
		}
		if seen[at] {
			t.Errorf("duplicate AssetType: %q", at)
		}
		seen[at] = true
	}
}

// ── RelationshipType constants ─────────────────────────────────────────

func TestRelationshipType_AllNonEmpty(t *testing.T) {
	types := []RelationshipType{
		RelManages, RelExposes, RelDeploysTo, RelPublishes,
		RelDeployedFrom, RelUses, RelAccesses, RelBelongsTo,
		RelPointsTo, RelLikelySameAs, RelCandidateSameAs,
	}
	seen := make(map[RelationshipType]bool)
	for _, rt := range types {
		if rt == "" {
			t.Error("RelationshipType should not be empty")
		}
		if seen[rt] {
			t.Errorf("duplicate RelationshipType: %q", rt)
		}
		seen[rt] = true
	}
}

// helpers

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
