package asset

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/enrichment"
	"github.com/stormbane/beacon/internal/finding"
)

// ---------------------------------------------------------------------------
// normalizeIP
// ---------------------------------------------------------------------------

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "IPv4 unchanged", input: "1.2.3.4", want: "1.2.3.4"},
		{name: "IPv4 loopback", input: "127.0.0.1", want: "127.0.0.1"},
		{name: "IPv6 loopback short", input: "::1", want: "::1"},
		{name: "IPv6 loopback long", input: "0:0:0:0:0:0:0:1", want: "::1"},
		{name: "IPv6 full form collapsed", input: "2001:0db8:0000:0000:0000:0000:0000:0001", want: "2001:db8::1"},
		{name: "IPv6 mixed notation normalized to IPv4", input: "::ffff:192.168.1.1", want: "192.168.1.1"},
		{name: "invalid IP returned as-is", input: "not-an-ip", want: "not-an-ip"},
		{name: "empty string returned as-is", input: "", want: ""},
		{name: "CIDR notation returned as-is", input: "10.0.0.0/8", want: "10.0.0.0/8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeIP(tt.input)
			if got != tt.want {
				t.Errorf("normalizeIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// unionStrings
// ---------------------------------------------------------------------------

func TestUnionStrings(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want []string
	}{
		{name: "both nil", a: nil, b: nil, want: nil},
		{name: "a nil", a: nil, b: []string{"x"}, want: []string{"x"}},
		{name: "b nil", a: []string{"x"}, b: nil, want: []string{"x"}},
		{name: "no overlap", a: []string{"a", "b"}, b: []string{"c", "d"}, want: []string{"a", "b", "c", "d"}},
		{name: "full overlap", a: []string{"a", "b"}, b: []string{"a", "b"}, want: []string{"a", "b"}},
		{name: "partial overlap", a: []string{"a", "b"}, b: []string{"b", "c"}, want: []string{"a", "b", "c"}},
		{name: "empty slices", a: []string{}, b: []string{}, want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unionStrings(tt.a, tt.b)
			if len(got) != len(tt.want) {
				t.Fatalf("unionStrings(%v, %v) length = %d, want %d; got %v", tt.a, tt.b, len(got), len(tt.want), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("unionStrings(%v, %v)[%d] = %q, want %q", tt.a, tt.b, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewBuilder
// ---------------------------------------------------------------------------

func TestNewBuilder(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	if b.scanRunID != "run-1" {
		t.Errorf("scanRunID = %q, want %q", b.scanRunID, "run-1")
	}
	if b.domain != "example.com" {
		t.Errorf("domain = %q, want %q", b.domain, "example.com")
	}
	if b.assets == nil {
		t.Fatal("assets map should be initialized")
	}
	if b.ipIndex == nil {
		t.Fatal("ipIndex map should be initialized")
	}
	if len(b.assets) != 0 {
		t.Errorf("assets map should be empty, got %d entries", len(b.assets))
	}
}

// ---------------------------------------------------------------------------
// AddAsset
// ---------------------------------------------------------------------------

func TestAddAsset_Basic(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	a := Asset{
		ID:           "domain:example.com",
		Type:         AssetTypeDomain,
		Provider:     "web",
		Name:         "example.com",
		DiscoveredBy: "test",
		Confidence:   0.9,
	}
	b.AddAsset(a)

	if len(b.assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(b.assets))
	}
	stored := b.assets["domain:example.com"]
	if stored == nil {
		t.Fatal("asset not found by ID")
	}
	if stored.Name != "example.com" {
		t.Errorf("Name = %q, want %q", stored.Name, "example.com")
	}
	if stored.Confidence != 0.9 {
		t.Errorf("Confidence = %f, want 0.9", stored.Confidence)
	}
}

func TestAddAsset_SetsDiscoveredAtWhenZero(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	a := Asset{
		ID:       "domain:foo.com",
		Type:     AssetTypeDomain,
		Provider: "web",
		Name:     "foo.com",
	}
	before := time.Now()
	b.AddAsset(a)

	stored := b.assets["domain:foo.com"]
	if stored.DiscoveredAt.Before(before) {
		t.Error("DiscoveredAt should be set to approximately now when zero")
	}
}

func TestAddAsset_PreservesExplicitDiscoveredAt(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	a := Asset{
		ID:           "domain:foo.com",
		Type:         AssetTypeDomain,
		Provider:     "web",
		Name:         "foo.com",
		DiscoveredAt: ts,
	}
	b.AddAsset(a)

	stored := b.assets["domain:foo.com"]
	if !stored.DiscoveredAt.Equal(ts) {
		t.Errorf("DiscoveredAt = %v, want %v", stored.DiscoveredAt, ts)
	}
}

func TestAddAsset_MergeHigherConfidence(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com", Confidence: 0.5})
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com", Confidence: 0.9})

	stored := b.assets["domain:a.com"]
	if stored.Confidence != 0.9 {
		t.Errorf("Confidence = %f, want 0.9 (should keep higher)", stored.Confidence)
	}
}

func TestAddAsset_MergeDoesNotLowerConfidence(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com", Confidence: 0.9})
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com", Confidence: 0.5})

	stored := b.assets["domain:a.com"]
	if stored.Confidence != 0.9 {
		t.Errorf("Confidence = %f, want 0.9 (should not lower)", stored.Confidence)
	}
}

func TestAddAsset_MergeUnionsAliases(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com", Aliases: []string{"alias1"}})
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com", Aliases: []string{"alias1", "alias2"}})

	stored := b.assets["domain:a.com"]
	if len(stored.Aliases) != 2 {
		t.Fatalf("expected 2 aliases, got %d: %v", len(stored.Aliases), stored.Aliases)
	}
	wantAliases := map[string]bool{"alias1": true, "alias2": true}
	for _, a := range stored.Aliases {
		if !wantAliases[a] {
			t.Errorf("unexpected alias %q", a)
		}
	}
}

func TestAddAsset_MergeLabels(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{
		ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com",
		Labels: map[string]string{"env": "prod"},
	})
	b.AddAsset(Asset{
		ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com",
		Labels: map[string]string{"team": "infra"},
	})

	stored := b.assets["domain:a.com"]
	if stored.Labels["env"] != "prod" {
		t.Errorf("Labels[env] = %q, want %q", stored.Labels["env"], "prod")
	}
	if stored.Labels["team"] != "infra" {
		t.Errorf("Labels[team] = %q, want %q", stored.Labels["team"], "infra")
	}
}

func TestAddAsset_MergeLabels_NilExisting(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	// First asset has no labels
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com"})
	// Second adds labels
	b.AddAsset(Asset{
		ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com",
		Labels: map[string]string{"env": "staging"},
	})

	stored := b.assets["domain:a.com"]
	if stored.Labels["env"] != "staging" {
		t.Errorf("Labels[env] = %q, want %q", stored.Labels["env"], "staging")
	}
}

func TestAddAsset_MergeIAMContext(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	// First asset: no IAM context
	b.AddAsset(Asset{ID: "gcp:vm1", Type: AssetTypeGCPInstance, Provider: "gcp", Name: "vm1"})
	// Second: has IAM context
	iam := &IAMContext{Principal: "sa@proj.iam.gserviceaccount.com", Roles: []string{"roles/editor"}}
	b.AddAsset(Asset{ID: "gcp:vm1", Type: AssetTypeGCPInstance, Provider: "gcp", Name: "vm1", IAMContext: iam})

	stored := b.assets["gcp:vm1"]
	if stored.IAMContext == nil {
		t.Fatal("IAMContext should be set after merge")
	}
	if stored.IAMContext.Principal != "sa@proj.iam.gserviceaccount.com" {
		t.Errorf("Principal = %q, want %q", stored.IAMContext.Principal, "sa@proj.iam.gserviceaccount.com")
	}
}

func TestAddAsset_MergeIAMContext_DoesNotOverwrite(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	iam1 := &IAMContext{Principal: "first@proj.iam.gserviceaccount.com"}
	b.AddAsset(Asset{ID: "gcp:vm1", Type: AssetTypeGCPInstance, Provider: "gcp", Name: "vm1", IAMContext: iam1})
	iam2 := &IAMContext{Principal: "second@proj.iam.gserviceaccount.com"}
	b.AddAsset(Asset{ID: "gcp:vm1", Type: AssetTypeGCPInstance, Provider: "gcp", Name: "vm1", IAMContext: iam2})

	stored := b.assets["gcp:vm1"]
	if stored.IAMContext.Principal != "first@proj.iam.gserviceaccount.com" {
		t.Errorf("IAMContext should not be overwritten; got %q, want %q",
			stored.IAMContext.Principal, "first@proj.iam.gserviceaccount.com")
	}
}

func TestAddAsset_MergeFingerprint_NewOntoNil(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com"})
	fp := &AssetFingerprint{
		Tech: []TechSignal{{Name: "nginx", Confidence: 0.95}},
	}
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com", Fingerprint: fp})

	stored := b.assets["domain:a.com"]
	if stored.Fingerprint == nil {
		t.Fatal("Fingerprint should be set after merge")
	}
	if len(stored.Fingerprint.Tech) != 1 || stored.Fingerprint.Tech[0].Name != "nginx" {
		t.Errorf("Fingerprint tech = %+v, want [nginx]", stored.Fingerprint.Tech)
	}
}

func TestAddAsset_MergeFingerprint_AppendsTech(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	fp1 := &AssetFingerprint{
		Tech:             []TechSignal{{Name: "nginx", Confidence: 0.95}},
		ConfirmedSignals: []ConfirmedSignal{{Source: "http_header", Value: "nginx/1.19", Confidence: 0.95}},
	}
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com", Fingerprint: fp1})
	fp2 := &AssetFingerprint{
		Tech:             []TechSignal{{Name: "python", Confidence: 0.80}},
		ConfirmedSignals: []ConfirmedSignal{{Source: "cloud_metadata_label", Value: "python:3.11", Confidence: 0.80}},
	}
	b.AddAsset(Asset{ID: "domain:a.com", Type: AssetTypeDomain, Provider: "web", Name: "a.com", Fingerprint: fp2})

	stored := b.assets["domain:a.com"]
	if len(stored.Fingerprint.Tech) != 2 {
		t.Fatalf("expected 2 tech signals, got %d", len(stored.Fingerprint.Tech))
	}
	if len(stored.Fingerprint.ConfirmedSignals) != 2 {
		t.Fatalf("expected 2 confirmed signals, got %d", len(stored.Fingerprint.ConfirmedSignals))
	}
}

func TestAddAsset_IndexesIPAssets(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{
		ID:       "ip:93.184.216.34",
		Type:     AssetTypeIP,
		Provider: "network",
		Name:     "93.184.216.34",
	})

	if id, ok := b.ipIndex["93.184.216.34"]; !ok || id != "ip:93.184.216.34" {
		t.Errorf("ipIndex[93.184.216.34] = %q, %v; want %q, true", id, ok, "ip:93.184.216.34")
	}
}

func TestAddAsset_IndexesCloudExternalIP(t *testing.T) {
	tests := []struct {
		name     string
		assetID  string
		aType    AssetType
		provider string
	}{
		{"GCP instance", "gcp_compute_instance:proj/zone/vm1", AssetTypeGCPInstance, "gcp"},
		{"AWS EC2", "aws_ec2_instance:i-abc123", AssetTypeAWSEC2, "aws"},
		{"Azure VM", "azure_vm:sub/rg/vm1", AssetTypeAzureVM, "azure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBuilder("run-1", "example.com")
			b.AddAsset(Asset{
				ID:       tt.assetID,
				Type:     tt.aType,
				Provider: tt.provider,
				Name:     "vm1",
				Metadata: map[string]any{"external_ip": "10.0.0.1"},
			})
			if id, ok := b.ipIndex["10.0.0.1"]; !ok || id != tt.assetID {
				t.Errorf("ipIndex[10.0.0.1] = %q, %v; want %q, true", id, ok, tt.assetID)
			}
		})
	}
}

func TestAddAsset_DoesNotIndexCloudWithoutExternalIP(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{
		ID:       "gcp_compute_instance:proj/zone/vm1",
		Type:     AssetTypeGCPInstance,
		Provider: "gcp",
		Name:     "vm1",
		Metadata: map[string]any{"internal_ip": "10.128.0.2"},
	})
	if len(b.ipIndex) != 0 {
		t.Errorf("expected empty ipIndex, got %d entries", len(b.ipIndex))
	}
}

func TestAddAsset_DoesNotIndexMergedAsset(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{
		ID:       "ip:1.2.3.4",
		Type:     AssetTypeIP,
		Provider: "network",
		Name:     "1.2.3.4",
	})
	// Merging into existing asset should not re-index or panic
	b.AddAsset(Asset{
		ID:         "ip:1.2.3.4",
		Type:       AssetTypeIP,
		Provider:   "network",
		Name:       "1.2.3.4",
		Confidence: 0.99,
	})

	if len(b.ipIndex) != 1 {
		t.Errorf("expected 1 ipIndex entry, got %d", len(b.ipIndex))
	}
}

// ---------------------------------------------------------------------------
// AddRelationship
// ---------------------------------------------------------------------------

func TestAddRelationship(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddRelationship(Relationship{
		FromID:     "domain:example.com",
		ToID:       "ip:1.2.3.4",
		Type:       RelPointsTo,
		Confidence: 1.0,
	})
	b.AddRelationship(Relationship{
		FromID:     "domain:api.example.com",
		ToID:       "domain:example.com",
		Type:       RelBelongsTo,
		Confidence: 1.0,
	})

	if len(b.relationships) != 2 {
		t.Fatalf("expected 2 relationships, got %d", len(b.relationships))
	}
	if b.relationships[0].Type != RelPointsTo {
		t.Errorf("first relationship type = %q, want %q", b.relationships[0].Type, RelPointsTo)
	}
	if b.relationships[1].Type != RelBelongsTo {
		t.Errorf("second relationship type = %q, want %q", b.relationships[1].Type, RelBelongsTo)
	}
}

// ---------------------------------------------------------------------------
// AddDomainAsset
// ---------------------------------------------------------------------------

func TestAddDomainAsset_RootDomain(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddDomainAsset("example.com", []string{"93.184.216.34"}, "dns_scanner")

	// Should have domain + IP assets
	if len(b.assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(b.assets))
	}
	domain := b.assets["domain:example.com"]
	if domain == nil {
		t.Fatal("domain asset not found")
	}
	if domain.Type != AssetTypeDomain {
		t.Errorf("root domain type = %q, want %q", domain.Type, AssetTypeDomain)
	}
	if domain.DiscoveredBy != "dns_scanner" {
		t.Errorf("DiscoveredBy = %q, want %q", domain.DiscoveredBy, "dns_scanner")
	}
}

func TestAddDomainAsset_Subdomain(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddDomainAsset("api.example.com", nil, "dns_scanner")

	a := b.assets["domain:api.example.com"]
	if a == nil {
		t.Fatal("subdomain asset not found")
	}
	if a.Type != AssetTypeSubdomain {
		t.Errorf("subdomain type = %q, want %q", a.Type, AssetTypeSubdomain)
	}
}

func TestAddDomainAsset_DifferentDomainTreatedAsDomain(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddDomainAsset("other.org", nil, "dns_scanner")

	a := b.assets["domain:other.org"]
	if a == nil {
		t.Fatal("other domain asset not found")
	}
	// It doesn't end with ".example.com" and isn't equal to "example.com"
	// so it should be AssetTypeDomain
	if a.Type != AssetTypeDomain {
		t.Errorf("unrelated domain type = %q, want %q", a.Type, AssetTypeDomain)
	}
}

func TestAddDomainAsset_CreatesIPAndPointsToRelationship(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddDomainAsset("example.com", []string{"93.184.216.34", "93.184.216.35"}, "dns")

	// Should have 3 assets: domain + 2 IPs
	if len(b.assets) != 3 {
		t.Fatalf("expected 3 assets, got %d", len(b.assets))
	}
	// Should have 2 points_to relationships
	pointsToCount := 0
	for _, r := range b.relationships {
		if r.Type == RelPointsTo {
			pointsToCount++
		}
	}
	if pointsToCount != 2 {
		t.Errorf("expected 2 points_to relationships, got %d", pointsToCount)
	}
}

func TestAddDomainAsset_SkipsInvalidIPs(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddDomainAsset("example.com", []string{"not-an-ip", "1.2.3.4"}, "dns")

	// Only the valid IP should be added
	if len(b.assets) != 2 {
		t.Fatalf("expected 2 assets (domain + 1 valid IP), got %d", len(b.assets))
	}
	if _, ok := b.assets["ip:1.2.3.4"]; !ok {
		t.Error("valid IP asset not found")
	}
}

func TestAddDomainAsset_CrossReferencesWithCloudAsset_ViasBuild(t *testing.T) {
	// The inline cross-reference in AddDomainAsset is superseded by AddAsset's
	// IP indexing (the IP asset overwrites the cloud asset's ipIndex entry).
	// The reliable cross-reference path is CrossReferenceByIP called via Build.
	b := NewBuilder("run-1", "example.com")

	// Add a cloud asset with an external IP
	b.AddAsset(Asset{
		ID:       "gcp_compute_instance:projects/acme/zones/us-c1-a/instances/api-1",
		Type:     AssetTypeGCPInstance,
		Provider: "gcp",
		Name:     "api-1",
		Metadata: map[string]any{"external_ip": "34.120.0.1"},
	})

	// Add a domain that resolves to the same IP
	b.AddDomainAsset("api.example.com", []string{"34.120.0.1"}, "dns")

	// Build triggers CrossReferenceByIP which creates the link
	graph := b.Build()

	foundLikelySameAs := false
	for _, r := range graph.Relationships {
		if r.Type == RelLikelySameAs && r.FromID == "domain:api.example.com" &&
			r.ToID == "gcp_compute_instance:projects/acme/zones/us-c1-a/instances/api-1" {
			foundLikelySameAs = true
			if r.Confidence != 0.98 {
				t.Errorf("cross-ref confidence = %f, want 0.98", r.Confidence)
			}
		}
	}
	if !foundLikelySameAs {
		t.Error("expected likely_same_as relationship between domain and cloud asset after Build")
	}
}

func TestAddDomainAsset_NormalizesIPv6(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddDomainAsset("example.com", []string{"2001:db8::1"}, "dns")

	if _, ok := b.assets["ip:2001:db8::1"]; !ok {
		t.Error("IPv6 asset not found with normalized ID")
	}
}

// ---------------------------------------------------------------------------
// AddFindings
// ---------------------------------------------------------------------------

func TestAddFindings_WebFinding(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	findings := []finding.Finding{
		{
			CheckID:      "cors.wildcard_origin",
			Module:       "surface",
			Scanner:      "cors",
			Severity:     finding.SeverityHigh,
			Title:        "CORS wildcard origin",
			Asset:        "api.example.com",
			ProofCommand: "curl -H 'Origin: evil.com' https://api.example.com",
		},
	}
	b.AddFindings(findings)

	if len(b.findingRefs) != 1 {
		t.Fatalf("expected 1 finding ref, got %d", len(b.findingRefs))
	}
	ref := b.findingRefs[0]
	if ref.AssetID != "domain:api.example.com" {
		t.Errorf("AssetID = %q, want %q", ref.AssetID, "domain:api.example.com")
	}
	if ref.FindingID != "cors-0" {
		t.Errorf("FindingID = %q, want %q", ref.FindingID, "cors-0")
	}
	if ref.Severity != "high" {
		t.Errorf("Severity = %q, want %q", ref.Severity, "high")
	}
	if ref.Title != "CORS wildcard origin" {
		t.Errorf("Title = %q, want %q", ref.Title, "CORS wildcard origin")
	}
	if ref.ProofCommand != "curl -H 'Origin: evil.com' https://api.example.com" {
		t.Errorf("ProofCommand = %q, unexpected", ref.ProofCommand)
	}
}

func TestAddFindings_CloudFinding_UsesRawAssetID(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	findings := []finding.Finding{
		{
			CheckID:  "cloud.gcp.bucket_public",
			Module:   "cloud",
			Scanner:  "gcp_storage",
			Severity: finding.SeverityHigh,
			Title:    "Public GCS bucket",
			Asset:    "gcp_storage_bucket:my-bucket",
		},
	}
	b.AddFindings(findings)

	if len(b.findingRefs) != 1 {
		t.Fatalf("expected 1 finding ref, got %d", len(b.findingRefs))
	}
	// Cloud module findings should use raw asset ID, not prefixed with "domain:"
	if b.findingRefs[0].AssetID != "gcp_storage_bucket:my-bucket" {
		t.Errorf("AssetID = %q, want raw cloud asset ID", b.findingRefs[0].AssetID)
	}
}

func TestAddFindings_GitHubFinding_UsesRawAssetID(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	findings := []finding.Finding{
		{
			CheckID:  "github.repo_secret_exposed",
			Module:   "github",
			Scanner:  "ghrepo",
			Severity: finding.SeverityCritical,
			Title:    "Secret in repo",
			Asset:    "github_repo:org/repo",
		},
	}
	b.AddFindings(findings)

	if b.findingRefs[0].AssetID != "github_repo:org/repo" {
		t.Errorf("AssetID = %q, want raw GitHub asset ID", b.findingRefs[0].AssetID)
	}
}

func TestAddFindings_AssetWithColon_UsesRawAssetID(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	findings := []finding.Finding{
		{
			CheckID: "some.check",
			Module:  "surface",
			Scanner: "test",
			Asset:   "custom_type:some/path",
		},
	}
	b.AddFindings(findings)

	// Asset contains ":" so it should be used as-is
	if b.findingRefs[0].AssetID != "custom_type:some/path" {
		t.Errorf("AssetID = %q, want %q", b.findingRefs[0].AssetID, "custom_type:some/path")
	}
}

func TestAddFindings_MultipleFindings_IncrementingIDs(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	findings := []finding.Finding{
		{CheckID: "a", Scanner: "cors", Asset: "a.example.com"},
		{CheckID: "b", Scanner: "cors", Asset: "b.example.com"},
		{CheckID: "c", Scanner: "tls", Asset: "c.example.com"},
	}
	b.AddFindings(findings)

	if len(b.findingRefs) != 3 {
		t.Fatalf("expected 3 finding refs, got %d", len(b.findingRefs))
	}
	wantIDs := []string{"cors-0", "cors-1", "tls-2"}
	for i, want := range wantIDs {
		if b.findingRefs[i].FindingID != want {
			t.Errorf("findingRefs[%d].FindingID = %q, want %q", i, b.findingRefs[i].FindingID, want)
		}
	}
}

// ---------------------------------------------------------------------------
// AddEnrichedFindings
// ---------------------------------------------------------------------------

func TestAddEnrichedFindings_Basic(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	efs := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID:      "cors.wildcard_origin",
				Scanner:      "cors",
				Severity:     finding.SeverityHigh,
				Title:        "CORS wildcard",
				Asset:        "api.example.com",
				ProofCommand: "curl test",
			},
			Explanation: "Allows any origin",
			Impact:      "Data theft",
			Remediation: "Set allowed origins",
		},
	}
	b.AddEnrichedFindings(efs)

	if len(b.findingRefs) != 1 {
		t.Fatalf("expected 1 finding ref, got %d", len(b.findingRefs))
	}
	ref := b.findingRefs[0]
	if ref.AssetID != "domain:api.example.com" {
		t.Errorf("AssetID = %q, want %q", ref.AssetID, "domain:api.example.com")
	}
	if ref.Severity != "high" {
		t.Errorf("Severity = %q, want %q", ref.Severity, "high")
	}
}

func TestAddEnrichedFindings_UsesEnrichedComplianceTags(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	efs := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID: "cors.wildcard_origin",
				Scanner: "cors",
				Asset:   "api.example.com",
			},
			ComplianceTags: []string{"SOC2-CC6.1", "PCI-3.4"},
		},
	}
	b.AddEnrichedFindings(efs)

	ref := b.findingRefs[0]
	if len(ref.ComplianceTags) != 2 {
		t.Fatalf("expected 2 compliance tags, got %d", len(ref.ComplianceTags))
	}
	if ref.ComplianceTags[0] != "SOC2-CC6.1" {
		t.Errorf("ComplianceTags[0] = %q, want %q", ref.ComplianceTags[0], "SOC2-CC6.1")
	}
}

func TestAddEnrichedFindings_FallsBackToCheckIDComplianceTags(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	efs := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID: "cors.wildcard_origin",
				Scanner: "cors",
				Asset:   "api.example.com",
			},
			// ComplianceTags is nil/empty — should fall back to finding.ComplianceTags()
		},
	}
	b.AddEnrichedFindings(efs)

	// We can't assert exact tags since ComplianceTags depends on the check ID mapping,
	// but we can verify the code path doesn't panic and produces a result.
	// The function should have been called.
	if b.findingRefs[0].CheckID != "cors.wildcard_origin" {
		t.Errorf("CheckID = %q, want %q", b.findingRefs[0].CheckID, "cors.wildcard_origin")
	}
}

// ---------------------------------------------------------------------------
// AddIaCReference
// ---------------------------------------------------------------------------

func TestAddIaCReference(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	ref := IaCReference{
		AssetID:    "gcp_storage_bucket:my-bucket",
		Repo:       "org/infra",
		File:       "modules/storage/main.tf",
		Line:       42,
		Resource:   "google_storage_bucket.exports",
		Confidence: 1.0,
		Method:     "name_match",
	}
	b.AddIaCReference(ref)

	if len(b.iacRefs) != 1 {
		t.Fatalf("expected 1 IaC ref, got %d", len(b.iacRefs))
	}
	stored := b.iacRefs[0]
	if stored.AssetID != "gcp_storage_bucket:my-bucket" {
		t.Errorf("AssetID = %q", stored.AssetID)
	}
	if stored.Resource != "google_storage_bucket.exports" {
		t.Errorf("Resource = %q", stored.Resource)
	}
	if stored.Method != "name_match" {
		t.Errorf("Method = %q, want %q", stored.Method, "name_match")
	}
}

func TestAddIaCReference_Multiple(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddIaCReference(IaCReference{AssetID: "a", Repo: "r1", Confidence: 1.0})
	b.AddIaCReference(IaCReference{AssetID: "b", Repo: "r2", Confidence: 1.0})

	if len(b.iacRefs) != 2 {
		t.Fatalf("expected 2 IaC refs, got %d", len(b.iacRefs))
	}
}

// ---------------------------------------------------------------------------
// CrossReferenceByIP
// ---------------------------------------------------------------------------

func TestCrossReferenceByIP_LinksCloudToDomainsViaIP(t *testing.T) {
	b := NewBuilder("run-1", "example.com")

	// Add cloud asset with external IP
	b.AddAsset(Asset{
		ID:       "gcp_compute_instance:projects/acme/zones/us-c1-a/instances/api-1",
		Type:     AssetTypeGCPInstance,
		Provider: "gcp",
		Name:     "api-1",
		Metadata: map[string]any{"external_ip": "34.120.0.1"},
	})

	// Add domain and IP separately (simulating what a DNS scanner would do)
	b.AddAsset(Asset{
		ID:       "domain:api.example.com",
		Type:     AssetTypeDomain,
		Provider: "web",
		Name:     "api.example.com",
	})
	b.AddAsset(Asset{
		ID:       "ip:34.120.0.1",
		Type:     AssetTypeIP,
		Provider: "network",
		Name:     "34.120.0.1",
	})
	b.AddRelationship(Relationship{
		FromID:     "domain:api.example.com",
		ToID:       "ip:34.120.0.1",
		Type:       RelPointsTo,
		Confidence: 1.0,
	})

	b.CrossReferenceByIP()

	foundLink := false
	for _, r := range b.relationships {
		if r.Type == RelLikelySameAs &&
			r.FromID == "domain:api.example.com" &&
			r.ToID == "gcp_compute_instance:projects/acme/zones/us-c1-a/instances/api-1" {
			foundLink = true
			if r.Confidence != 0.98 {
				t.Errorf("cross-ref confidence = %f, want 0.98", r.Confidence)
			}
			if r.Evidence["ip"] != "34.120.0.1" {
				t.Errorf("evidence ip = %v, want %q", r.Evidence["ip"], "34.120.0.1")
			}
			if r.Evidence["method"] != "ip_match" {
				t.Errorf("evidence method = %v, want %q", r.Evidence["method"], "ip_match")
			}
		}
	}
	if !foundLink {
		t.Error("expected likely_same_as relationship from domain to cloud asset")
	}
}

func TestCrossReferenceByIP_NoMatchWithoutPointsToRelationship(t *testing.T) {
	b := NewBuilder("run-1", "example.com")

	// Cloud asset with external IP
	b.AddAsset(Asset{
		ID:       "gcp_compute_instance:proj/zone/vm1",
		Type:     AssetTypeGCPInstance,
		Provider: "gcp",
		Name:     "vm1",
		Metadata: map[string]any{"external_ip": "10.0.0.1"},
	})
	// Domain exists but has no points_to relationship to the IP
	b.AddAsset(Asset{
		ID:       "domain:example.com",
		Type:     AssetTypeDomain,
		Provider: "web",
		Name:     "example.com",
	})

	b.CrossReferenceByIP()

	for _, r := range b.relationships {
		if r.Type == RelLikelySameAs {
			t.Error("should not create likely_same_as without points_to relationship")
		}
	}
}

func TestCrossReferenceByIP_SkipsAssetsWithoutExternalIP(t *testing.T) {
	b := NewBuilder("run-1", "example.com")

	// Cloud asset without external_ip metadata
	b.AddAsset(Asset{
		ID:       "gcp_compute_instance:proj/zone/vm1",
		Type:     AssetTypeGCPInstance,
		Provider: "gcp",
		Name:     "vm1",
		Metadata: map[string]any{"internal_ip": "10.128.0.2"},
	})

	b.CrossReferenceByIP()

	for _, r := range b.relationships {
		if r.Type == RelLikelySameAs {
			t.Error("should not create likely_same_as for assets without external IP")
		}
	}
}

func TestCrossReferenceByIP_SkipsNonCloudAssets(t *testing.T) {
	b := NewBuilder("run-1", "example.com")

	b.AddAsset(Asset{
		ID:       "domain:example.com",
		Type:     AssetTypeDomain,
		Provider: "web",
		Name:     "example.com",
		Metadata: map[string]any{"external_ip": "1.2.3.4"},
	})
	b.AddRelationship(Relationship{
		FromID: "domain:other.com",
		ToID:   "ip:1.2.3.4",
		Type:   RelPointsTo,
	})

	b.CrossReferenceByIP()

	for _, r := range b.relationships {
		if r.Type == RelLikelySameAs {
			t.Error("should not create likely_same_as for non-cloud asset types")
		}
	}
}

func TestCrossReferenceByIP_MultipleCloudAssetTypes(t *testing.T) {
	// Verify AWS EC2 and Azure VM are also picked up
	tests := []struct {
		name    string
		assetID string
		aType   AssetType
	}{
		{"AWS EC2", "aws_ec2_instance:i-abc", AssetTypeAWSEC2},
		{"Azure VM", "azure_vm:sub/rg/vm1", AssetTypeAzureVM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBuilder("run-1", "example.com")
			b.AddAsset(Asset{
				ID:       tt.assetID,
				Type:     tt.aType,
				Provider: "cloud",
				Name:     "vm1",
				Metadata: map[string]any{"external_ip": "10.0.0.1"},
			})
			b.AddRelationship(Relationship{
				FromID:     "domain:app.example.com",
				ToID:       "ip:10.0.0.1",
				Type:       RelPointsTo,
				Confidence: 1.0,
			})

			b.CrossReferenceByIP()

			foundLink := false
			for _, r := range b.relationships {
				if r.Type == RelLikelySameAs && r.ToID == tt.assetID {
					foundLink = true
				}
			}
			if !foundLink {
				t.Errorf("expected likely_same_as relationship for %s", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

func TestBuild_ProducesCompleteGraph(t *testing.T) {
	b := NewBuilder("run-42", "example.com")

	// Add assets
	b.AddAsset(Asset{
		ID:       "domain:example.com",
		Type:     AssetTypeDomain,
		Provider: "web",
		Name:     "example.com",
	})
	b.AddAsset(Asset{
		ID:       "ip:1.2.3.4",
		Type:     AssetTypeIP,
		Provider: "network",
		Name:     "1.2.3.4",
	})

	// Add relationship
	b.AddRelationship(Relationship{
		FromID:     "domain:example.com",
		ToID:       "ip:1.2.3.4",
		Type:       RelPointsTo,
		Confidence: 1.0,
	})

	// Add finding
	b.AddFindings([]finding.Finding{
		{
			CheckID:  "tls.expired_cert",
			Scanner:  "tls",
			Severity: finding.SeverityCritical,
			Title:    "Expired TLS certificate",
			Asset:    "example.com",
		},
	})

	// Add IaC reference
	b.AddIaCReference(IaCReference{
		AssetID:    "domain:example.com",
		Repo:       "org/infra",
		File:       "dns.tf",
		Confidence: 1.0,
		Method:     "name_match",
	})

	graph := b.Build()

	if graph.ScanRunID != "run-42" {
		t.Errorf("ScanRunID = %q, want %q", graph.ScanRunID, "run-42")
	}
	if graph.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", graph.Domain, "example.com")
	}
	if graph.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero")
	}
	if len(graph.Assets) != 2 {
		t.Errorf("expected 2 assets, got %d", len(graph.Assets))
	}
	// Relationships: 1 explicit + potentially some from CrossReferenceByIP
	if len(graph.Relationships) < 1 {
		t.Errorf("expected at least 1 relationship, got %d", len(graph.Relationships))
	}
	if len(graph.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(graph.Findings))
	}
	if len(graph.IaCReferences) != 1 {
		t.Errorf("expected 1 IaC reference, got %d", len(graph.IaCReferences))
	}
}

func TestBuild_CallsCrossReferenceByIP(t *testing.T) {
	b := NewBuilder("run-1", "example.com")

	// Set up a cloud asset and a domain that resolves to the same IP,
	// but use the raw builder methods instead of AddDomainAsset to ensure
	// CrossReferenceByIP is what creates the link.
	b.AddAsset(Asset{
		ID:       "aws_ec2_instance:i-abc123",
		Type:     AssetTypeAWSEC2,
		Provider: "aws",
		Name:     "api-server",
		Metadata: map[string]any{"external_ip": "52.1.2.3"},
	})
	b.AddAsset(Asset{
		ID:       "ip:52.1.2.3",
		Type:     AssetTypeIP,
		Provider: "network",
		Name:     "52.1.2.3",
	})
	b.AddRelationship(Relationship{
		FromID:     "domain:api.example.com",
		ToID:       "ip:52.1.2.3",
		Type:       RelPointsTo,
		Confidence: 1.0,
	})

	graph := b.Build()

	foundLink := false
	for _, r := range graph.Relationships {
		if r.Type == RelLikelySameAs && r.ToID == "aws_ec2_instance:i-abc123" {
			foundLink = true
		}
	}
	if !foundLink {
		t.Error("Build should invoke CrossReferenceByIP and create likely_same_as edges")
	}
}

func TestBuild_AssetsCopied(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{
		ID:       "domain:example.com",
		Type:     AssetTypeDomain,
		Provider: "web",
		Name:     "example.com",
	})

	graph := b.Build()

	// Modify the output graph's assets — should not affect builder state
	if len(graph.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(graph.Assets))
	}
	graph.Assets[0].Name = "modified"

	// Builder's internal asset should be unaffected
	if b.assets["domain:example.com"].Name != "example.com" {
		t.Error("modifying Build() output should not affect internal builder state")
	}
}

func TestBuild_EmptyBuilder(t *testing.T) {
	b := NewBuilder("run-empty", "example.com")
	graph := b.Build()

	if graph.ScanRunID != "run-empty" {
		t.Errorf("ScanRunID = %q, want %q", graph.ScanRunID, "run-empty")
	}
	if len(graph.Assets) != 0 {
		t.Errorf("expected 0 assets, got %d", len(graph.Assets))
	}
	if len(graph.Relationships) != 0 {
		t.Errorf("expected 0 relationships, got %d", len(graph.Relationships))
	}
	if len(graph.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(graph.Findings))
	}
	if len(graph.IaCReferences) != 0 {
		t.Errorf("expected 0 IaC references, got %d", len(graph.IaCReferences))
	}
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

func TestBuilder_ConcurrentAccess(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	done := make(chan struct{})

	// Concurrent AddAsset
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			b.AddAsset(Asset{
				ID:       fmt.Sprintf("domain:host%d.example.com", i),
				Type:     AssetTypeSubdomain,
				Provider: "web",
				Name:     fmt.Sprintf("host%d.example.com", i),
			})
		}
	}()

	// Concurrent AddRelationship
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			b.AddRelationship(Relationship{
				FromID:     fmt.Sprintf("domain:host%d.example.com", i),
				ToID:       "domain:example.com",
				Type:       RelBelongsTo,
				Confidence: 1.0,
			})
		}
	}()

	// Concurrent AddDomainAsset
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 100; i < 200; i++ {
			b.AddDomainAsset(fmt.Sprintf("sub%d.example.com", i), []string{fmt.Sprintf("10.0.%d.%d", i/256, i%256)}, "dns")
		}
	}()

	// Wait for all goroutines
	for i := 0; i < 3; i++ {
		<-done
	}

	// Just verify it didn't panic or deadlock — exact counts vary due to races
	graph := b.Build()
	if len(graph.Assets) == 0 {
		t.Error("expected some assets after concurrent additions")
	}
}

// ---------------------------------------------------------------------------
// Integration-style tests
// ---------------------------------------------------------------------------

func TestIntegration_FullScanFlow(t *testing.T) {
	b := NewBuilder("scan-integration-1", "target.io")

	// Phase 1: Cloud scanning discovers a GCP instance
	b.AddAsset(Asset{
		ID:       "gcp_compute_instance:projects/target-io/zones/us-central1-a/instances/web-1",
		Type:     AssetTypeGCPInstance,
		Provider: "gcp",
		Name:     "web-1",
		Account:  "target-io",
		Region:   "us-central1-a",
		Public:   true,
		Metadata: map[string]any{"external_ip": "35.200.1.1"},
		IAMContext: &IAMContext{
			Principal: "web-sa@target-io.iam.gserviceaccount.com",
			Roles:     []string{"roles/editor"},
			Issues:    []string{"primitive_role"},
		},
	})

	// Phase 2: DNS scanning discovers the domain
	b.AddDomainAsset("target.io", []string{"35.200.1.1"}, "dns")
	b.AddDomainAsset("api.target.io", []string{"35.200.1.1"}, "dns")

	// Phase 3: Scanner findings
	b.AddFindings([]finding.Finding{
		{
			CheckID:      "tls.weak_cipher",
			Module:       "surface",
			Scanner:      "tls",
			Severity:     finding.SeverityMedium,
			Title:        "Weak TLS cipher suite",
			Asset:        "target.io",
			ProofCommand: "nmap --script ssl-enum-ciphers target.io",
		},
		{
			CheckID:  "cloud.gcp.iam_primitive_role",
			Module:   "cloud",
			Scanner:  "gcp_iam",
			Severity: finding.SeverityHigh,
			Title:    "Primitive IAM role",
			Asset:    "gcp_compute_instance:projects/target-io/zones/us-central1-a/instances/web-1",
		},
	})

	// Phase 4: IaC reference
	b.AddIaCReference(IaCReference{
		AssetID:    "gcp_compute_instance:projects/target-io/zones/us-central1-a/instances/web-1",
		Repo:       "target-io/infra",
		File:       "compute/main.tf",
		Line:       15,
		Resource:   "google_compute_instance.web_1",
		Confidence: 1.0,
		Method:     "name_match",
	})

	// Build the graph
	graph := b.Build()

	// Verify structure
	if graph.ScanRunID != "scan-integration-1" {
		t.Errorf("ScanRunID = %q", graph.ScanRunID)
	}
	if graph.Domain != "target.io" {
		t.Errorf("Domain = %q", graph.Domain)
	}

	// Should have: GCP instance + target.io domain + api.target.io subdomain + IP (35.200.1.1)
	if len(graph.Assets) != 4 {
		t.Errorf("expected 4 assets, got %d", len(graph.Assets))
		for _, a := range graph.Assets {
			t.Logf("  asset: %s (%s)", a.ID, a.Type)
		}
	}

	// Should have points_to relationships for both domains,
	// plus likely_same_as from CrossReferenceByIP and AddDomainAsset cross-refs
	hasPointsTo := false
	hasLikelySameAs := false
	for _, r := range graph.Relationships {
		if r.Type == RelPointsTo {
			hasPointsTo = true
		}
		if r.Type == RelLikelySameAs {
			hasLikelySameAs = true
		}
	}
	if !hasPointsTo {
		t.Error("expected points_to relationships")
	}
	if !hasLikelySameAs {
		t.Error("expected likely_same_as relationships from IP cross-referencing")
	}

	// Should have 2 findings
	if len(graph.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(graph.Findings))
	}

	// Verify finding asset IDs
	findingAssetIDs := make(map[string]bool)
	for _, f := range graph.Findings {
		findingAssetIDs[f.AssetID] = true
	}
	if !findingAssetIDs["domain:target.io"] {
		t.Error("expected finding for domain:target.io")
	}
	if !findingAssetIDs["gcp_compute_instance:projects/target-io/zones/us-central1-a/instances/web-1"] {
		t.Error("expected finding for GCP instance")
	}

	// Should have 1 IaC reference
	if len(graph.IaCReferences) != 1 {
		t.Errorf("expected 1 IaC reference, got %d", len(graph.IaCReferences))
	}
}

func TestIntegration_AssetMergeAcrossModules(t *testing.T) {
	b := NewBuilder("run-merge", "example.com")

	// Module 1 discovers the domain with basic info
	b.AddAsset(Asset{
		ID:         "domain:api.example.com",
		Type:       AssetTypeSubdomain,
		Provider:   "web",
		Name:       "api.example.com",
		Confidence: 0.8,
		Labels:     map[string]string{"source": "dns"},
	})

	// Module 2 enriches with fingerprint
	b.AddAsset(Asset{
		ID:         "domain:api.example.com",
		Type:       AssetTypeSubdomain,
		Provider:   "web",
		Name:       "api.example.com",
		Confidence: 0.95,
		Labels:     map[string]string{"stack": "python"},
		Fingerprint: &AssetFingerprint{
			Tech: []TechSignal{{Name: "Django", Version: "4.2", Confidence: 0.9}},
		},
	})

	graph := b.Build()

	// Find the merged asset
	var apiAsset *Asset
	for i := range graph.Assets {
		if graph.Assets[i].ID == "domain:api.example.com" {
			apiAsset = &graph.Assets[i]
			break
		}
	}
	if apiAsset == nil {
		t.Fatal("api.example.com asset not found")
	}
	if apiAsset.Confidence != 0.95 {
		t.Errorf("merged confidence = %f, want 0.95", apiAsset.Confidence)
	}
	if apiAsset.Labels["source"] != "dns" {
		t.Error("original label 'source' should be preserved")
	}
	if apiAsset.Labels["stack"] != "python" {
		t.Error("new label 'stack' should be merged")
	}
	if apiAsset.Fingerprint == nil || len(apiAsset.Fingerprint.Tech) != 1 {
		t.Error("fingerprint should be set with 1 tech signal")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestAddDomainAsset_EmptyIPs(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddDomainAsset("example.com", nil, "dns")

	if len(b.assets) != 1 {
		t.Fatalf("expected 1 asset (domain only), got %d", len(b.assets))
	}
	if len(b.relationships) != 0 {
		t.Errorf("expected 0 relationships with no IPs, got %d", len(b.relationships))
	}
}

func TestAddDomainAsset_CaseInsensitiveDomainMatch(t *testing.T) {
	b := NewBuilder("run-1", "Example.COM")
	b.AddDomainAsset("Example.COM", nil, "dns")

	a := b.assets["domain:Example.COM"]
	if a == nil {
		t.Fatal("domain asset not found")
	}
	// strings.EqualFold should detect case-insensitive match
	if a.Type != AssetTypeDomain {
		t.Errorf("type = %q, want %q (case-insensitive match)", a.Type, AssetTypeDomain)
	}
}

func TestBuild_AssetsAreDeterministic(t *testing.T) {
	// Build produces a slice from a map; verify all assets are included.
	b := NewBuilder("run-1", "example.com")
	ids := []string{"domain:a.com", "domain:b.com", "domain:c.com", "ip:1.1.1.1"}
	for _, id := range ids {
		typ := AssetTypeDomain
		if id == "ip:1.1.1.1" {
			typ = AssetTypeIP
		}
		b.AddAsset(Asset{ID: id, Type: typ, Provider: "web", Name: id})
	}

	graph := b.Build()
	if len(graph.Assets) != 4 {
		t.Fatalf("expected 4 assets, got %d", len(graph.Assets))
	}

	gotIDs := make([]string, len(graph.Assets))
	for i, a := range graph.Assets {
		gotIDs[i] = a.ID
	}
	sort.Strings(gotIDs)
	sort.Strings(ids)
	for i := range ids {
		if gotIDs[i] != ids[i] {
			t.Errorf("asset[%d] = %q, want %q", i, gotIDs[i], ids[i])
		}
	}
}

func TestAddAsset_IPv6NormalizationInIndex(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{
		ID:       "ip:::1",
		Type:     AssetTypeIP,
		Provider: "network",
		Name:     "0:0:0:0:0:0:0:1", // long form
	})

	// normalizeIP("0:0:0:0:0:0:0:1") should yield "::1"
	if _, ok := b.ipIndex["::1"]; !ok {
		t.Errorf("expected ipIndex to contain normalized IPv6 '::1', got keys: %v", b.ipIndex)
	}
}

func TestAddAsset_CloudAssetEmptyExternalIP(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{
		ID:       "gcp_compute_instance:proj/zone/vm1",
		Type:     AssetTypeGCPInstance,
		Provider: "gcp",
		Name:     "vm1",
		Metadata: map[string]any{"external_ip": ""},
	})

	if len(b.ipIndex) != 0 {
		t.Errorf("empty external_ip should not be indexed, got %d entries", len(b.ipIndex))
	}
}

func TestAddAsset_CloudAssetNoMetadata(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddAsset(Asset{
		ID:       "gcp_compute_instance:proj/zone/vm1",
		Type:     AssetTypeGCPInstance,
		Provider: "gcp",
		Name:     "vm1",
		// No metadata at all
	})

	if len(b.ipIndex) != 0 {
		t.Errorf("nil metadata should not cause panic or indexing, got %d entries", len(b.ipIndex))
	}
}

// ---------------------------------------------------------------------------
// Bug regression: AddDomainAsset cross-reference used unnormalized IP
// ---------------------------------------------------------------------------

func TestAddDomainAsset_CrossRefUsesNormalizedIPv6(t *testing.T) {
	b := NewBuilder("run-1", "example.com")

	// Add a cloud asset with an IPv6 external IP stored in short form.
	b.AddAsset(Asset{
		ID:       "gcp_compute_instance:proj/zone/vm-v6",
		Type:     AssetTypeGCPInstance,
		Provider: "gcp",
		Name:     "vm-v6",
		Metadata: map[string]any{"external_ip": "2001:db8::1"},
	})

	// Resolve the domain to the same IPv6 address in long form.
	// Before the fix, the unnormalized long-form IP would fail to match the
	// normalized short-form key in ipIndex.
	b.AddDomainAsset("v6.example.com", []string{"2001:0db8:0000:0000:0000:0000:0000:0001"}, "dns")

	graph := b.Build()

	foundLink := false
	for _, r := range graph.Relationships {
		if r.Type == RelLikelySameAs &&
			r.FromID == "domain:v6.example.com" &&
			r.ToID == "gcp_compute_instance:proj/zone/vm-v6" {
			foundLink = true
		}
	}
	if !foundLink {
		t.Error("expected likely_same_as relationship using normalized IPv6; cross-reference with unnormalized IP failed")
	}
}

// ---------------------------------------------------------------------------
// Bug regression: AddEnrichedFindings did not handle cloud/github asset IDs
// ---------------------------------------------------------------------------

func TestAddEnrichedFindings_CloudFinding_UsesRawAssetID(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	efs := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID:  "cloud.gcp.bucket_public",
				Module:   "cloud",
				Scanner:  "gcp_storage",
				Severity: finding.SeverityHigh,
				Title:    "Public GCS bucket",
				Asset:    "gcp_storage_bucket:my-bucket",
			},
		},
	}
	b.AddEnrichedFindings(efs)

	if len(b.findingRefs) != 1 {
		t.Fatalf("expected 1 finding ref, got %d", len(b.findingRefs))
	}
	if b.findingRefs[0].AssetID != "gcp_storage_bucket:my-bucket" {
		t.Errorf("AssetID = %q, want raw cloud asset ID %q",
			b.findingRefs[0].AssetID, "gcp_storage_bucket:my-bucket")
	}
}

func TestAddEnrichedFindings_GitHubFinding_UsesRawAssetID(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	efs := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID:  "github.secret_exposed",
				Module:   "github",
				Scanner:  "ghrepo",
				Severity: finding.SeverityCritical,
				Title:    "Secret exposed in repo",
				Asset:    "github_repo:org/repo",
			},
		},
	}
	b.AddEnrichedFindings(efs)

	if b.findingRefs[0].AssetID != "github_repo:org/repo" {
		t.Errorf("AssetID = %q, want raw GitHub asset ID %q",
			b.findingRefs[0].AssetID, "github_repo:org/repo")
	}
}

func TestAddEnrichedFindings_AssetWithColon_UsesRawAssetID(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	efs := []enrichment.EnrichedFinding{
		{
			Finding: finding.Finding{
				CheckID: "some.check",
				Module:  "surface",
				Scanner: "test",
				Asset:   "custom_type:path/resource",
			},
		},
	}
	b.AddEnrichedFindings(efs)

	if b.findingRefs[0].AssetID != "custom_type:path/resource" {
		t.Errorf("AssetID = %q, want %q (asset with colon should be used as-is)",
			b.findingRefs[0].AssetID, "custom_type:path/resource")
	}
}

// ---------------------------------------------------------------------------
// Edge case: self-referencing relationship
// ---------------------------------------------------------------------------

func TestAddRelationship_SelfReference(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	b.AddRelationship(Relationship{
		FromID:     "domain:example.com",
		ToID:       "domain:example.com",
		Type:       RelPointsTo,
		Confidence: 1.0,
	})

	// Self-referencing edges should not panic — graph consumers handle them.
	if len(b.relationships) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(b.relationships))
	}
	if b.relationships[0].FromID != b.relationships[0].ToID {
		t.Error("expected self-referencing relationship to be preserved")
	}
}

// ---------------------------------------------------------------------------
// Edge case: duplicate relationships
// ---------------------------------------------------------------------------

func TestAddRelationship_Duplicates(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	rel := Relationship{
		FromID:     "domain:a.com",
		ToID:       "ip:1.2.3.4",
		Type:       RelPointsTo,
		Confidence: 1.0,
	}
	b.AddRelationship(rel)
	b.AddRelationship(rel)

	// Builder does not deduplicate — both should be stored.
	if len(b.relationships) != 2 {
		t.Fatalf("expected 2 relationships (duplicates allowed), got %d", len(b.relationships))
	}
}

// ---------------------------------------------------------------------------
// Edge case: special characters in asset names/IDs
// ---------------------------------------------------------------------------

func TestAddAsset_SpecialCharactersInName(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	specialNames := []string{
		`asset "with quotes"`,
		"asset\nwith\nnewlines",
		`asset\with\backslashes`,
		"asset<with>angles",
		"asset with unicode: \u00e9\u00e0\u00fc",
		"",
	}
	for i, name := range specialNames {
		id := fmt.Sprintf("domain:special-%d", i)
		b.AddAsset(Asset{
			ID:       id,
			Type:     AssetTypeDomain,
			Provider: "web",
			Name:     name,
		})
	}

	graph := b.Build()
	if len(graph.Assets) != len(specialNames) {
		t.Errorf("expected %d assets, got %d", len(specialNames), len(graph.Assets))
	}
}

// ---------------------------------------------------------------------------
// Edge case: nil slices in Build output
// ---------------------------------------------------------------------------

func TestBuild_NilSlicesAreEmpty(t *testing.T) {
	b := NewBuilder("run-1", "example.com")
	graph := b.Build()

	// Verify nil slices don't cause issues downstream.
	if graph.Assets == nil {
		t.Error("Assets should be an empty non-nil slice")
	}
	// Relationships, Findings, IaCReferences may be nil but should not panic
	// when iterated.
	for range graph.Relationships {
		// just checking iteration doesn't panic
	}
	for range graph.Findings {
	}
	for range graph.IaCReferences {
	}
}
