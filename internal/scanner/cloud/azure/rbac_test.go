package azure

import (
	"testing"
)

// -------------------------------------------------------------------------
// lastSegment
// -------------------------------------------------------------------------

func TestLastSegment_MultipleSegments(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
			want:  "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
		},
		{
			input: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
			want:  "b24988ac-6180-42a0-ab88-20f7382dd24c",
		},
		{
			input: "a/b/c",
			want:  "c",
		},
		{
			input: "single",
			want:  "single",
		},
		{
			input: "/leading/slash",
			want:  "slash",
		},
		{
			input: "trailing/slash/",
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := lastSegment(tt.input)
			if got != tt.want {
				t.Errorf("lastSegment(%q) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLastSegment_EmptyString(t *testing.T) {
	got := lastSegment("")
	if got != "" {
		t.Errorf("lastSegment(\"\") = %q; want %q", got, "")
	}
}

// -------------------------------------------------------------------------
// broadRoles map
// -------------------------------------------------------------------------

func TestBroadRoles_OwnerIsPresent(t *testing.T) {
	if !broadRoles["8e3af657-a8ff-443c-a75c-2fe8c4bcb635"] {
		t.Error("Owner role ID should be in broadRoles")
	}
}

func TestBroadRoles_ContributorIsPresent(t *testing.T) {
	if !broadRoles["b24988ac-6180-42a0-ab88-20f7382dd24c"] {
		t.Error("Contributor role ID should be in broadRoles")
	}
}

func TestBroadRoles_ReaderIsNotBroad(t *testing.T) {
	// Reader role (acdd72a7-3385-48ef-bd42-f606fba81ae7) should NOT be in broadRoles.
	if broadRoles["acdd72a7-3385-48ef-bd42-f606fba81ae7"] {
		t.Error("Reader role ID should not be in broadRoles")
	}
}

func TestBroadRoles_ArbitraryIDNotBroad(t *testing.T) {
	if broadRoles["00000000-0000-0000-0000-000000000000"] {
		t.Error("arbitrary role ID should not be in broadRoles")
	}
}

// -------------------------------------------------------------------------
// Scanner constructor and Name
// -------------------------------------------------------------------------

func TestNew_ReturnsScanner(t *testing.T) {
	cfg := Config{
		SubscriptionIDs: []string{"sub-1"},
		TenantID:        "tenant-123",
		ClientID:        "client-456",
		ClientSecret:    "secret-789",
	}
	s := New(cfg)
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.cfg.TenantID != "tenant-123" {
		t.Errorf("cfg.TenantID = %q; want %q", s.cfg.TenantID, "tenant-123")
	}
}

func TestNew_EmptyConfig(t *testing.T) {
	s := New(Config{})
	if s == nil {
		t.Fatal("New returned nil")
	}
	if len(s.cfg.SubscriptionIDs) != 0 {
		t.Errorf("expected empty SubscriptionIDs, got %d", len(s.cfg.SubscriptionIDs))
	}
}

func TestScanner_Name(t *testing.T) {
	s := New(Config{})
	if got := s.Name(); got != "cloud/azure" {
		t.Errorf("Name() = %q; want %q", got, "cloud/azure")
	}
}
