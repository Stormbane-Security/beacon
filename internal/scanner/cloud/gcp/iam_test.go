package gcp

import (
	"testing"
	"time"
)

// ── formatAge ────────────────────────────────────────────────────────────────

func TestFormatAge_Days(t *testing.T) {
	tests := []struct {
		name     string
		age      time.Duration
		wantUnit string // "d" for days, "h" for hours
	}{
		{
			name:     "100 days ago",
			age:      100 * 24 * time.Hour,
			wantUnit: "d",
		},
		{
			name:     "1 day ago",
			age:      25 * time.Hour,
			wantUnit: "d",
		},
		{
			name:     "12 hours ago",
			age:      12 * time.Hour,
			wantUnit: "h",
		},
		{
			name:     "1 hour ago",
			age:      1 * time.Hour,
			wantUnit: "h",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			created := time.Now().Add(-tt.age)
			got := formatAge(created)
			if len(got) == 0 {
				t.Fatal("formatAge returned empty string")
			}
			lastChar := got[len(got)-1:]
			if lastChar != tt.wantUnit {
				t.Errorf("formatAge(%v ago) = %q; want suffix %q", tt.age, got, tt.wantUnit)
			}
		})
	}
}

func TestFormatAge_DayCount(t *testing.T) {
	// 95 days ago should produce "95d".
	created := time.Now().Add(-95 * 24 * time.Hour)
	got := formatAge(created)
	if got != "95d" {
		t.Errorf("formatAge(95 days ago) = %q; want %q", got, "95d")
	}
}

func TestFormatAge_HourCount(t *testing.T) {
	// 5 hours ago should produce "5h".
	created := time.Now().Add(-5 * time.Hour)
	got := formatAge(created)
	if got != "5h" {
		t.Errorf("formatAge(5 hours ago) = %q; want %q", got, "5h")
	}
}

func TestFormatAge_ZeroDuration(t *testing.T) {
	// Just now should produce "0h".
	got := formatAge(time.Now())
	if got != "0h" {
		t.Errorf("formatAge(now) = %q; want %q", got, "0h")
	}
}

// ── primitiveRoles ───────────────────────────────────────────────────────────

func TestPrimitiveRoles_OwnerAndEditor(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{"roles/owner", true},
		{"roles/editor", true},
		{"roles/viewer", false},
		{"roles/storage.admin", false},
		{"roles/compute.admin", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			got := primitiveRoles[tt.role]
			if got != tt.want {
				t.Errorf("primitiveRoles[%q] = %v; want %v", tt.role, got, tt.want)
			}
		})
	}
}
