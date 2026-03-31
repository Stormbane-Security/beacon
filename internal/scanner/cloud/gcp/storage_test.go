package gcp

import "testing"

// ── roleToAction ─────────────────────────────────────────────────────────────

func TestRoleToAction(t *testing.T) {
	tests := []struct {
		role string
		want string
	}{
		{role: "roles/storage.objectAdmin", want: "read, write, and delete objects in"},
		{role: "roles/storage.admin", want: "read, write, and delete objects in"},
		{role: "roles/storage.objectCreator", want: "upload objects to"},
		{role: "roles/storage.objectViewer", want: "read objects from"},
		{role: "roles/storage.legacyObjectReader", want: "read objects from"},
		{role: "roles/storage.legacyBucketReader", want: "access"},
		{role: "roles/viewer", want: "access"},
		{role: "", want: "access"},
		{role: "some-unknown-role", want: "access"},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			got := roleToAction(tt.role)
			if got != tt.want {
				t.Errorf("roleToAction(%q) = %q; want %q", tt.role, got, tt.want)
			}
		})
	}
}
