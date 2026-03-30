package aws

import "testing"

// ---------------------------------------------------------------------------
// isSensitivePort — pure function tests
// ---------------------------------------------------------------------------

func TestIsSensitivePort(t *testing.T) {
	tests := []struct {
		name     string
		from     int32
		to       int32
		expected bool
	}{
		// Exact matches for each sensitive port.
		{"SSH exact", 22, 22, true},
		{"RDP exact", 3389, 3389, true},
		{"PostgreSQL exact", 5432, 5432, true},
		{"MySQL exact", 3306, 3306, true},
		{"MongoDB exact", 27017, 27017, true},
		{"Redis exact", 6379, 6379, true},
		{"Elasticsearch exact", 9200, 9200, true},
		{"HTTP alt exact", 8080, 8080, true},
		{"HTTPS alt exact", 8443, 8443, true},
		{"Docker unencrypted exact", 2375, 2375, true},
		{"Docker TLS exact", 2376, 2376, true},

		// Sensitive port within a range.
		{"range includes SSH", 20, 25, true},
		{"range includes RDP", 3380, 3400, true},
		{"range includes MySQL and PostgreSQL", 3300, 5500, true},
		{"range includes Redis", 6370, 6380, true},
		{"range includes MongoDB", 27000, 27100, true},
		{"range includes Elasticsearch", 9100, 9300, true},
		{"range includes Docker", 2370, 2380, true},
		{"range includes HTTP alt", 8000, 8100, true},
		{"range includes HTTPS alt", 8400, 8500, true},

		// Full port range open (0-65535).
		{"full port range", 0, 65535, true},

		// Non-sensitive ports.
		{"HTTP 80", 80, 80, false},
		{"HTTPS 443", 443, 443, false},
		{"DNS 53", 53, 53, false},
		{"SMTP 25", 25, 25, false},
		{"high port non-sensitive", 50000, 50000, false},
		{"low range no sensitive port", 1, 21, false},
		{"range between SSH and Docker", 23, 2374, false},
		{"range between Docker and MySQL", 2377, 3305, false},
		{"range between MySQL and RDP", 3307, 3388, false},
		{"range between RDP and PostgreSQL", 3390, 5431, false},
		{"range between PostgreSQL and Redis", 5433, 6378, false},
		{"range between Redis and HTTP alt", 6380, 8079, false},
		{"range between HTTP alt and HTTPS alt", 8081, 8442, false},
		{"range between HTTPS alt and Elasticsearch", 8444, 9199, false},
		{"range between Elasticsearch and MongoDB", 9201, 27016, false},
		{"above MongoDB", 27018, 40000, false},

		// Edge cases.
		{"zero range no sensitive port", 0, 0, false},
		{"single port 65535", 65535, 65535, false},
		{"from equals to boundary of sensitive", 21, 21, false},
		{"from equals to just above SSH", 23, 23, false},

		// Boundary tests for sensitive ports.
		{"just below SSH", 21, 21, false},
		{"just above SSH", 23, 23, false},
		{"boundary includes SSH from below", 21, 22, true},
		{"boundary includes SSH from above", 22, 23, true},
		{"just below RDP", 3388, 3388, false},
		{"just above RDP", 3390, 3390, false},

		// Range that spans from 0 to 65535 but NOT via from==0 && to==65535.
		// This still catches sensitive ports via individual checks.
		{"range 1-65534 still catches SSH", 1, 65534, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSensitivePort(tt.from, tt.to)
			if got != tt.expected {
				t.Errorf("isSensitivePort(%d, %d) = %v, want %v", tt.from, tt.to, got, tt.expected)
			}
		})
	}
}

// TestIsSensitivePort_AllPortsOpen verifies the special case where
// from=0, to=65535 is flagged even when no individual sensitive port
// would be checked (the function explicitly checks for the full range).
func TestIsSensitivePort_AllPortsOpen(t *testing.T) {
	if !isSensitivePort(0, 65535) {
		t.Error("isSensitivePort(0, 65535) = false, want true for full port range")
	}
}

// TestIsSensitivePort_NotFullRange verifies that partial ranges near the
// 0-65535 boundary are NOT flagged unless they contain a sensitive port.
func TestIsSensitivePort_NotFullRange(t *testing.T) {
	// 0 to 65534 still includes all sensitive ports, so it should be true
	// (via the individual port checks, not the full-range check).
	if !isSensitivePort(0, 65534) {
		t.Error("isSensitivePort(0, 65534) = false, want true (contains SSH on port 22)")
	}

	// 1 to 65535 also includes all sensitive ports.
	if !isSensitivePort(1, 65535) {
		t.Error("isSensitivePort(1, 65535) = false, want true (contains SSH on port 22)")
	}

	// 0 to 0 does NOT contain any sensitive port and is NOT the full range.
	if isSensitivePort(0, 0) {
		t.Error("isSensitivePort(0, 0) = true, want false (port 0 is not sensitive)")
	}
}
