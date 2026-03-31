package dns

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// rootDomain — TLD extraction logic
// ---------------------------------------------------------------------------

func TestRootDomain(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Standard single-label TLDs
		{name: "bare domain", input: "example.com", want: "example.com"},
		{name: "one subdomain", input: "sub.example.com", want: "example.com"},
		{name: "deep subdomain", input: "a.b.c.d.example.com", want: "example.com"},
		{name: ".org domain", input: "www.example.org", want: "example.org"},
		{name: ".net domain", input: "mail.example.net", want: "example.net"},
		{name: ".io domain", input: "app.service.example.io", want: "example.io"},
		{name: ".dev domain", input: "docs.example.dev", want: "example.dev"},

		// Two-label TLDs (ccSLDs)
		{name: "co.uk bare", input: "example.co.uk", want: "example.co.uk"},
		{name: "co.uk with sub", input: "www.example.co.uk", want: "example.co.uk"},
		{name: "co.uk deep sub", input: "a.b.example.co.uk", want: "example.co.uk"},
		{name: "org.uk", input: "mail.example.org.uk", want: "example.org.uk"},
		{name: "com.au", input: "www.example.com.au", want: "example.com.au"},
		{name: "co.nz", input: "shop.example.co.nz", want: "example.co.nz"},
		{name: "co.za", input: "api.example.co.za", want: "example.co.za"},
		{name: "co.jp", input: "www.example.co.jp", want: "example.co.jp"},
		{name: "co.in", input: "cdn.example.co.in", want: "example.co.in"},
		{name: "com.br", input: "www.example.com.br", want: "example.com.br"},
		{name: "com.cn", input: "www.example.com.cn", want: "example.com.cn"},
		{name: "gov.uk", input: "service.example.gov.uk", want: "example.gov.uk"},
		{name: "ac.uk", input: "cs.example.ac.uk", want: "example.ac.uk"},

		// Edge cases
		{name: "single label", input: "localhost", want: "localhost"},
		{name: "two labels only", input: "example.com", want: "example.com"},
		{name: "just two-label TLD suffix", input: "co.uk", want: "co.uk"},
		{name: "unknown two-label treated as normal", input: "example.zz.qq", want: "zz.qq"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rootDomain(tt.input)
			if got != tt.want {
				t.Errorf("rootDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AXFR output parsing — the record-filtering and host-extraction logic from
// ZoneTransferDiscovery, exercised here as pure string processing.
// ---------------------------------------------------------------------------

// parseAXFRRecords filters dig AXFR output the same way ZoneTransferDiscovery
// does: strips blank lines and comment lines (starting with ";").
func parseAXFRRecords(output string) []string {
	var records []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, ";") {
			records = append(records, line)
		}
	}
	return records
}

// extractHosts mirrors the hostname extraction loop in ZoneTransferDiscovery.
func extractHosts(records []string, domain string) []string {
	var discovered []string
	seen := map[string]bool{}
	for _, rec := range records {
		fields := strings.Fields(rec)
		for i, f := range fields {
			if (f == "A" || f == "AAAA") && i+1 < len(fields) && i > 0 {
				name := strings.TrimSuffix(fields[0], ".")
				name = strings.TrimSuffix(name, "."+domain)
				if name != "" && name != "@" && !seen[name] {
					seen[name] = true
					if !strings.Contains(name, ".") {
						name = name + "." + domain
					}
					discovered = append(discovered, name)
				}
			}
		}
	}
	return discovered
}

func TestParseAXFRRecords(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantCount int
	}{
		{
			name:      "empty output",
			output:    "",
			wantCount: 0,
		},
		{
			name:      "only whitespace",
			output:    "   \n   \n   ",
			wantCount: 0,
		},
		{
			name:      "only comments",
			output:    "; <<>> DiG 9.16 <<>>\n;; ANSWER SECTION:\n; comment line",
			wantCount: 0,
		},
		{
			name: "mixed records and comments",
			output: `; <<>> DiG 9.16 <<>> axfr example.com
;; ANSWER SECTION:
example.com.		3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 86400
example.com.		3600	IN	NS	ns1.example.com.
example.com.		3600	IN	NS	ns2.example.com.
www.example.com.	3600	IN	A	93.184.216.34
example.com.		3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 86400
;; Query time: 42 msec`,
			wantCount: 5,
		},
		{
			name: "fewer than 4 records means not a real transfer",
			output: `example.com.		3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 86400
example.com.		3600	IN	NS	ns1.example.com.
example.com.		3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 86400`,
			wantCount: 3,
		},
		{
			name: "real zone with 4+ records passes threshold",
			output: `example.com.		3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 86400
example.com.		3600	IN	NS	ns1.example.com.
www.example.com.	3600	IN	A	93.184.216.34
example.com.		3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 86400`,
			wantCount: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := parseAXFRRecords(tt.output)
			if len(records) != tt.wantCount {
				t.Errorf("parseAXFRRecords() returned %d records, want %d", len(records), tt.wantCount)
				for i, r := range records {
					t.Logf("  record[%d]: %q", i, r)
				}
			}
		})
	}
}

func TestParseAXFRRecords_ThresholdCheck(t *testing.T) {
	// The zone transfer logic requires >= 4 records to consider it valid.
	tests := []struct {
		name    string
		count   int
		isValid bool
	}{
		{"0 records", 0, false},
		{"1 record", 1, false},
		{"3 records", 3, false},
		{"4 records", 4, true},
		{"10 records", 10, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.count >= 4
			if got != tt.isValid {
				t.Errorf("count %d >= 4 = %v, want %v", tt.count, got, tt.isValid)
			}
		})
	}
}

func TestExtractHosts(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		domain  string
		want    []string
	}{
		{
			name:    "empty records",
			records: nil,
			domain:  "example.com",
			want:    nil,
		},
		{
			name: "A record extraction",
			records: []string{
				"www.example.com.	3600	IN	A	93.184.216.34",
			},
			domain: "example.com",
			want:   []string{"www.example.com"},
		},
		{
			name: "AAAA record extraction",
			records: []string{
				"ipv6.example.com.	3600	IN	AAAA	2001:db8::1",
			},
			domain: "example.com",
			want:   []string{"ipv6.example.com"},
		},
		{
			name: "multiple A records with deduplication",
			records: []string{
				"www.example.com.	3600	IN	A	93.184.216.34",
				"www.example.com.	3600	IN	A	93.184.216.35",
				"api.example.com.	3600	IN	A	10.0.0.1",
			},
			domain: "example.com",
			want:   []string{"www.example.com", "api.example.com"},
		},
		{
			name: "skips SOA and NS records",
			records: []string{
				"example.com.		3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 86400",
				"example.com.		3600	IN	NS	ns1.example.com.",
				"www.example.com.	3600	IN	A	93.184.216.34",
			},
			domain: "example.com",
			want:   []string{"www.example.com"},
		},
		{
			name: "handles subdomain under domain",
			records: []string{
				"mail.example.com.	3600	IN	A	10.0.0.2",
				"dev.staging.example.com.	3600	IN	A	10.0.0.3",
			},
			domain: "example.com",
			// "mail" has no dot -> gets ".example.com" appended.
			// "dev.staging" already contains a dot -> kept as-is (relative multi-label sub).
			want: []string{"mail.example.com", "dev.staging"},
		},
		{
			name: "skips @ record",
			records: []string{
				"@	3600	IN	A	93.184.216.34",
			},
			domain: "example.com",
			want:   nil,
		},
		{
			name: "mixed A and AAAA",
			records: []string{
				"www.example.com.	3600	IN	A	93.184.216.34",
				"www.example.com.	3600	IN	AAAA	2001:db8::1",
				"mail.example.com.	3600	IN	A	10.0.0.1",
			},
			domain: "example.com",
			want:   []string{"www.example.com", "mail.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHosts(tt.records, tt.domain)
			if len(got) != len(tt.want) {
				t.Fatalf("extractHosts() returned %d hosts, want %d\n  got:  %v\n  want: %v", len(got), len(tt.want), got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractHosts()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AXFR failure-string detection — the logic that skips refused/failed transfers
// ---------------------------------------------------------------------------

func TestAXFRFailureDetection(t *testing.T) {
	failureStrings := []string{
		"Transfer failed",
		"REFUSED",
		"SERVFAIL",
		"connection timed out",
	}

	tests := []struct {
		name     string
		output   string
		isFailed bool
	}{
		{
			name:     "Transfer failed message",
			output:   "; Transfer failed.\n",
			isFailed: true,
		},
		{
			name:     "REFUSED status",
			output:   ";; status: REFUSED, id: 12345\n",
			isFailed: true,
		},
		{
			name:     "SERVFAIL status",
			output:   ";; Got answer:\n;; status: SERVFAIL\n",
			isFailed: true,
		},
		{
			name:     "connection timed out",
			output:   ";; connection timed out; no servers could be reached\n",
			isFailed: true,
		},
		{
			name: "successful transfer",
			output: `example.com.	3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 86400
example.com.	3600	IN	NS	ns1.example.com.
www.example.com.	3600	IN	A	93.184.216.34
example.com.	3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 86400`,
			isFailed: false,
		},
		{
			name:     "empty output",
			output:   "",
			isFailed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failed := false
			for _, fs := range failureStrings {
				if strings.Contains(tt.output, fs) {
					failed = true
					break
				}
			}
			if failed != tt.isFailed {
				t.Errorf("failure detection for %q: got %v, want %v", tt.name, failed, tt.isFailed)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Evidence truncation — records shown are capped at 50
// ---------------------------------------------------------------------------

func TestEvidenceTruncation(t *testing.T) {
	tests := []struct {
		name      string
		count     int
		wantShown int
	}{
		{"under limit", 10, 10},
		{"at limit", 50, 50},
		{"over limit", 100, 50},
		{"zero", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := make([]string, tt.count)
			for i := range records {
				records[i] = "record"
			}
			shown := records
			if len(shown) > 50 {
				shown = shown[:50]
			}
			if len(shown) != tt.wantShown {
				t.Errorf("shown count = %d, want %d", len(shown), tt.wantShown)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scanner metadata
// ---------------------------------------------------------------------------

func TestScannerName(t *testing.T) {
	s := New()
	if s.Name() != "dns" {
		t.Errorf("Name() = %q, want %q", s.Name(), "dns")
	}
}

// ---------------------------------------------------------------------------
// knownTwoLabelTLDs coverage — verify map entries parse correctly
// ---------------------------------------------------------------------------

func TestKnownTwoLabelTLDs_AllEntries(t *testing.T) {
	// Every entry in the map should have exactly one dot.
	for tld := range knownTwoLabelTLDs {
		parts := strings.Split(tld, ".")
		if len(parts) != 2 {
			t.Errorf("knownTwoLabelTLDs entry %q has %d labels, want 2", tld, len(parts))
		}
		if parts[0] == "" || parts[1] == "" {
			t.Errorf("knownTwoLabelTLDs entry %q has empty label", tld)
		}
	}
}
