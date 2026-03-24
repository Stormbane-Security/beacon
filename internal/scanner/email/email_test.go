package email

// Unit tests for email scanner helper functions.
// Tests are written against expected correct behaviour, not to rubber-stamp
// the existing implementation. Each test documents the precise contract it
// verifies so failures are immediately actionable.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// ── estimateDKIMKeyLength ─────────────────────────────────────────────────────

// generateDKIMRecord creates a real DER-encoded SPKI public key and wraps it
// in a minimal DKIM TXT record string for testing.
func generateDKIMRecord(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

func TestEstimateDKIMKeyLength_1024(t *testing.T) {
	record := generateDKIMRecord(t, 1024)
	got := estimateDKIMKeyLength(record)
	if got != 1024 {
		t.Errorf("1024-bit key: got %d bits, want 1024", got)
	}
}

func TestEstimateDKIMKeyLength_2048(t *testing.T) {
	record := generateDKIMRecord(t, 2048)
	got := estimateDKIMKeyLength(record)
	if got != 2048 {
		t.Errorf("2048-bit key: got %d bits, want 2048", got)
	}
}

func TestEstimateDKIMKeyLength_4096(t *testing.T) {
	record := generateDKIMRecord(t, 4096)
	got := estimateDKIMKeyLength(record)
	if got != 4096 {
		t.Errorf("4096-bit key: got %d bits, want 4096", got)
	}
}

func TestEstimateDKIMKeyLength_RevokedKey(t *testing.T) {
	// p= empty means the key has been revoked (RFC 6376 §3.6.1)
	record := "v=DKIM1; k=rsa; p="
	got := estimateDKIMKeyLength(record)
	if got != 0 {
		t.Errorf("revoked key (empty p=): got %d, want 0", got)
	}
}

func TestEstimateDKIMKeyLength_MissingP(t *testing.T) {
	record := "v=DKIM1; k=rsa"
	got := estimateDKIMKeyLength(record)
	if got != 0 {
		t.Errorf("record without p= tag: got %d, want 0", got)
	}
}

func TestEstimateDKIMKeyLength_InvalidBase64(t *testing.T) {
	record := "v=DKIM1; k=rsa; p=!!!notbase64!!!"
	got := estimateDKIMKeyLength(record)
	if got != 0 {
		t.Errorf("invalid base64 p= tag: got %d, want 0", got)
	}
}

func TestEstimateDKIMKeyLength_ValidBase64ButNotDER(t *testing.T) {
	// Valid base64 that doesn't decode to a valid DER public key.
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString([]byte("this is not a DER key"))
	got := estimateDKIMKeyLength(record)
	if got != 0 {
		t.Errorf("valid base64 but not DER: got %d, want 0", got)
	}
}

// ── countSPFLookups ───────────────────────────────────────────────────────────

func TestCountSPFLookups_BasicMechanisms(t *testing.T) {
	tests := []struct {
		name string
		spf  string
		want int
	}{
		{
			name: "include counts as one lookup",
			spf:  "v=spf1 include:_spf.google.com ~all",
			want: 1,
		},
		{
			name: "a mechanism counts as one lookup",
			spf:  "v=spf1 a ~all",
			want: 1,
		},
		{
			name: "a:host counts as one lookup",
			spf:  "v=spf1 a:mail.example.com ~all",
			want: 1,
		},
		{
			name: "a/cidr counts as one lookup",
			spf:  "v=spf1 a/24 ~all",
			want: 1,
		},
		{
			name: "mx mechanism counts as one lookup",
			spf:  "v=spf1 mx ~all",
			want: 1,
		},
		{
			name: "mx:host counts as one lookup",
			spf:  "v=spf1 mx:mail.example.com ~all",
			want: 1,
		},
		{
			name: "ip4 does NOT count (no DNS lookup)",
			spf:  "v=spf1 ip4:1.2.3.4 ~all",
			want: 0,
		},
		{
			name: "ip6 does NOT count (no DNS lookup)",
			spf:  "v=spf1 ip6:::1 ~all",
			want: 0,
		},
		{
			name: "all does NOT count",
			spf:  "v=spf1 -all",
			want: 0,
		},
		{
			name: "'a' token must not match 'all' as prefix",
			spf:  "v=spf1 -all ~all +all",
			want: 0,
		},
		{
			name: "'a' token must not match 'aws' prefix",
			// regression: old HasPrefix("a") would count "aws" as a lookup
			spf:  "v=spf1 include:_spf.aws.com -all",
			want: 1,
		},
		{
			name: "multiple includes",
			spf:  "v=spf1 include:a.com include:b.com include:c.com -all",
			want: 3,
		},
		{
			name: "ten lookups — at the RFC limit",
			spf:  "v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com -all",
			want: 10,
		},
		{
			name: "ptr mechanism counts as one lookup (deprecated but valid)",
			spf:  "v=spf1 ptr:example.com -all",
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countSPFLookups(tt.spf)
			if got != tt.want {
				t.Errorf("countSPFLookups(%q) = %d; want %d", tt.spf, got, tt.want)
			}
		})
	}
}

// ── parseDMARCTags ────────────────────────────────────────────────────────────

func TestParseDMARCTags(t *testing.T) {
	tests := []struct {
		record string
		key    string
		want   string
	}{
		{"v=DMARC1; p=reject; rua=mailto:dmarc@example.com", "p", "reject"},
		{"v=DMARC1; p=none", "rua", ""},
		{"v=DMARC1; p=quarantine; sp=none; rua=mailto:r@x.com; ruf=mailto:f@x.com", "sp", "none"},
		{"v=DMARC1; p=none; rua=mailto:a@b.com", "rua", "mailto:a@b.com"},
		// Whitespace around = signs
		{"v=DMARC1; p = reject", "p", "reject"},
	}

	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			tags := parseDMARCTags(tt.record)
			got := tags[tt.key]
			if got != tt.want {
				t.Errorf("parseDMARCTags(%q)[%q] = %q; want %q", tt.record, tt.key, got, tt.want)
			}
		})
	}
}
