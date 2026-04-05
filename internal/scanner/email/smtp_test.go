package email

// Tests for SMTP probe logic. Using package email (not email_test) to access
// the unexported leaksSoftware helper directly.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// ─── leaksSoftware ───────────────────────────────────────────────────────────

func TestLeaksSoftware_RecognisedServers(t *testing.T) {
	cases := []struct {
		banner string
		want   bool
	}{
		{"220 mail.example.com ESMTP Postfix (Ubuntu)", true},
		{"220 smtp.example.com ESMTP Sendmail 8.15.2", true},
		{"220 mail.example.com ESMTP Exim 4.94.2", true},
		{"220 EXAMPLE-COM Microsoft ESMTP MAIL Service", true},
		{"220 exchange.corp.com Microsoft Exchange Server", true},
		{"220 mail.example.com ESMTP Zimbra", true},
		{"220 smtp.example.com ESMTP", false},          // no software name
		{"220 mail.example.com", false},                 // bare greeting
		{"220 smtp.office365.com Service ready", false}, // Microsoft 365 hides version
		{"", false},
	}

	for _, tc := range cases {
		got := leaksSoftware(tc.banner)
		if got != tc.want {
			t.Errorf("leaksSoftware(%q) = %v; want %v", tc.banner, got, tc.want)
		}
	}
}

// ─── Mock SMTP server ─────────────────────────────────────────────────────────

// ─── SMTP connection-level tests ────────────────────────────────────────────

// TestCheckSMTPBannerLeakDetected tests that a Postfix banner triggers the
// banner leak finding via checkSMTPConn with a mock server on a high port.
func TestCheckSMTPBannerLeakDetected(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start mock SMTP server: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Postfix banner + EHLO response, then reject relay
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		scanner := bufio.NewScanner(conn)

		_, _ = fmt.Fprintf(conn, "220 mail.test.local ESMTP Postfix (Ubuntu)\r\n")
		scanner.Scan() // EHLO
		_, _ = fmt.Fprintf(conn, "250 mail.test.local\r\n")
		scanner.Scan() // QUIT
		_, _ = fmt.Fprintf(conn, "221 Bye\r\n")
	}()

	conn, err := net.DialTimeout("tcp", l.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("cannot connect to mock SMTP: %v", err)
	}
	defer func() { _ = conn.Close() }()

	now := time.Now()
	findings := checkSMTPConn(conn, "test.local", "mail.test.local", now, module.ScanSurface)

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckEmailSMTPBannerLeak {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected banner leak finding for Postfix banner, got %d findings: %+v", len(findings), findings)
	}
}

// TestCheckSMTPOpenRelayViaLocalServer verifies the open relay detection logic
// using checkSMTPConn with a mock server that accepts relay attempts.
func TestCheckSMTPOpenRelayViaLocalServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start mock SMTP server: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Simulate an open relay: accepts everything
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		scanner := bufio.NewScanner(conn)

		_, _ = fmt.Fprintf(conn, "220 mail.example.com ESMTP\r\n")
		scanner.Scan() // EHLO
		_, _ = fmt.Fprintf(conn, "250 mail.example.com\r\n")
		scanner.Scan() // MAIL FROM
		_, _ = fmt.Fprintf(conn, "250 2.1.0 Ok\r\n")
		scanner.Scan() // RCPT TO
		_, _ = fmt.Fprintf(conn, "250 2.1.5 Ok\r\n")
		scanner.Scan() // QUIT
		_, _ = fmt.Fprintf(conn, "221 Bye\r\n")
	}()

	conn, err := net.DialTimeout("tcp", l.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("cannot connect to mock SMTP: %v", err)
	}
	defer func() { _ = conn.Close() }()

	now := time.Now()
	findings := checkSMTPConn(conn, "example.com", "mail.example.com", now, module.ScanDeep)

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckEmailSMTPOpenRelay {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected open relay finding, got %d findings: %+v", len(findings), findings)
	}
}

// TestLeaksSoftware_CaseSensitivity verifies the check is case-insensitive.
func TestLeaksSoftware_CaseSensitivity(t *testing.T) {
	cases := []struct {
		banner string
		want   bool
	}{
		{"220 mail.example.com ESMTP POSTFIX", true},  // uppercase
		{"220 mail.example.com esmtp postfix", true},  // lowercase
		{"220 mail.example.com EsMtP pOsTfIx", true}, // mixed case
		{"220 mail.example.com ESMTP exim4", true},
	}

	for _, tc := range cases {
		got := leaksSoftware(tc.banner)
		if got != tc.want {
			t.Errorf("leaksSoftware(%q) = %v; want %v (case-insensitive check)", tc.banner, got, tc.want)
		}
	}
}

// TestCheckSMTPFindsNoIssuesWhenNoMX verifies that domains without MX records
// produce no SMTP findings (graceful empty return).
func TestCheckSMTPNoMXRecordReturnsNoFindings(t *testing.T) {
	// "invalid." is an RFC 2606 reserved TLD with no DNS records.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	now := time.Now()
	findings := checkSMTP(ctx, "no-mx.invalid", now, module.ScanSurface)
	if len(findings) != 0 {
		t.Errorf("expected no SMTP findings for domain with no MX records, got %d", len(findings))
	}
}

// TestCheckSMTPFindingCheckIDs verifies the finding.CheckID constants used
// by SMTP checks are registered in the finding registry (mode = Surface).
func TestCheckSMTPFindingCheckIDsAreRegistered(t *testing.T) {
	checks := []finding.CheckID{
		finding.CheckEmailSMTPBannerLeak,
		finding.CheckEmailSMTPOpenRelay,
	}
	for _, id := range checks {
		meta := finding.Meta(id)
		if meta.CheckID != id {
			t.Errorf("CheckID %q not registered in Registry — Meta() returned default", id)
		}
		if meta.Mode != finding.ModeSurface {
			t.Errorf("CheckID %q has mode %v; SMTP checks must be ModeSurface", id, meta.Mode)
		}
	}
}
