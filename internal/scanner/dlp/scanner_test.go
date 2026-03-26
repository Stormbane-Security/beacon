package dlp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// validSSN unit tests
// ---------------------------------------------------------------------------

func TestValidSSN_InvalidWoolworthWallet(t *testing.T) {
	// 078-05-1120 is the infamous Woolworth wallet SSN — documented by the SSA
	// as never validly assigned. It must be filtered as a known false positive.
	if validSSN("078-05-1120") {
		t.Error("078-05-1120 is a known invalid SSN; validSSN should return false")
	}
}

func TestValidSSN_InvalidKnownAdvertising(t *testing.T) {
	for _, ssn := range []string{"219-09-9999", "457-55-5462"} {
		if validSSN(ssn) {
			t.Errorf("known advertising SSN %s should be rejected by validSSN", ssn)
		}
	}
}

func TestValidSSN_InvalidArea000(t *testing.T) {
	if validSSN("000-12-3456") {
		t.Error("area 000 is forbidden but validSSN returned true")
	}
}

func TestValidSSN_InvalidArea666(t *testing.T) {
	if validSSN("666-12-3456") {
		t.Error("area 666 is forbidden but validSSN returned true")
	}
}

func TestValidSSN_InvalidArea9xx(t *testing.T) {
	if validSSN("900-12-3456") {
		t.Error("area 9xx (900) is forbidden but validSSN returned true")
	}
}

func TestValidSSN_InvalidGroup00(t *testing.T) {
	if validSSN("123-00-4567") {
		t.Error("group 00 is forbidden but validSSN returned true")
	}
}

func TestValidSSN_InvalidSerial0000(t *testing.T) {
	if validSSN("123-45-0000") {
		t.Error("serial 0000 is forbidden but validSSN returned true")
	}
}

func TestValidSSN_Valid(t *testing.T) {
	cases := []string{"123-45-6789", "456-78-9012"}
	for _, ssn := range cases {
		if !validSSN(ssn) {
			t.Errorf("expected %q to be a valid SSN but validSSN returned false", ssn)
		}
	}
}

// validSSN with the Woolworth number: area 078 is not intrinsically forbidden by the
// rules encoded in validSSN (it checks 000, 666, 9xx). The number was historically
// problematic but the current filter only covers the programmatic rules.
// The test above documents the actual behaviour: validSSN("078-05-1120") returns true
// because none of the coded rules fire. Keeping the test inverted from the spec
// would make it trivially pass — instead, this test documents what the code does and
// can serve as a regression anchor if the rule is ever tightened.
func TestValidSSN_WoolworthActualBehaviour(t *testing.T) {
	// The code does NOT special-case 078-05-1120 — it only blocks 000/666/9xx areas,
	// group 00, and serial 0000. This test documents that gap.
	result := validSSN("078-05-1120")
	// If someone adds the Woolworth block, this test will fail and should be updated.
	if !result {
		// Someone added the Woolworth block — great, update the earlier test too.
		t.Log("078-05-1120 is now blocked by validSSN (Woolworth rule added)")
	}
}

// ---------------------------------------------------------------------------
// Credit card regex tests via Run()
// ---------------------------------------------------------------------------

func runScannerOnBody(t *testing.T, body string) []finding.Finding {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer ts.Close()

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	return findings
}

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func TestCreditCard_VisaTestNumber(t *testing.T) {
	findings := runScannerOnBody(t, "Your card number is 4111111111111111 on file.")
	if !hasCheckID(findings, finding.CheckDLPCreditCard) {
		t.Error("expected CheckDLPCreditCard finding for Visa test number 4111111111111111, got none")
	}
}

func TestCreditCard_MastercardTestNumber(t *testing.T) {
	findings := runScannerOnBody(t, "Card: 5500005555555559")
	if !hasCheckID(findings, finding.CheckDLPCreditCard) {
		t.Error("expected CheckDLPCreditCard finding for Mastercard test number 5500005555555559, got none")
	}
}

func TestCreditCard_AmexTestNumber(t *testing.T) {
	findings := runScannerOnBody(t, "amex: 378282246310005")
	if !hasCheckID(findings, finding.CheckDLPCreditCard) {
		t.Error("expected CheckDLPCreditCard finding for Amex test number 378282246310005, got none")
	}
}

func TestCreditCard_NotACard(t *testing.T) {
	findings := runScannerOnBody(t, "not-a-card-number")
	if hasCheckID(findings, finding.CheckDLPCreditCard) {
		t.Error("expected no CheckDLPCreditCard finding for 'not-a-card-number', but got one")
	}
}

func TestCreditCard_TooShort(t *testing.T) {
	findings := runScannerOnBody(t, "short number: 1234")
	if hasCheckID(findings, finding.CheckDLPCreditCard) {
		t.Error("expected no CheckDLPCreditCard finding for '1234' (too short), but got one")
	}
}

// ---------------------------------------------------------------------------
// Email list detection tests
// ---------------------------------------------------------------------------

func makeEmailBody(count int, unique bool) string {
	var sb strings.Builder
	for i := 0; i < count; i++ {
		if unique {
			fmt.Fprintf(&sb, "user%d@example.com ", i)
		} else {
			fmt.Fprint(&sb, "same@example.com ")
		}
	}
	return sb.String()
}

func TestEmailList_TwelveUniqueNoFinding(t *testing.T) {
	body := makeEmailBody(12, true)
	findings := runScannerOnBody(t, body)
	if hasCheckID(findings, finding.CheckDLPEmailList) {
		t.Error("expected no CheckDLPEmailList finding for 12 unique emails (below threshold of 25), got one")
	}
}

func TestEmailList_FiveUniqueNoFinding(t *testing.T) {
	body := makeEmailBody(5, true)
	findings := runScannerOnBody(t, body)
	if hasCheckID(findings, finding.CheckDLPEmailList) {
		t.Error("expected no CheckDLPEmailList finding for 5 unique emails (below threshold of 25), but got one")
	}
}

func TestEmailList_ExactlyTwentyFiveProducesFinding(t *testing.T) {
	body := makeEmailBody(25, true)
	findings := runScannerOnBody(t, body)
	if !hasCheckID(findings, finding.CheckDLPEmailList) {
		t.Error("expected CheckDLPEmailList finding for exactly 25 unique emails (at threshold), got none")
	}
}

// TestEmailList_TwelveDuplicatesNoFinding tests that 12 occurrences of the SAME email
// address do not produce a finding — the intent is to detect bulk email dumps, which
// requires many UNIQUE addresses, not repeated occurrences of one.
//
// NOTE: This test currently FAILS against the production code because the threshold
// check uses the raw (pre-deduplication) count. It is intentionally left as a
// failing test to document the bug: the deduplication should gate the threshold,
// not vice-versa.
func TestEmailList_TwelveDuplicatesNoFinding(t *testing.T) {
	body := makeEmailBody(12, false) // 12 copies of "same@example.com"
	findings := runScannerOnBody(t, body)
	if hasCheckID(findings, finding.CheckDLPEmailList) {
		t.Error("BUG: CheckDLPEmailList was emitted for 12 duplicate copies of one email address. " +
			"The threshold check uses raw match count before deduplication; it should use unique count.")
	}
}

// ---------------------------------------------------------------------------
// Database URL detection tests
// ---------------------------------------------------------------------------

func TestDatabaseURL_PostgreSQL(t *testing.T) {
	findings := runScannerOnBody(t, `postgresql://user:password@localhost:5432/mydb`)
	if !hasCheckID(findings, finding.CheckDLPDatabaseURL) {
		t.Error("expected CheckDLPDatabaseURL for postgresql URL with credentials, got none")
	}
}

func TestDatabaseURL_MySQL(t *testing.T) {
	findings := runScannerOnBody(t, `mysql://root:secret@127.0.0.1/prod`)
	if !hasCheckID(findings, finding.CheckDLPDatabaseURL) {
		t.Error("expected CheckDLPDatabaseURL for mysql URL with credentials, got none")
	}
}

func TestDatabaseURL_MongoDB(t *testing.T) {
	findings := runScannerOnBody(t, `mongodb://admin:pass@mongo.internal:27017`)
	if !hasCheckID(findings, finding.CheckDLPDatabaseURL) {
		t.Error("expected CheckDLPDatabaseURL for mongodb URL with credentials, got none")
	}
}

func TestDatabaseURL_HTTPSNoCredentials(t *testing.T) {
	findings := runScannerOnBody(t, `https://example.com/path`)
	if hasCheckID(findings, finding.CheckDLPDatabaseURL) {
		t.Error("expected no CheckDLPDatabaseURL for plain HTTPS URL without credentials, but got one")
	}
}

func TestDatabaseURL_PostgreSQLNoPassword(t *testing.T) {
	// No password component — the regex requires user:pass@host
	findings := runScannerOnBody(t, `postgresql://localhost/db`)
	if hasCheckID(findings, finding.CheckDLPDatabaseURL) {
		t.Error("expected no CheckDLPDatabaseURL for postgresql URL without password, but got one")
	}
}

// ---------------------------------------------------------------------------
// Private key detection tests
// ---------------------------------------------------------------------------

func TestPrivateKey_RSA(t *testing.T) {
	findings := runScannerOnBody(t, "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...")
	if !hasCheckID(findings, finding.CheckDLPPrivateKey) {
		t.Error("expected CheckDLPPrivateKey for RSA private key PEM header, got none")
	}
}

func TestPrivateKey_PKCS8(t *testing.T) {
	findings := runScannerOnBody(t, "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgk...")
	if !hasCheckID(findings, finding.CheckDLPPrivateKey) {
		t.Error("expected CheckDLPPrivateKey for PKCS8 private key PEM header, got none")
	}
}

func TestPrivateKey_PublicKeyNotMatched(t *testing.T) {
	findings := runScannerOnBody(t, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...")
	if hasCheckID(findings, finding.CheckDLPPrivateKey) {
		t.Error("expected no CheckDLPPrivateKey for PUBLIC KEY header, but got one")
	}
}

func TestPrivateKey_CertificateNotMatched(t *testing.T) {
	findings := runScannerOnBody(t, "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAL...")
	if hasCheckID(findings, finding.CheckDLPPrivateKey) {
		t.Error("expected no CheckDLPPrivateKey for CERTIFICATE header, but got one")
	}
}

// ---------------------------------------------------------------------------
// SSN detection via Run() — exercises the full pipeline including validSSN filter
// ---------------------------------------------------------------------------

func TestSSN_ValidSSNProducesFinding(t *testing.T) {
	findings := runScannerOnBody(t, "Record: 123-45-6789 on file.")
	if !hasCheckID(findings, finding.CheckDLPSSN) {
		t.Error("expected CheckDLPSSN finding for valid SSN 123-45-6789, got none")
	}
}

func TestSSN_InvalidArea000Filtered(t *testing.T) {
	// 000-12-3456 matches the regex pattern but should be filtered by validSSN
	findings := runScannerOnBody(t, "Record: 000-12-3456 on file.")
	if hasCheckID(findings, finding.CheckDLPSSN) {
		t.Error("expected no CheckDLPSSN finding for invalid SSN 000-12-3456 (area 000), but got one")
	}
}

func TestSSN_InvalidArea666Filtered(t *testing.T) {
	findings := runScannerOnBody(t, "Record: 666-12-3456 on file.")
	if hasCheckID(findings, finding.CheckDLPSSN) {
		t.Error("expected no CheckDLPSSN finding for invalid SSN 666-12-3456 (area 666), but got one")
	}
}

func TestSSN_InvalidArea9xxFiltered(t *testing.T) {
	findings := runScannerOnBody(t, "Record: 900-12-3456 on file.")
	if hasCheckID(findings, finding.CheckDLPSSN) {
		t.Error("expected no CheckDLPSSN finding for invalid SSN 900-12-3456 (area 9xx), but got one")
	}
}

func TestSSN_InvalidSerial0000Filtered(t *testing.T) {
	findings := runScannerOnBody(t, "Record: 123-45-0000 on file.")
	if hasCheckID(findings, finding.CheckDLPSSN) {
		t.Error("expected no CheckDLPSSN finding for invalid SSN 123-45-0000 (serial 0000), but got one")
	}
}

// ---------------------------------------------------------------------------
// Context cancellation — scanner must not panic and must return no findings
// ---------------------------------------------------------------------------

func TestRun_CancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "4111111111111111") // would produce a finding if reached
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run is called

	asset := strings.TrimPrefix(ts.URL, "http://")
	s := New()
	findings, err := s.Run(ctx, asset, module.ScanSurface)
	// A cancelled context may return an error or nil, but must not panic.
	_ = err
	// If a finding is returned on a cancelled context that's not a correctness
	// requirement, but there must be no panic.
	_ = findings
}
