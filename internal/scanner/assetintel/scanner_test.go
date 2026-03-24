package assetintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
)

// redirectTransport rewrites all request host to a mock server so internal
// lookup functions (which hardcode their API hosts) hit the mock instead.
type redirectTransport string

func (b redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = "http"
	req2.URL.Host = strings.TrimPrefix(string(b), "http://")
	return http.DefaultTransport.RoundTrip(req2)
}

func mockClient(t *testing.T, handler http.HandlerFunc) (*http.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	client := &http.Client{Transport: redirectTransport(srv.URL)}
	return client, srv
}

// ── Shodan ────────────────────────────────────────────────────────────────────

func TestShodan_KeySentInHeader(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "my-shodan-key" {
			t.Errorf("Key header = %q; want %q", r.Header.Get("Key"), "my-shodan-key")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ports":[80,443],"org":"ExampleCorp","os":""}`))
	})
	defer srv.Close()

	f := shodanLookup(context.Background(), client, "example.com", "1.2.3.4", "my-shodan-key")
	if f == nil {
		t.Fatal("expected finding, got nil")
	}
	if f.CheckID != finding.CheckShodanHostInfo {
		t.Errorf("CheckID = %q; want %q", f.CheckID, finding.CheckShodanHostInfo)
	}
}

func TestShodan_EmptyPortsAndOrg_ReturnsNil(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ports":[],"org":""}`))
	})
	defer srv.Close()

	f := shodanLookup(context.Background(), client, "example.com", "1.2.3.4", "key")
	if f != nil {
		t.Errorf("expected nil for empty Shodan response, got %s", f.CheckID)
	}
}

func TestShodan_Non200_ReturnsNil(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"Invalid API key"}`))
	})
	defer srv.Close()

	f := shodanLookup(context.Background(), client, "example.com", "1.2.3.4", "badkey")
	if f != nil {
		t.Errorf("expected nil for 401 response, got %s", f.CheckID)
	}
}

func TestShodan_WithCVEs_SeverityIsHigh(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Real Shodan format: vulns is an object keyed by CVE ID.
		w.Write([]byte(`{"ports":[22],"org":"Acme","os":"Linux","vulns":{"CVE-2021-44228":{"cvss":10.0},"CVE-2022-1234":{"cvss":9.8}}}`))
	})
	defer srv.Close()

	f := shodanLookup(context.Background(), client, "example.com", "1.2.3.4", "key")
	if f == nil {
		t.Fatal("expected finding with CVEs, got nil")
	}
	if f.Severity < finding.SeverityHigh {
		t.Errorf("Severity = %d; want >= High when CVEs present", f.Severity)
	}
	vulns, _ := f.Evidence["vulns"].([]string)
	if len(vulns) == 0 {
		t.Error("Evidence missing vulns field")
	}
}

// ── VirusTotal ────────────────────────────────────────────────────────────────

func TestVirusTotal_APIKeyInHeader(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "vtkey" {
			t.Errorf("x-apikey header = %q; want vtkey", r.Header.Get("x-apikey"))
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":5,"suspicious":0,"harmless":60},"reputation":-10}}}`))
	})
	defer srv.Close()

	f := virusTotalLookup(context.Background(), client, "evil.com", "vtkey")
	if f == nil {
		t.Fatal("expected finding for malicious domain, got nil")
	}
	if f.CheckID != finding.CheckVirusTotalReputation {
		t.Errorf("CheckID = %q; want %q", f.CheckID, finding.CheckVirusTotalReputation)
	}
}

func TestVirusTotal_CleanDomain_ReturnsNil(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":72},"reputation":0}}}`))
	})
	defer srv.Close()

	f := virusTotalLookup(context.Background(), client, "clean.com", "vtkey")
	if f != nil {
		t.Errorf("expected nil for clean VT domain, got %s", f.CheckID)
	}
}

func TestVirusTotal_Non200_ReturnsNil(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
	defer srv.Close()

	f := virusTotalLookup(context.Background(), client, "example.com", "badkey")
	if f != nil {
		t.Errorf("expected nil for 403, got %s", f.CheckID)
	}
}

// ── GreyNoise ─────────────────────────────────────────────────────────────────

func TestGreyNoise_APIKeyInHeader(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("key") != "gnkey" {
			t.Errorf("key header = %q; want gnkey", r.Header.Get("key"))
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ip":"1.2.3.4","noise":true,"riot":false,"classification":"malicious","name":"MalBot"}`))
	})
	defer srv.Close()

	f := greyNoiseLookup(context.Background(), client, "example.com", "1.2.3.4", "gnkey")
	if f == nil {
		t.Fatal("expected finding for malicious IP, got nil")
	}
	if f.CheckID != finding.CheckGreyNoiseContext {
		t.Errorf("CheckID = %q; want %q", f.CheckID, finding.CheckGreyNoiseContext)
	}
}

func TestGreyNoise_404_ReturnsNil(t *testing.T) {
	// 404 from GreyNoise means IP has no data — not an error.
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"message":"IP not found in dataset"}`))
	})
	defer srv.Close()

	f := greyNoiseLookup(context.Background(), client, "example.com", "1.2.3.4", "gnkey")
	if f != nil {
		t.Errorf("expected nil for GreyNoise 404, got %s", f.CheckID)
	}
}

func TestGreyNoise_RiotIP_ReturnsNil(t *testing.T) {
	// RIOT = "rule it out" — known benign infrastructure (e.g. Google DNS).
	// No finding should be emitted.
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ip":"8.8.8.8","noise":false,"riot":true,"classification":"benign","name":"Google Public DNS"}`))
	})
	defer srv.Close()

	f := greyNoiseLookup(context.Background(), client, "example.com", "8.8.8.8", "gnkey")
	if f != nil {
		t.Errorf("expected nil for RIOT/benign IP, got %s", f.CheckID)
	}
}

// ── Censys ────────────────────────────────────────────────────────────────────

func TestCensys_CredentialsSentAsBasicAuth(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "cid" || pass != "csecret" {
			t.Errorf("basic auth = %q:%q; want cid:csecret", user, pass)
		}
		w.WriteHeader(200)
		// Real Censys v2 format: asn is integer, name is string inside autonomous_system.
		w.Write([]byte(`{"result":{"ip":"1.2.3.4","autonomous_system":{"asn":12345,"name":"ExampleASN","bgp_prefix":"1.2.0.0/16"},"services":[{"port":443,"service_name":"HTTPS"}]}}`))
	})
	defer srv.Close()

	f := censysLookup(context.Background(), client, "example.com", "1.2.3.4", "cid", "csecret")
	if f == nil {
		t.Fatal("expected Censys finding, got nil")
	}
	if f.CheckID != finding.CheckCensysHostData {
		t.Errorf("CheckID = %q; want %q", f.CheckID, finding.CheckCensysHostData)
	}
}

func TestCensys_Non200_ReturnsNil(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429) // rate limit
	})
	defer srv.Close()

	f := censysLookup(context.Background(), client, "example.com", "1.2.3.4", "cid", "csecret")
	if f != nil {
		t.Errorf("expected nil for 429, got %s", f.CheckID)
	}
}

// ── SecurityTrails ────────────────────────────────────────────────────────────

func TestSecurityTrails_APIKeyInHeader(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apikey") != "stkey" {
			t.Errorf("apikey header = %q; want stkey", r.Header.Get("apikey"))
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"subdomains":["mail","vpn","dev"],"endpoint":"example.com"}`))
	})
	defer srv.Close()

	f := securityTrailsLookup(context.Background(), client, "example.com", "stkey")
	if f == nil {
		t.Fatal("expected SecurityTrails finding, got nil")
	}
}

func TestSecurityTrails_EmptySubdomains_ReturnsNil(t *testing.T) {
	client, srv := mockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"subdomains":[]}`))
	})
	defer srv.Close()

	f := securityTrailsLookup(context.Background(), client, "example.com", "stkey")
	if f != nil {
		t.Errorf("expected nil for empty subdomains, got %s", f.CheckID)
	}
}

// ── Scanner struct ─────────────────────────────────────────────────────────────

func TestNewWithKeys_FieldsSet(t *testing.T) {
	s := NewWithKeys("shodan", "vt", "st", "cid", "csec", "gn")
	if s.shodanKey != "shodan" {
		t.Errorf("shodanKey = %q; want shodan", s.shodanKey)
	}
	if s.virusTotalKey != "vt" {
		t.Errorf("virusTotalKey = %q; want vt", s.virusTotalKey)
	}
	if s.censysID != "cid" || s.censysSecret != "csec" {
		t.Errorf("censys = %q/%q; want cid/csec", s.censysID, s.censysSecret)
	}
	if s.greyNoiseKey != "gn" {
		t.Errorf("greyNoiseKey = %q; want gn", s.greyNoiseKey)
	}
	if s.securityTrailsKey != "st" {
		t.Errorf("securityTrailsKey = %q; want st", s.securityTrailsKey)
	}
}

func TestNew_EmptyKey(t *testing.T) {
	s := New("")
	if s.shodanKey != "" {
		t.Errorf("expected empty shodanKey, got %q", s.shodanKey)
	}
}
