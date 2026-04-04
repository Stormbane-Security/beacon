package bigip

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestDecodeBigIPCookie(t *testing.T) {
	tests := []struct {
		value string
		ip    string
		port  int
		ok    bool
	}{
		// 10.1.1.100 = 100 + 1*256 + 1*65536 + 10*16777216 = 167837028
		// port 8080 = (80<<8)|31 = 20511 ... let me compute correctly
		// 10.1.1.100 LE: 100 | (1<<8) | (1<<16) | (10<<24) = 100+256+65536+167772160 = 167838052
		// port 80: (80<<8)|(0) = 20480... no.
		// Port encoding: bytes swapped. Port 80 = 0x0050.
		// Swapped: 0x5000 = 20480.
		{"167838052.20480.0000", "100.1.1.10", 80, true},
		// 192.168.1.1 LE: 1 | (1<<8) | (168<<16) | (192<<24) = 1+256+11010048+3221225472 = 3232235777
		// Port 443 = 0x01BB. Swapped: 0xBB01 = 47873
		{"3232235777.47873.0000", "1.1.168.192", 443, true},
		// Invalid
		{"notanumber.123.0", "", 0, false},
		{"", "", 0, false},
	}

	for _, tc := range tests {
		ip, port, ok := decodeBigIPCookie(tc.value)
		if ok != tc.ok {
			t.Errorf("decodeBigIPCookie(%q) ok=%v, want %v", tc.value, ok, tc.ok)
			continue
		}
		if ok && (ip != tc.ip || port != tc.port) {
			t.Errorf("decodeBigIPCookie(%q) = %s:%d, want %s:%d", tc.value, ip, port, tc.ip, tc.port)
		}
	}
}

func TestBigIPCookieDetection(t *testing.T) {
	// Server that sets a BIGipServer cookie.
	// Encode 10.0.0.1 port 80:
	// IP: 1 | (0<<8) | (0<<16) | (10<<24) = 167772161
	// Port 80: swap bytes = 20480
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "BIGipServerpool_web",
			Value: "167772161.20480.0000",
		})
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "OK")
	}))
	defer srv.Close()

	s := New()
	asset := srv.Listener.Addr().String()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected BIG-IP cookie finding, got none")
	}
	if findings[0].CheckID != "lb.bigip_cookie_leak" {
		t.Errorf("expected lb.bigip_cookie_leak, got %s", findings[0].CheckID)
	}
	ev := findings[0].Evidence
	if ev["decoded_ip"] != "1.0.0.10" {
		t.Errorf("expected decoded IP 1.0.0.10, got %v", ev["decoded_ip"])
	}
	if ev["decoded_port"] != 80 {
		t.Errorf("expected decoded port 80, got %v", ev["decoded_port"])
	}
}

func TestNoBigIPCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "OK")
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}
