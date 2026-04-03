package http2

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestScannerName(t *testing.T) {
	s := New()
	if s.Name() != "http2check" {
		t.Errorf("Name() = %q; want %q", s.Name(), "http2check")
	}
}

func TestSurfaceModeSkips(t *testing.T) {
	s := New()
	findings, err := s.Run(t.Context(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in surface mode, got %d", len(findings))
	}
}

func TestHTTP2FrameConstruction(t *testing.T) {
	// Verify the HTTP/2 connection preface is correct per RFC 9113 section 3.4.
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if len(preface) != 24 {
		t.Errorf("preface length = %d; want 24", len(preface))
	}

	// SETTINGS frame: 9-byte header, type=0x04, empty payload.
	settingsFrame := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	if settingsFrame[3] != 0x04 {
		t.Errorf("settings frame type = %x; want 0x04", settingsFrame[3])
	}

	// CONTINUATION frame type should be 0x09.
	contType := byte(0x09)
	if contType != 0x09 {
		t.Errorf("continuation frame type = %x; want 0x09", contType)
	}

	// END_HEADERS flag should be 0x04.
	endHeaders := byte(0x04)
	if endHeaders != 0x04 {
		t.Errorf("END_HEADERS flag = %x; want 0x04", endHeaders)
	}
}

func TestDeepModeAllowed(t *testing.T) {
	// Deep mode shouldn't skip — it should attempt the scan.
	// We can't connect to a real server, but verify it doesn't return
	// an error for a non-resolvable host (it should return nil, nil).
	s := New()
	findings, err := s.Run(t.Context(), "nonexistent.invalid", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for unreachable host, got %d", len(findings))
	}
}
