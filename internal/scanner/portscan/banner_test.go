package portscan

import (
	"testing"

	"github.com/stormbane/beacon/internal/module"
)

func TestParseSSHVersion(t *testing.T) {
	tests := []struct {
		banner string
		want   string
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "OpenSSH_9.6p1"},
		{"SSH-2.0-dropbear_2022.83", "dropbear_2022.83"},
		{"SSH-1.99-Cisco-1.25", "Cisco-1.25"},
		{"SSH-2.0-libssh_0.9.6", "libssh_0.9.6"},
		{"not an ssh banner", ""},
		{"", ""},
		{"SSH-2.0-", ""},         // nothing after proto
		{"SSH-noversion", ""},    // missing second dash
	}

	for _, tt := range tests {
		if got := parseSSHVersion(tt.banner); got != tt.want {
			t.Errorf("parseSSHVersion(%q) = %q; want %q", tt.banner, got, tt.want)
		}
	}
}

func TestParseFTPVersion(t *testing.T) {
	tests := []struct {
		banner string
		want   string
	}{
		{"220 ProFTPD 1.3.6 Server (hostname)", "ProFTPD 1.3.6"},
		{"220 (vsFTPd 3.0.3)", "vsFTPd 3.0.3"},
		{"220 FileZilla Server 1.8.1", "FileZilla"}, // " Server " suffix is stripped by the parser
		{"220 Microsoft FTP Service", "Microsoft FTP Service"},
		{"220-Welcome to FTP", "Welcome to FTP"},
		{"530 Login incorrect", ""},   // not a 220 banner
		{"", ""},
	}

	for _, tt := range tests {
		if got := parseFTPVersion(tt.banner); got != tt.want {
			t.Errorf("parseFTPVersion(%q) = %q; want %q", tt.banner, got, tt.want)
		}
	}
}

func TestBuildPortList(t *testing.T) {
	surf := buildPortList(module.ScanSurface)
	deep := buildPortList(module.ScanDeep)

	if len(deep) <= len(surf) {
		t.Errorf("deep mode should have more ports than surface: deep=%d surf=%d", len(deep), len(surf))
	}

	// All critical ports must appear in both modes.
	surfPorts := make(map[int]bool, len(surf))
	for _, e := range surf {
		surfPorts[e.port] = true
	}
	for _, e := range criticalPorts {
		if !surfPorts[e.port] {
			t.Errorf("critical port %d missing from surface scan list", e.port)
		}
	}

	// Extended ports must appear in deep but not necessarily surface.
	deepPorts := make(map[int]bool, len(deep))
	for _, e := range deep {
		deepPorts[e.port] = true
	}
	for _, e := range extendedPorts {
		if !deepPorts[e.port] {
			t.Errorf("extended port %d missing from deep scan list", e.port)
		}
	}
}

func TestEmitPortServiceDiscoveredWebPort(t *testing.T) {
	f := EmitPortServiceDiscovered("example.com", 3000, "node-dev", "")
	if f == nil {
		t.Fatal("expected finding for web service port 3000, got nil")
	}
	if f.Evidence["port_asset"] != "example.com:3000" {
		t.Errorf("port_asset = %v; want example.com:3000", f.Evidence["port_asset"])
	}
}

func TestEmitPortServiceDiscoveredNonWebPort(t *testing.T) {
	// Port 22 (SSH) is not a web service port — should return nil.
	f := EmitPortServiceDiscovered("example.com", 22, "ssh", "SSH-2.0-OpenSSH_9.6")
	if f != nil {
		t.Errorf("expected nil for non-web port 22, got finding: %+v", f)
	}
}

func TestEmitPortServiceDiscoveredKnownPorts(t *testing.T) {
	// Spot-check a few critical web service ports.
	webPorts := []int{5601, 8080, 9090, 9200, 16686}
	for _, port := range webPorts {
		f := EmitPortServiceDiscovered("host.example.com", port, "service", "")
		if f == nil {
			t.Errorf("expected finding for web port %d, got nil", port)
		}
	}
}
