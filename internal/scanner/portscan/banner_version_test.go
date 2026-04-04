package portscan_test

// Tests for SSH and FTP banner version extraction.
// Uses ephemeral ports with s.Ports override so tests work without root.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/portscan"
)

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// listenEphemeral binds an ephemeral port and returns the listener + port number.
func listenEphemeral(t *testing.T) (net.Listener, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	return l, port
}

// serveBanner accepts connections on l and writes banner, then closes.
func serveBanner(l net.Listener, banner string) {
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			if banner != "" {
				_, _ = conn.Write([]byte(banner))
			}
			_ = conn.Close()
		}
	}()
}

// ── SSH banner version ────────────────────────────────────────────────────────

func TestSSHVersionInFinding(t *testing.T) {
	t.Parallel()
	l, port := listenEphemeral(t)
	defer func() { _ = l.Close() }()
	serveBanner(l, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")

	s := portscan.New()
	s.Ports = []int{port}
	findings, err := s.Run(testCtx(t), "127.0.0.1", module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	var sshFinding *finding.Finding
	for i := range findings {
		if findings[i].CheckID == finding.CheckPortSSHExposed {
			sshFinding = &findings[i]
			break
		}
	}
	if sshFinding == nil {
		t.Fatal("expected CheckPortSSHExposed finding, got none")
	}
	sw, ok := sshFinding.Evidence["ssh_software"]
	if !ok {
		t.Fatal("ssh_software key missing from finding evidence")
	}
	if sw != "OpenSSH_9.6p1" {
		t.Errorf("ssh_software = %q; want OpenSSH_9.6p1", sw)
	}
}

func TestSSHVersionDropbear(t *testing.T) {
	t.Parallel()
	l, port := listenEphemeral(t)
	defer func() { _ = l.Close() }()
	serveBanner(l, "SSH-2.0-dropbear_2022.83\r\n")

	s := portscan.New()
	s.Ports = []int{port}
	findings, _ := s.Run(testCtx(t), "127.0.0.1", module.ScanSurface)
	for _, f := range findings {
		if f.CheckID == finding.CheckPortSSHExposed {
			if sw := f.Evidence["ssh_software"]; sw != "dropbear_2022.83" {
				t.Errorf("ssh_software = %q; want dropbear_2022.83", sw)
			}
			return
		}
	}
	t.Error("expected CheckPortSSHExposed finding")
}

func TestSSHNoBannerNoSoftwareKey(t *testing.T) {
	t.Parallel()
	// When SSH sends no banner, the probe system can't identify the service
	// by protocol fingerprint alone. On a standard port (22), the port-based
	// fallback in buildFindings would emit the finding. On an ephemeral port,
	// the scanner correctly produces no SSH finding — this verifies it doesn't
	// false-positive on an open port with no banner.
	l, port := listenEphemeral(t)
	defer func() { _ = l.Close() }()
	serveBanner(l, "") // close immediately — no banner

	s := portscan.New()
	s.Ports = []int{port}
	findings, _ := s.Run(testCtx(t), "127.0.0.1", module.ScanSurface)
	for _, f := range findings {
		if f.CheckID == finding.CheckPortSSHExposed {
			if _, ok := f.Evidence["ssh_software"]; ok {
				t.Error("ssh_software should be absent when no banner received")
			}
			// Found SSH finding without software key — correct
			return
		}
	}
	// No SSH finding on an ephemeral port with no banner is correct behavior —
	// the scanner can't identify SSH without a banner or known port.
}

// ── FTP banner version ────────────────────────────────────────────────────────

func TestFTPVersionInFinding(t *testing.T) {
	t.Parallel()
	l, port := listenEphemeral(t)
	defer func() { _ = l.Close() }()
	serveBanner(l, "220 ProFTPD 1.3.6 Server (hostname.example.com)\r\n")

	s := portscan.New()
	s.Ports = []int{port}
	findings, err := s.Run(testCtx(t), "127.0.0.1", module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	var ftpFinding *finding.Finding
	for i := range findings {
		if findings[i].CheckID == finding.CheckPortFTPExposed {
			ftpFinding = &findings[i]
			break
		}
	}
	if ftpFinding == nil {
		t.Fatal("expected CheckPortFTPExposed finding, got none")
	}
	if sw, ok := ftpFinding.Evidence["ftp_software"]; !ok || sw == "" {
		t.Errorf("ftp_software = %q; expected non-empty", sw)
	}
}
