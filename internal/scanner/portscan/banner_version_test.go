package portscan_test

// Tests for SSH and FTP banner version extraction.
// Uses the exported test surface via the existing test package.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/portscan"
)

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ── SSH banner version ────────────────────────────────────────────────────────

// TestSSHVersionInFinding verifies that an SSH banner's software identifier is
// stored in the finding evidence under "ssh_software".
func TestSSHVersionInFinding(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:22")
	if err != nil {
		t.Skipf("cannot bind port 22: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"))
			conn.Close()
		}
	}()

	s := portscan.New()
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

// TestSSHVersionDropbear verifies dropbear banner parsing.
func TestSSHVersionDropbear(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:22")
	if err != nil {
		t.Skipf("cannot bind port 22: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-dropbear_2022.83\r\n"))
			conn.Close()
		}
	}()

	s := portscan.New()
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

// TestSSHNoBannerNoSoftwareKey verifies that when no SSH banner is received
// the finding is still emitted but without an ssh_software key.
func TestSSHNoBannerNoSoftwareKey(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:22")
	if err != nil {
		t.Skipf("cannot bind port 22: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Close immediately — no banner
			conn.Close()
		}
	}()

	s := portscan.New()
	findings, _ := s.Run(testCtx(t), "127.0.0.1", module.ScanSurface)
	for _, f := range findings {
		if f.CheckID == finding.CheckPortSSHExposed {
			if _, ok := f.Evidence["ssh_software"]; ok {
				t.Error("ssh_software should be absent when no banner received")
			}
			return
		}
	}
	t.Error("expected CheckPortSSHExposed finding even with no banner")
}

// ── FTP banner version ────────────────────────────────────────────────────────

// TestFTPVersionInFinding verifies that an FTP 220 banner's software is stored
// in finding evidence under "ftp_software".
func TestFTPVersionInFinding(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:21")
	if err != nil {
		t.Skipf("cannot bind port 21: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("220 ProFTPD 1.3.6 Server (hostname.example.com)\r\n"))
			conn.Close()
		}
	}()

	s := portscan.New()
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
