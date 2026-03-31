package libvirt_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/scanner/onprem/libvirt"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// hasCheckID returns true if the slice contains at least one finding with the
// given check ID.
func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

// countCheckID counts findings with the given check ID.
func countCheckID(findings []finding.Finding, id finding.CheckID) int {
	n := 0
	for _, f := range findings {
		if f.CheckID == id {
			n++
		}
	}
	return n
}

// libvirtAPI is a minimal router for the REST proxy mock.
type libvirtAPI struct {
	handlers map[string]http.HandlerFunc
}

func (a *libvirtAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := a.handlers[r.URL.Path]; ok {
		h(w, r)
		return
	}
	http.NotFound(w, r)
}

// jsonResponse writes v as JSON with status 200.
func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// healthyDomains returns a VM inventory with all secure settings.
func healthyDomains() []map[string]any {
	return []map[string]any{
		{
			"name": "secure-vm", "uuid": "aaa-111", "state": "running",
			"vcpus": 4, "memory_mb": 8192,
			"os":          map[string]any{"type": "hvm", "arch": "x86_64", "boot": "hd"},
			"features":    map[string]any{"secure_boot": true},
			"disk_format": "qcow2",
			"memballoon":  "virtio",
			"network_mode": "nat",
		},
	}
}

// healthyNetworks returns a network inventory with isolated mode.
func healthyNetworks() []map[string]any {
	return []map[string]any{
		{"name": "isolated-net", "mode": "isolated", "bridge": "virbr1", "dhcp": true},
	}
}

// healthyBaseHandlers returns handlers for a healthy libvirt host baseline:
// - VMs with secure boot, qcow2, virtio memballoon
// - Networks in isolated mode
func healthyBaseHandlers() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"/domains": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, healthyDomains())
		},
		"/networks": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, healthyNetworks())
		},
	}
}

// noPortDialFunc returns a dial function that always fails (port closed).
func noPortDialFunc() func(string, string, time.Duration) (net.Conn, error) {
	return func(_, _ string, _ time.Duration) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("connection refused")}
	}
}

// newTestScanner creates a Scanner pointing at the given httptest server with
// all TCP/TLS port checks disabled (ports closed).
func newTestScanner(ts *httptest.Server) *libvirt.Scanner {
	s := libvirt.New(libvirt.Config{
		Endpoint: "http://192.168.1.50:8080",
		Host:     "192.168.1.50",
	})
	s.SetBaseURL(ts.URL)
	s.SetDialFunc(noPortDialFunc())
	return s
}

// ---------------------------------------------------------------------------
// Scanner.Name
// ---------------------------------------------------------------------------

func TestScannerName(t *testing.T) {
	s := libvirt.New(libvirt.Config{})
	if got := s.Name(); got != "onprem/libvirt" {
		t.Errorf("Scanner.Name() = %q, want %q", got, "onprem/libvirt")
	}
}

// ---------------------------------------------------------------------------
// Run — no endpoint, no host → returns empty
// ---------------------------------------------------------------------------

func TestRun_NoEndpointNoHost(t *testing.T) {
	s := libvirt.New(libvirt.Config{})
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with no config, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Healthy host — no findings
// ---------------------------------------------------------------------------

func TestHealthyHost_NoFindings(t *testing.T) {
	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		for _, f := range findings {
			t.Logf("  unexpected finding: %s — %s", f.CheckID, f.Title)
		}
		t.Errorf("expected 0 findings for healthy host, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Check: TCP no auth (port 16509 open)
// ---------------------------------------------------------------------------

func TestTCPNoAuth_PortOpen_Finding(t *testing.T) {
	// Start a real TCP listener to simulate libvirt TCP port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create TCP listener: %v", err)
	}
	defer ln.Close()

	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := libvirt.New(libvirt.Config{
		Endpoint: "http://192.168.1.50:8080",
		Host:     "192.168.1.50",
	})
	s.SetBaseURL(ts.URL)

	// Override dial to route TCP port 16509 to our test listener,
	// and refuse all other connections (TLS port closed).
	tcpAddr := ln.Addr().String()
	s.SetDialFunc(func(network, address string, timeout time.Duration) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(address)
		if port == "16509" {
			return net.DialTimeout(network, tcpAddr, timeout)
		}
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("connection refused")}
	})

	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremLibvirtTCPNoAuth) {
		t.Error("expected CheckOnpremLibvirtTCPNoAuth when TCP port 16509 is open")
	}

	// Verify finding has ProofCommand and Evidence.
	for _, f := range findings {
		if f.CheckID == finding.CheckOnpremLibvirtTCPNoAuth {
			if f.ProofCommand == "" {
				t.Error("TCPNoAuth finding missing ProofCommand")
			}
			if f.Evidence == nil {
				t.Error("TCPNoAuth finding missing Evidence")
			}
			if f.Severity != finding.SeverityCritical {
				t.Errorf("TCPNoAuth severity = %v, want Critical", f.Severity)
			}
		}
	}
}

func TestTCPNoAuth_PortClosed_NoFinding(t *testing.T) {
	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts) // all ports closed
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremLibvirtTCPNoAuth) {
		t.Error("should not emit CheckOnpremLibvirtTCPNoAuth when TCP port is closed")
	}
}

// ---------------------------------------------------------------------------
// Check: TLS disabled (TCP open, TLS closed)
// ---------------------------------------------------------------------------

func TestTLSDisabled_TCPOpenTLSClosed_Finding(t *testing.T) {
	// TCP listener simulating port 16509 open.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create TCP listener: %v", err)
	}
	defer ln.Close()

	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := libvirt.New(libvirt.Config{
		Endpoint: "http://192.168.1.50:8080",
		Host:     "192.168.1.50",
	})
	s.SetBaseURL(ts.URL)

	tcpAddr := ln.Addr().String()
	s.SetDialFunc(func(network, address string, timeout time.Duration) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(address)
		if port == "16509" {
			return net.DialTimeout(network, tcpAddr, timeout)
		}
		// TLS port 16514 → refused
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("connection refused")}
	})

	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremLibvirtTLSDisabled) {
		t.Error("expected CheckOnpremLibvirtTLSDisabled when TCP is open but TLS is not")
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckOnpremLibvirtTLSDisabled {
			if f.ProofCommand == "" {
				t.Error("TLSDisabled finding missing ProofCommand")
			}
			if f.Severity != finding.SeverityHigh {
				t.Errorf("TLSDisabled severity = %v, want High", f.Severity)
			}
		}
	}
}

func TestTLSDisabled_BothOpen_NoFinding(t *testing.T) {
	// Both TCP and TLS listeners open.
	lnTCP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create TCP listener: %v", err)
	}
	defer lnTCP.Close()

	lnTLS, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer lnTLS.Close()

	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := libvirt.New(libvirt.Config{
		Endpoint: "http://192.168.1.50:8080",
		Host:     "192.168.1.50",
	})
	s.SetBaseURL(ts.URL)

	tcpAddr := lnTCP.Addr().String()
	tlsAddr := lnTLS.Addr().String()
	s.SetDialFunc(func(network, address string, timeout time.Duration) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(address)
		switch port {
		case "16509":
			return net.DialTimeout(network, tcpAddr, timeout)
		case "16514":
			return net.DialTimeout(network, tlsAddr, timeout)
		}
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("connection refused")}
	})

	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremLibvirtTLSDisabled) {
		t.Error("should not emit CheckOnpremLibvirtTLSDisabled when TLS port is also open")
	}
}

func TestTLSDisabled_TCPClosed_NoFinding(t *testing.T) {
	// When TCP is closed, we don't check TLS at all.
	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremLibvirtTLSDisabled) {
		t.Error("should not emit TLSDisabled when TCP is also closed")
	}
}

// ---------------------------------------------------------------------------
// Check: VM without Secure Boot
// ---------------------------------------------------------------------------

func TestVMNoSecureBoot_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/domains"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{
			{
				"name": "insecure-vm", "uuid": "bbb-222", "state": "running",
				"vcpus": 2, "memory_mb": 4096,
				"os":          map[string]any{"type": "hvm", "arch": "x86_64", "boot": "hd"},
				"features":    map[string]any{"secure_boot": false},
				"disk_format": "qcow2",
				"memballoon":  "virtio",
				"network_mode": "nat",
			},
		})
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremLibvirtVMNoSecureBoot) {
		t.Error("expected CheckOnpremLibvirtVMNoSecureBoot for VM without secure boot")
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckOnpremLibvirtVMNoSecureBoot {
			if f.ProofCommand == "" {
				t.Error("VMNoSecureBoot finding missing ProofCommand")
			}
			if f.Evidence == nil {
				t.Error("VMNoSecureBoot finding missing Evidence")
			}
			if f.Severity != finding.SeverityMedium {
				t.Errorf("VMNoSecureBoot severity = %v, want Medium", f.Severity)
			}
		}
	}
}

func TestVMSecureBoot_NoFinding(t *testing.T) {
	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremLibvirtVMNoSecureBoot) {
		t.Error("should not emit VMNoSecureBoot for VM with secure boot enabled")
	}
}

// ---------------------------------------------------------------------------
// Check: VM using raw disk format
// ---------------------------------------------------------------------------

func TestVMRawDisk_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/domains"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{
			{
				"name": "raw-vm", "uuid": "ccc-333", "state": "running",
				"vcpus": 2, "memory_mb": 4096,
				"os":          map[string]any{"type": "hvm", "arch": "x86_64", "boot": "hd"},
				"features":    map[string]any{"secure_boot": true},
				"disk_format": "raw",
				"memballoon":  "virtio",
				"network_mode": "nat",
			},
		})
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremLibvirtVMRawDisk) {
		t.Error("expected CheckOnpremLibvirtVMRawDisk for VM with raw disk format")
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckOnpremLibvirtVMRawDisk {
			if f.ProofCommand == "" {
				t.Error("VMRawDisk finding missing ProofCommand")
			}
			if f.Evidence == nil {
				t.Error("VMRawDisk finding missing Evidence")
			}
			if f.Severity != finding.SeverityLow {
				t.Errorf("VMRawDisk severity = %v, want Low", f.Severity)
			}
		}
	}
}

func TestVMQcow2Disk_NoFinding(t *testing.T) {
	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremLibvirtVMRawDisk) {
		t.Error("should not emit VMRawDisk for VM with qcow2 disk format")
	}
}

// ---------------------------------------------------------------------------
// Check: VM no memory balloon
// ---------------------------------------------------------------------------

func TestVMNoMemBalloon_None_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/domains"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{
			{
				"name": "no-balloon", "uuid": "ddd-444", "state": "running",
				"vcpus": 2, "memory_mb": 4096,
				"os":          map[string]any{"type": "hvm", "arch": "x86_64", "boot": "hd"},
				"features":    map[string]any{"secure_boot": true},
				"disk_format": "qcow2",
				"memballoon":  "none",
				"network_mode": "nat",
			},
		})
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremLibvirtVMNoMemBalloon) {
		t.Error("expected CheckOnpremLibvirtVMNoMemBalloon when memballoon is 'none'")
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckOnpremLibvirtVMNoMemBalloon {
			if f.ProofCommand == "" {
				t.Error("VMNoMemBalloon finding missing ProofCommand")
			}
			if f.Severity != finding.SeverityLow {
				t.Errorf("VMNoMemBalloon severity = %v, want Low", f.Severity)
			}
		}
	}
}

func TestVMNoMemBalloon_Empty_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/domains"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{
			{
				"name": "no-balloon-empty", "uuid": "eee-555", "state": "running",
				"vcpus": 2, "memory_mb": 4096,
				"os":          map[string]any{"type": "hvm", "arch": "x86_64", "boot": "hd"},
				"features":    map[string]any{"secure_boot": true},
				"disk_format": "qcow2",
				"memballoon":  "",
				"network_mode": "nat",
			},
		})
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremLibvirtVMNoMemBalloon) {
		t.Error("expected CheckOnpremLibvirtVMNoMemBalloon when memballoon is empty")
	}
}

func TestVMMemBalloonVirtio_NoFinding(t *testing.T) {
	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremLibvirtVMNoMemBalloon) {
		t.Error("should not emit VMNoMemBalloon when memballoon is 'virtio'")
	}
}

// ---------------------------------------------------------------------------
// Check: Network no isolation (NAT mode)
// ---------------------------------------------------------------------------

func TestNetNoIsolation_NAT_Finding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/networks"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{
			{"name": "default", "mode": "nat", "bridge": "virbr0", "dhcp": true},
		})
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremLibvirtNetNoIsolation) {
		t.Error("expected CheckOnpremLibvirtNetNoIsolation for NAT network")
	}

	for _, f := range findings {
		if f.CheckID == finding.CheckOnpremLibvirtNetNoIsolation {
			if f.ProofCommand == "" {
				t.Error("NetNoIsolation finding missing ProofCommand")
			}
			if f.Evidence == nil {
				t.Error("NetNoIsolation finding missing Evidence")
			}
			if f.Severity != finding.SeverityMedium {
				t.Errorf("NetNoIsolation severity = %v, want Medium", f.Severity)
			}
		}
	}
}

func TestNetNoIsolation_MultipleNAT_CountsEach(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/networks"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{
			{"name": "default", "mode": "nat", "bridge": "virbr0", "dhcp": true},
			{"name": "lab", "mode": "nat", "bridge": "virbr2", "dhcp": true},
		})
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := countCheckID(findings, finding.CheckOnpremLibvirtNetNoIsolation); got != 2 {
		t.Errorf("expected 2 NetNoIsolation findings for 2 NAT networks, got %d", got)
	}
}

func TestNetIsolated_NoFinding(t *testing.T) {
	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremLibvirtNetNoIsolation) {
		t.Error("should not emit NetNoIsolation for isolated-mode network")
	}
}

func TestNetRouted_NoFinding(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/networks"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{
			{"name": "routed-net", "mode": "route", "bridge": "virbr3", "dhcp": false},
		})
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremLibvirtNetNoIsolation) {
		t.Error("should not emit NetNoIsolation for routed-mode network")
	}
}

// ---------------------------------------------------------------------------
// Scan error — REST proxy returns error
// ---------------------------------------------------------------------------

func TestScanError_DomainsFail(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/domains"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error")) //nolint:errcheck
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremLibvirtScanError) {
		t.Error("expected CheckOnpremLibvirtScanError when domains endpoint fails")
	}
}

func TestScanError_NetworksFail(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/networks"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error")) //nolint:errcheck
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckOnpremLibvirtScanError) {
		t.Error("expected CheckOnpremLibvirtScanError when networks endpoint fails")
	}
}

// ---------------------------------------------------------------------------
// Multiple VMs — each generates independent findings
// ---------------------------------------------------------------------------

func TestMultipleVMs_IndependentFindings(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/domains"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{
			{
				"name": "vm-1", "uuid": "111-aaa", "state": "running",
				"vcpus": 2, "memory_mb": 4096,
				"os":          map[string]any{"type": "hvm", "arch": "x86_64", "boot": "hd"},
				"features":    map[string]any{"secure_boot": false},
				"disk_format": "raw",
				"memballoon":  "none",
				"network_mode": "nat",
			},
			{
				"name": "vm-2", "uuid": "222-bbb", "state": "running",
				"vcpus": 4, "memory_mb": 8192,
				"os":          map[string]any{"type": "hvm", "arch": "x86_64", "boot": "hd"},
				"features":    map[string]any{"secure_boot": true},
				"disk_format": "qcow2",
				"memballoon":  "virtio",
				"network_mode": "nat",
			},
		})
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// vm-1: no secure boot, raw disk, no memballoon = 3 findings
	// vm-2: all healthy = 0 findings
	if got := countCheckID(findings, finding.CheckOnpremLibvirtVMNoSecureBoot); got != 1 {
		t.Errorf("expected 1 VMNoSecureBoot finding, got %d", got)
	}
	if got := countCheckID(findings, finding.CheckOnpremLibvirtVMRawDisk); got != 1 {
		t.Errorf("expected 1 VMRawDisk finding, got %d", got)
	}
	if got := countCheckID(findings, finding.CheckOnpremLibvirtVMNoMemBalloon); got != 1 {
		t.Errorf("expected 1 VMNoMemBalloon finding, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// All findings have Scanner, Asset, and DiscoveredAt set
// ---------------------------------------------------------------------------

func TestFindingFields_AllPopulated(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/domains"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{
			{
				"name": "test-vm", "uuid": "fff-666", "state": "running",
				"vcpus": 1, "memory_mb": 1024,
				"os":          map[string]any{"type": "hvm", "arch": "x86_64", "boot": "hd"},
				"features":    map[string]any{"secure_boot": false},
				"disk_format": "raw",
				"memballoon":  "none",
				"network_mode": "nat",
			},
		})
	}
	handlers["/networks"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{
			{"name": "default", "mode": "nat", "bridge": "virbr0", "dhcp": true},
		})
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings but got none")
	}

	for _, f := range findings {
		if f.Scanner != "onprem/libvirt" {
			t.Errorf("finding %s has Scanner=%q, want %q", f.CheckID, f.Scanner, "onprem/libvirt")
		}
		if f.Asset != "kvm.local" {
			t.Errorf("finding %s has Asset=%q, want %q", f.CheckID, f.Asset, "kvm.local")
		}
		if f.DiscoveredAt.IsZero() {
			t.Errorf("finding %s has zero DiscoveredAt", f.CheckID)
		}
		if f.CheckID != finding.CheckOnpremLibvirtScanError {
			if f.ProofCommand == "" {
				t.Errorf("finding %s missing ProofCommand", f.CheckID)
			}
			if f.Evidence == nil {
				t.Errorf("finding %s missing Evidence", f.CheckID)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Host derivation from Endpoint
// ---------------------------------------------------------------------------

func TestHostDerivedFromEndpoint(t *testing.T) {
	// TCP listener to simulate open port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create TCP listener: %v", err)
	}
	defer ln.Close()

	api := &libvirtAPI{handlers: healthyBaseHandlers()}
	ts := httptest.NewServer(api)
	defer ts.Close()

	// No explicit Host — it should be derived from Endpoint.
	s := libvirt.New(libvirt.Config{
		Endpoint: "http://10.0.0.5:8080",
	})
	s.SetBaseURL(ts.URL)

	tcpAddr := ln.Addr().String()
	s.SetDialFunc(func(network, address string, timeout time.Duration) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(address)
		if port == "16509" {
			return net.DialTimeout(network, tcpAddr, timeout)
		}
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("connection refused")}
	})

	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect TCP open because Host was derived from Endpoint.
	if !hasCheckID(findings, finding.CheckOnpremLibvirtTCPNoAuth) {
		t.Error("expected TCPNoAuth finding when Host is derived from Endpoint")
	}
}

// ---------------------------------------------------------------------------
// Empty VM list — no domain findings
// ---------------------------------------------------------------------------

func TestEmptyDomainList_NoFindings(t *testing.T) {
	handlers := healthyBaseHandlers()
	handlers["/domains"] = func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, []map[string]any{})
	}

	api := &libvirtAPI{handlers: handlers}
	ts := httptest.NewServer(api)
	defer ts.Close()

	s := newTestScanner(ts)
	findings, err := s.Run(context.Background(), "kvm.local", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		switch f.CheckID {
		case finding.CheckOnpremLibvirtVMNoSecureBoot,
			finding.CheckOnpremLibvirtVMRawDisk,
			finding.CheckOnpremLibvirtVMNoMemBalloon:
			t.Errorf("should not emit VM finding %s with empty domain list", f.CheckID)
		}
	}
}
