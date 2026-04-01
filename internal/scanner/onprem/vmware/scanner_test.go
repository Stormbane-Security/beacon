package vmware_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/onprem/vmware"
)

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

// vCenterMock builds a mock vCenter REST API server.
type vCenterMock struct {
	Hosts      []map[string]any
	VMs        []map[string]any
	VMDetails  map[string]map[string]any
	Datastores []map[string]any
	AuthFail   bool
}

func (m *vCenterMock) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication endpoint.
		if r.URL.Path == "/api/session" && r.Method == http.MethodPost {
			if m.AuthFail {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`"test-session-token"`))
			return
		}

		// Require session token for all other endpoints.
		token := r.Header.Get("vmware-api-session-id")
		if token == "" {
			http.Error(w, "missing session", http.StatusUnauthorized)
			return
		}

		switch {
		case r.URL.Path == "/api/vcenter/host" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(m.Hosts)

		case strings.HasPrefix(r.URL.Path, "/api/vcenter/host/") && r.Method == http.MethodGet:
			hostID := strings.TrimPrefix(r.URL.Path, "/api/vcenter/host/")
			for _, h := range m.Hosts {
				if h["host"] == hostID {
					json.NewEncoder(w).Encode(h)
					return
				}
			}
			http.NotFound(w, r)

		case r.URL.Path == "/api/vcenter/vm" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(m.VMs)

		case strings.HasSuffix(r.URL.Path, "/snapshots"):
			vmID := strings.TrimPrefix(r.URL.Path, "/api/vcenter/vm/")
			vmID = strings.TrimSuffix(vmID, "/snapshots")
			if detail, ok := m.VMDetails[vmID]; ok {
				if snaps, ok := detail["snapshots"]; ok {
					json.NewEncoder(w).Encode(snaps)
					return
				}
			}
			json.NewEncoder(w).Encode([]any{})

		case strings.HasPrefix(r.URL.Path, "/api/vcenter/vm/") && r.Method == http.MethodGet:
			vmID := strings.TrimPrefix(r.URL.Path, "/api/vcenter/vm/")
			if detail, ok := m.VMDetails[vmID]; ok {
				json.NewEncoder(w).Encode(detail)
				return
			}
			http.NotFound(w, r)

		case r.URL.Path == "/api/vcenter/datastore" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(m.Datastores)

		default:
			http.NotFound(w, r)
		}
	}
}

func runScanner(t *testing.T, ts *httptest.Server, scanType module.ScanType) ([]finding.Finding, error) {
	t.Helper()
	cfg := vmware.Config{
		Endpoint:      ts.URL,
		Username:      "admin",
		Password:      "password",
		SkipTLSVerify: false, // test server is plain HTTP
	}
	s := vmware.New(cfg, ts.Client())
	asset := strings.TrimPrefix(ts.URL, "http://")
	return s.Run(context.Background(), asset, scanType)
}

// --------------------------------------------------------------------------
// Surface mode: scanner is deep-only
// --------------------------------------------------------------------------

func TestSurfaceMode_ReturnsNil(t *testing.T) {
	mock := &vCenterMock{}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode, got %d", len(findings))
	}
}

// --------------------------------------------------------------------------
// Authentication failure: scan error finding
// --------------------------------------------------------------------------

func TestAuthFailure_EmitsScanError(t *testing.T) {
	mock := &vCenterMock{AuthFail: true}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareScanError) {
		t.Error("expected CheckOnpremVMwareScanError when authentication fails")
	}
}

// --------------------------------------------------------------------------
// ESXi SSH enabled
// --------------------------------------------------------------------------

func TestESXiSSH_Detected(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":             "host-1",
				"name":             "esxi-prod-01",
				"connection_state": "CONNECTED",
				"power_state":      "POWERED_ON",
				"ssh_enabled":      true,
				"lockdown_mode":    "NORMAL",
			},
		},
		VMs:        []map[string]any{},
		VMDetails:  map[string]map[string]any{},
		Datastores: []map[string]any{},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareESXiSSH) {
		t.Error("expected CheckOnpremVMwareESXiSSH when SSH is enabled on ESXi host")
	}
}

// --------------------------------------------------------------------------
// ESXi Shell enabled
// --------------------------------------------------------------------------

func TestESXiShell_Detected(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":             "host-2",
				"name":             "esxi-prod-02",
				"connection_state": "CONNECTED",
				"power_state":      "POWERED_ON",
				"shell_running":    true,
				"lockdown_mode":    "NORMAL",
			},
		},
		VMs:        []map[string]any{},
		VMDetails:  map[string]map[string]any{},
		Datastores: []map[string]any{},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareESXiShell) {
		t.Error("expected CheckOnpremVMwareESXiShell when ESXi Shell is running")
	}
}

// --------------------------------------------------------------------------
// No lockdown mode
// --------------------------------------------------------------------------

func TestNoLockdown_Detected(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":             "host-3",
				"name":             "esxi-dev-01",
				"connection_state": "CONNECTED",
				"power_state":      "POWERED_ON",
				"lockdown_mode":    "DISABLED",
			},
		},
		VMs:        []map[string]any{},
		VMDetails:  map[string]map[string]any{},
		Datastores: []map[string]any{},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareNoLockdown) {
		t.Error("expected CheckOnpremVMwareNoLockdown when lockdown mode is DISABLED")
	}
}

// --------------------------------------------------------------------------
// VM without VMware Tools
// --------------------------------------------------------------------------

func TestVMNoTools_Detected(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":          "host-1",
				"name":          "esxi-01",
				"lockdown_mode": "NORMAL",
			},
		},
		VMs: []map[string]any{
			{"vm": "vm-1", "name": "web-server-01", "power_state": "POWERED_ON"},
		},
		VMDetails: map[string]map[string]any{
			"vm-1": {
				"name": "web-server-01",
				"guest": map[string]any{
					"tools_status": "toolsNotInstalled",
				},
				"snapshots": []any{map[string]any{"id": "snap-1"}},
			},
		},
		Datastores: []map[string]any{},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareVMNoTools) {
		t.Error("expected CheckOnpremVMwareVMNoTools when tools_status is toolsNotInstalled")
	}
}

// --------------------------------------------------------------------------
// VM with copy/paste enabled
// --------------------------------------------------------------------------

func TestVMCopyPaste_Detected(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":          "host-1",
				"name":          "esxi-01",
				"lockdown_mode": "NORMAL",
			},
		},
		VMs: []map[string]any{
			{"vm": "vm-2", "name": "dev-box", "power_state": "POWERED_ON"},
		},
		VMDetails: map[string]map[string]any{
			"vm-2": {
				"name": "dev-box",
				"guest": map[string]any{
					"tools_status": "toolsOk",
				},
				"extra_config": []map[string]any{
					{"key": "isolation.tools.copy.disable", "value": "FALSE"},
					{"key": "isolation.tools.paste.disable", "value": "FALSE"},
				},
				"snapshots": []any{map[string]any{"id": "snap-1"}},
			},
		},
		Datastores: []map[string]any{},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareVMCopyPaste) {
		t.Error("expected CheckOnpremVMwareVMCopyPaste when copy/paste is enabled")
	}
}

// --------------------------------------------------------------------------
// VM with disk shrink enabled
// --------------------------------------------------------------------------

func TestVMDiskShrink_Detected(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":          "host-1",
				"name":          "esxi-01",
				"lockdown_mode": "NORMAL",
			},
		},
		VMs: []map[string]any{
			{"vm": "vm-3", "name": "db-server", "power_state": "POWERED_ON"},
		},
		VMDetails: map[string]map[string]any{
			"vm-3": {
				"name": "db-server",
				"guest": map[string]any{
					"tools_status": "toolsOk",
				},
				"extra_config": []map[string]any{
					{"key": "isolation.tools.diskShrink.disable", "value": "FALSE"},
				},
				"snapshots": []any{map[string]any{"id": "snap-1"}},
			},
		},
		Datastores: []map[string]any{},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareVMDiskShrink) {
		t.Error("expected CheckOnpremVMwareVMDiskShrink when disk shrink is enabled")
	}
}

// --------------------------------------------------------------------------
// VM with drag-drop enabled
// --------------------------------------------------------------------------

func TestVMDragDrop_Detected(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":          "host-1",
				"name":          "esxi-01",
				"lockdown_mode": "NORMAL",
			},
		},
		VMs: []map[string]any{
			{"vm": "vm-4", "name": "jumpbox", "power_state": "POWERED_ON"},
		},
		VMDetails: map[string]map[string]any{
			"vm-4": {
				"name": "jumpbox",
				"guest": map[string]any{
					"tools_status": "toolsOk",
				},
				"extra_config": []map[string]any{
					{"key": "isolation.tools.dnd.disable", "value": "FALSE"},
				},
				"snapshots": []any{map[string]any{"id": "snap-1"}},
			},
		},
		Datastores: []map[string]any{},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareVMDragDrop) {
		t.Error("expected CheckOnpremVMwareVMDragDrop when drag-drop is enabled")
	}
}

// --------------------------------------------------------------------------
// VM with no snapshots
// --------------------------------------------------------------------------

func TestVMNoSnapshot_Detected(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":          "host-1",
				"name":          "esxi-01",
				"lockdown_mode": "NORMAL",
			},
		},
		VMs: []map[string]any{
			{"vm": "vm-5", "name": "app-server", "power_state": "POWERED_ON"},
		},
		VMDetails: map[string]map[string]any{
			"vm-5": {
				"name": "app-server",
				"guest": map[string]any{
					"tools_status": "toolsOk",
				},
				"snapshots": []any{},
			},
		},
		Datastores: []map[string]any{},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareVMNoSnapshot) {
		t.Error("expected CheckOnpremVMwareVMNoSnapshot when VM has no snapshots")
	}
}

// --------------------------------------------------------------------------
// Datastore without encryption
// --------------------------------------------------------------------------

func TestDatastoreNoEncrypt_Detected(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":          "host-1",
				"name":          "esxi-01",
				"lockdown_mode": "NORMAL",
			},
		},
		VMs:       []map[string]any{},
		VMDetails: map[string]map[string]any{},
		Datastores: []map[string]any{
			{"datastore": "ds-1", "name": "vmfs-prod", "type": "VMFS"},
		},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareDatastoreNoEncrypt) {
		t.Error("expected CheckOnpremVMwareDatastoreNoEncrypt for VMFS datastore")
	}
}

// --------------------------------------------------------------------------
// vSAN datastore: should NOT trigger encryption finding
// --------------------------------------------------------------------------

func TestDatastoreVSAN_NoFinding(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":          "host-1",
				"name":          "esxi-01",
				"lockdown_mode": "NORMAL",
			},
		},
		VMs:       []map[string]any{},
		VMDetails: map[string]map[string]any{},
		Datastores: []map[string]any{
			{"datastore": "ds-2", "name": "vsan-cluster", "type": "vsan"},
		},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremVMwareDatastoreNoEncrypt) {
		t.Error("vSAN datastore should not trigger CheckOnpremVMwareDatastoreNoEncrypt")
	}
}

// --------------------------------------------------------------------------
// Outdated ESXi version
// --------------------------------------------------------------------------

func TestOutdatedVersion_Detected(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":          "host-1",
				"name":          "esxi-old",
				"lockdown_mode": "NORMAL",
				"version":       "6.5.0",
			},
		},
		VMs:        []map[string]any{},
		VMDetails:  map[string]map[string]any{},
		Datastores: []map[string]any{},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareOutdatedVersion) {
		t.Error("expected CheckOnpremVMwareOutdatedVersion for ESXi 6.5.0")
	}
}

// --------------------------------------------------------------------------
// Healthy environment: no findings except lockdown (disabled by default in mock)
// --------------------------------------------------------------------------

func TestHealthyEnvironment_MinimalFindings(t *testing.T) {
	mock := &vCenterMock{
		Hosts: []map[string]any{
			{
				"host":          "host-1",
				"name":          "esxi-secure",
				"lockdown_mode": "NORMAL",
				"version":       "8.0.2",
			},
		},
		VMs: []map[string]any{
			{"vm": "vm-1", "name": "secure-vm", "power_state": "POWERED_ON"},
		},
		VMDetails: map[string]map[string]any{
			"vm-1": {
				"name": "secure-vm",
				"guest": map[string]any{
					"tools_status": "toolsOk",
				},
				"snapshots": []any{map[string]any{"id": "snap-1"}},
			},
		},
		Datastores: []map[string]any{
			{"datastore": "ds-1", "name": "vsan-prod", "type": "vsan"},
		},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not have critical findings.
	if hasCheckID(findings, finding.CheckOnpremVMwareESXiSSH) {
		t.Error("healthy environment should not have SSH finding")
	}
	if hasCheckID(findings, finding.CheckOnpremVMwareESXiShell) {
		t.Error("healthy environment should not have Shell finding")
	}
	if hasCheckID(findings, finding.CheckOnpremVMwareOutdatedVersion) {
		t.Error("healthy environment should not have outdated version finding")
	}
}

// --------------------------------------------------------------------------
// ProofCommand is set on all findings
// --------------------------------------------------------------------------

func TestAllFindings_HaveProofCommand(t *testing.T) {
	mock := &vCenterMock{
		AuthFail: true,
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.ProofCommand == "" {
			t.Errorf("finding %s must have ProofCommand set", f.CheckID)
		}
		if f.Evidence == nil {
			t.Errorf("finding %s must have Evidence set", f.CheckID)
		}
	}
}

// --------------------------------------------------------------------------
// Context cancellation: no panic
// --------------------------------------------------------------------------

func TestContextCancelled_NoPanic(t *testing.T) {
	mock := &vCenterMock{}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := vmware.Config{
		Endpoint: ts.URL,
		Username: "admin",
		Password: "password",
	}
	s := vmware.New(cfg, ts.Client())
	_, _ = s.Run(ctx, "test-host", module.ScanDeep) // must not panic
}

// --------------------------------------------------------------------------
// SkipTLSVerify triggers default certs finding
// --------------------------------------------------------------------------

func TestSkipTLSVerify_DefaultCertsFinding(t *testing.T) {
	mock := &vCenterMock{
		Hosts:      []map[string]any{},
		VMs:        []map[string]any{},
		VMDetails:  map[string]map[string]any{},
		Datastores: []map[string]any{},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	cfg := vmware.Config{
		Endpoint:      ts.URL,
		Username:      "admin",
		Password:      "password",
		SkipTLSVerify: true,
	}
	s := vmware.New(cfg, ts.Client())
	asset := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), asset, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremVMwareDefaultCerts) {
		t.Error("expected CheckOnpremVMwareDefaultCerts when SkipTLSVerify is true")
	}
}
