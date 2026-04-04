package nas_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/onprem/nas"
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

// --------------------------------------------------------------------------
// Mock NAS server builders
// --------------------------------------------------------------------------

// synologyMock creates a mock Synology DSM server.
type synologyMock struct {
	DSMInfo       map[string]any
	Shares        map[string]any
	Snapshots     map[string]any
	ISCSITargets  map[string]any
	AuthSuccess   bool
}

func defaultSynologyMock() *synologyMock {
	return &synologyMock{
		DSMInfo: map[string]any{
			"data": map[string]any{
				"version_string": "7.2.1-69057",
				"model":          "DS920+",
				"smb_enabled":    true,
				"smb1_enabled":   false,
				"ssh_enabled":    false,
			},
			"success": true,
		},
		Shares: map[string]any{
			"data": map[string]any{
				"shares": []any{},
			},
			"success": true,
		},
		Snapshots: map[string]any{
			"data": map[string]any{
				"snapshots": []any{map[string]any{"id": 1}},
				"total":     1,
			},
			"success": true,
		},
		ISCSITargets: map[string]any{
			"data": map[string]any{
				"targets": []any{},
			},
			"success": true,
		},
		AuthSuccess: false,
	}
}

func (m *synologyMock) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		api := q.Get("api")

		switch {
		// Detection endpoint.
		case strings.Contains(r.URL.Path, "query.cgi") && q.Get("method") == "query":
			json.NewEncoder(w).Encode(map[string]any{
				"data":    map[string]any{"SYNO.API.Auth": map[string]any{"path": "auth.cgi"}},
				"success": true,
			})

		// Auth endpoint.
		case strings.Contains(r.URL.Path, "auth.cgi") && api == "SYNO.API.Auth":
			if m.AuthSuccess {
				json.NewEncoder(w).Encode(map[string]any{"success": true})
			} else {
				json.NewEncoder(w).Encode(map[string]any{"success": false})
			}

		// DSM info.
		case api == "SYNO.DSM.Info":
			json.NewEncoder(w).Encode(m.DSMInfo)

		// Shares.
		case api == "SYNO.FileStation.List":
			json.NewEncoder(w).Encode(m.Shares)

		// Snapshots.
		case api == "SYNO.Snapshot.Replication.List":
			json.NewEncoder(w).Encode(m.Snapshots)

		// iSCSI.
		case api == "SYNO.ISCSIServer.Target.List":
			json.NewEncoder(w).Encode(m.ISCSITargets)

		default:
			http.NotFound(w, r)
		}
	}
}

// truenasMock creates a mock TrueNAS server.
type truenasMock struct {
	SystemInfo    map[string]any
	SMBShares     []map[string]any
	NFSShares     []map[string]any
	SMBConfig     map[string]any
	SSHConfig     map[string]any
	ISCSITargets  []map[string]any
	SnapshotTasks []any
	AuthSuccess   bool
}

func defaultTrueNASMock() *truenasMock {
	return &truenasMock{
		SystemInfo: map[string]any{
			"version":  "TrueNAS-SCALE-24.04",
			"hostname": "truenas-prod",
		},
		SMBShares:     []map[string]any{},
		NFSShares:     []map[string]any{},
		SMBConfig:     map[string]any{"enable_smb1": false, "server_min_protocol": "SMB2"},
		SSHConfig:     map[string]any{"rootlogin": false},
		ISCSITargets:  []map[string]any{},
		SnapshotTasks: []any{map[string]any{"id": 1}},
		AuthSuccess:   false,
	}
}

func (m *truenasMock) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch path {
		case "/api/v2.0/system/info":
			json.NewEncoder(w).Encode(m.SystemInfo)
		case "/api/v2.0/sharing/smb":
			json.NewEncoder(w).Encode(m.SMBShares)
		case "/api/v2.0/sharing/nfs":
			json.NewEncoder(w).Encode(m.NFSShares)
		case "/api/v2.0/smb":
			json.NewEncoder(w).Encode(m.SMBConfig)
		case "/api/v2.0/ssh":
			json.NewEncoder(w).Encode(m.SSHConfig)
		case "/api/v2.0/iscsi/target":
			json.NewEncoder(w).Encode(m.ISCSITargets)
		case "/api/v2.0/pool/snapshottask":
			json.NewEncoder(w).Encode(m.SnapshotTasks)
		default:
			http.NotFound(w, r)
		}
	}
}

func runScanner(t *testing.T, ts *httptest.Server, nasType string) ([]finding.Finding, error) {
	t.Helper()
	cfg := nas.Config{
		Endpoint:      ts.URL,
		Username:      "admin",
		Password:      "password",
		NASType:       nasType,
		SkipTLSVerify: false,
	}
	s := nas.New(cfg, ts.Client())
	asset := strings.TrimPrefix(ts.URL, "http://")
	return s.Run(context.Background(), asset, module.ScanDeep)
}

// --------------------------------------------------------------------------
// Surface mode gating is handled by the on-prem module dispatcher, not by
// the scanner itself. See internal/modules/onprem/module.go.
// --------------------------------------------------------------------------

func TestSurfaceMode_RunsWhenCalledDirectly(t *testing.T) {
	mock := defaultSynologyMock()
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	cfg := nas.Config{
		Endpoint: ts.URL,
		NASType:  "synology",
	}
	s := nas.New(cfg, ts.Client())
	findings, err := s.Run(context.Background(), "test-nas", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Scanner no longer self-gates; it produces findings regardless of scan
	// type. The on-prem module dispatcher prevents surface-mode invocations.
	if len(findings) == 0 {
		t.Error("expected findings when scanner is called directly in surface mode")
	}
}

// --------------------------------------------------------------------------
// Synology: SMBv1 enabled
// --------------------------------------------------------------------------

func TestSynology_SMBv1_Detected(t *testing.T) {
	mock := defaultSynologyMock()
	mock.DSMInfo = map[string]any{
		"data": map[string]any{
			"version_string": "7.2.1-69057",
			"model":          "DS920+",
			"smb_enabled":    true,
			"smb1_enabled":   true,
			"ssh_enabled":    false,
		},
		"success": true,
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "synology")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASSMBv1) {
		t.Error("expected CheckOnpremNASSMBv1 when SMBv1 is enabled on Synology")
	}
}

// --------------------------------------------------------------------------
// Synology: SSH enabled
// --------------------------------------------------------------------------

func TestSynology_SSH_Detected(t *testing.T) {
	mock := defaultSynologyMock()
	mock.DSMInfo = map[string]any{
		"data": map[string]any{
			"version_string": "7.2.1-69057",
			"model":          "DS920+",
			"smb_enabled":    true,
			"smb1_enabled":   false,
			"ssh_enabled":    true,
		},
		"success": true,
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "synology")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASSSHRoot) {
		t.Error("expected CheckOnpremNASSSHRoot when SSH is enabled on Synology")
	}
}

// --------------------------------------------------------------------------
// Synology: outdated firmware
// --------------------------------------------------------------------------

func TestSynology_OutdatedFirmware_Detected(t *testing.T) {
	mock := defaultSynologyMock()
	mock.DSMInfo = map[string]any{
		"data": map[string]any{
			"version_string": "6.2.4-25556",
			"model":          "DS218+",
			"smb_enabled":    false,
			"smb1_enabled":   false,
			"ssh_enabled":    false,
		},
		"success": true,
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "synology")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASOutdatedFirmware) {
		t.Error("expected CheckOnpremNASOutdatedFirmware for DSM 6.2.4")
	}
}

// --------------------------------------------------------------------------
// Synology: default credentials accepted
// --------------------------------------------------------------------------

func TestSynology_DefaultCreds_Detected(t *testing.T) {
	mock := defaultSynologyMock()
	mock.AuthSuccess = true
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "synology")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASDefaultAdmin) {
		t.Error("expected CheckOnpremNASDefaultAdmin when default credentials are accepted")
	}
}

// --------------------------------------------------------------------------
// Synology: public shares without ACL
// --------------------------------------------------------------------------

func TestSynology_PublicShares_Detected(t *testing.T) {
	mock := defaultSynologyMock()
	mock.Shares = map[string]any{
		"data": map[string]any{
			"shares": []any{
				map[string]any{
					"name": "public",
					"path": "/volume1/public",
					"additional": map[string]any{
						"perm": map[string]any{
							"acl_enable":  false,
							"is_acl_mode": false,
						},
					},
				},
			},
		},
		"success": true,
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "synology")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASPublicShares) {
		t.Error("expected CheckOnpremNASPublicShares when share has no ACL")
	}
}

// --------------------------------------------------------------------------
// Synology: no snapshot protection
// --------------------------------------------------------------------------

func TestSynology_NoSnapshots_Detected(t *testing.T) {
	mock := defaultSynologyMock()
	mock.Snapshots = map[string]any{
		"data": map[string]any{
			"snapshots": []any{},
			"total":     0,
		},
		"success": true,
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "synology")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASNoSnapshotProtection) {
		t.Error("expected CheckOnpremNASNoSnapshotProtection when no snapshots exist")
	}
}

// --------------------------------------------------------------------------
// Synology: iSCSI without CHAP
// --------------------------------------------------------------------------

func TestSynology_ISCSINoAuth_Detected(t *testing.T) {
	mock := defaultSynologyMock()
	mock.ISCSITargets = map[string]any{
		"data": map[string]any{
			"targets": []any{
				map[string]any{
					"name":      "iqn.2000-01.com.synology:ds920.target-1",
					"auth_type": 0,
				},
			},
		},
		"success": true,
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "synology")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASiSCSINoAuth) {
		t.Error("expected CheckOnpremNASiSCSINoAuth when auth_type is 0")
	}
}

// --------------------------------------------------------------------------
// TrueNAS: SMBv1 enabled
// --------------------------------------------------------------------------

func TestTrueNAS_SMBv1_Detected(t *testing.T) {
	mock := defaultTrueNASMock()
	mock.SMBConfig = map[string]any{
		"enable_smb1":         true,
		"server_min_protocol": "NT1",
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "truenas")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASSMBv1) {
		t.Error("expected CheckOnpremNASSMBv1 when SMBv1 is enabled on TrueNAS")
	}
}

// --------------------------------------------------------------------------
// TrueNAS: SMB guest shares
// --------------------------------------------------------------------------

func TestTrueNAS_GuestShares_Detected(t *testing.T) {
	mock := defaultTrueNASMock()
	mock.SMBShares = []map[string]any{
		{
			"name":    "public_data",
			"path":    "/mnt/pool/public",
			"guestok": true,
			"enabled": true,
		},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "truenas")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASPublicShares) {
		t.Error("expected CheckOnpremNASPublicShares for guest-accessible SMB share")
	}
}

// --------------------------------------------------------------------------
// TrueNAS: unrestricted NFS export
// --------------------------------------------------------------------------

func TestTrueNAS_UnrestrictedNFS_Detected(t *testing.T) {
	mock := defaultTrueNASMock()
	mock.NFSShares = []map[string]any{
		{
			"path":    "/mnt/pool/backups",
			"enabled": true,
			"hosts":   []string{},
			"network": []string{},
		},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "truenas")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASPublicShares) {
		t.Error("expected CheckOnpremNASPublicShares for unrestricted NFS export")
	}
}

// --------------------------------------------------------------------------
// TrueNAS: SSH root login enabled
// --------------------------------------------------------------------------

func TestTrueNAS_SSHRoot_Detected(t *testing.T) {
	mock := defaultTrueNASMock()
	mock.SSHConfig = map[string]any{
		"rootlogin": true,
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "truenas")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASSSHRoot) {
		t.Error("expected CheckOnpremNASSSHRoot when SSH root login is enabled on TrueNAS")
	}
}

// --------------------------------------------------------------------------
// TrueNAS: iSCSI without CHAP
// --------------------------------------------------------------------------

func TestTrueNAS_ISCSINoAuth_Detected(t *testing.T) {
	mock := defaultTrueNASMock()
	mock.ISCSITargets = []map[string]any{
		{
			"name": "iqn.2005-10.org.freenas.ctl:backup-target",
			"auth": "none",
		},
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "truenas")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASiSCSINoAuth) {
		t.Error("expected CheckOnpremNASiSCSINoAuth when auth is 'none'")
	}
}

// --------------------------------------------------------------------------
// TrueNAS: no snapshot tasks
// --------------------------------------------------------------------------

func TestTrueNAS_NoSnapshots_Detected(t *testing.T) {
	mock := defaultTrueNASMock()
	mock.SnapshotTasks = []any{}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "truenas")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASNoSnapshotProtection) {
		t.Error("expected CheckOnpremNASNoSnapshotProtection when no snapshot tasks exist")
	}
}

// --------------------------------------------------------------------------
// TrueNAS: outdated version
// --------------------------------------------------------------------------

func TestTrueNAS_OutdatedVersion_Detected(t *testing.T) {
	mock := defaultTrueNASMock()
	mock.SystemInfo = map[string]any{
		"version":  "TrueNAS-12.0-U8.1",
		"hostname": "truenas-old",
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "truenas")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASOutdatedFirmware) {
		t.Error("expected CheckOnpremNASOutdatedFirmware for TrueNAS-12.0")
	}
}

// --------------------------------------------------------------------------
// QNAP: outdated firmware
// --------------------------------------------------------------------------

func TestQNAP_OutdatedFirmware_Detected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "authLogin.cgi"):
			// Detection + auth endpoint.
			if r.URL.Query().Get("user") != "" {
				w.Write([]byte(`<QDocRoot><authPassed>0</authPassed></QDocRoot>`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<QDocRoot></QDocRoot>`))
			}
		case strings.Contains(r.URL.Path, "manaRequest.cgi"):
			w.Write([]byte(`<QDocRoot><version>4.5.4</version><modelName>TS-453D</modelName></QDocRoot>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	findings, err := runScanner(t, ts, "qnap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASOutdatedFirmware) {
		t.Error("expected CheckOnpremNASOutdatedFirmware for QTS 4.5.4")
	}
}

// --------------------------------------------------------------------------
// QNAP: SMBv1 enabled
// --------------------------------------------------------------------------

func TestQNAP_SMBv1_Detected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "authLogin.cgi"):
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<QDocRoot></QDocRoot>`))
		case strings.Contains(r.URL.Path, "manaRequest.cgi"):
			w.Write([]byte(`<QDocRoot><version>5.1.0</version><modelName>TS-464</modelName><samba_smb1>1</samba_smb1></QDocRoot>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	findings, err := runScanner(t, ts, "qnap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASSMBv1) {
		t.Error("expected CheckOnpremNASSMBv1 for QNAP with samba_smb1 enabled")
	}
}

// --------------------------------------------------------------------------
// NAS type detection failure
// --------------------------------------------------------------------------

func TestAutoDetect_Failure_EmitsScanError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	cfg := nas.Config{
		Endpoint: ts.URL,
		NASType:  "auto",
	}
	s := nas.New(cfg, ts.Client())
	findings, err := s.Run(context.Background(), "unknown-nas", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASScanError) {
		t.Error("expected CheckOnpremNASScanError when NAS type cannot be detected")
	}
}

// --------------------------------------------------------------------------
// HTTP endpoint (no TLS) emits no-TLS finding
// --------------------------------------------------------------------------

func TestHTTPEndpoint_NoTLS_Detected(t *testing.T) {
	mock := defaultSynologyMock()
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	// The test server URL starts with http:// which should trigger the no-TLS check.
	cfg := nas.Config{
		Endpoint: ts.URL, // http://...
		NASType:  "synology",
	}
	s := nas.New(cfg, ts.Client())
	findings, err := s.Run(context.Background(), "test-nas", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremNASNoTLS) {
		t.Error("expected CheckOnpremNASNoTLS when endpoint uses plain HTTP")
	}
}

// --------------------------------------------------------------------------
// Healthy environment: minimal findings
// --------------------------------------------------------------------------

func TestHealthySynology_MinimalFindings(t *testing.T) {
	mock := defaultSynologyMock()
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	// Use https:// in config to avoid no-TLS finding.
	// (We still connect over HTTP to the test server, but the endpoint string says https.)
	cfg := nas.Config{
		Endpoint: strings.Replace(ts.URL, "http://", "https://", 1),
		NASType:  "synology",
	}
	// Use a custom client that connects to the actual HTTP test server.
	s := nas.New(cfg, ts.Client())

	findings, err := s.Run(context.Background(), "test-nas", module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasCheckID(findings, finding.CheckOnpremNASSMBv1) {
		t.Error("healthy environment should not have SMBv1 finding")
	}
	if hasCheckID(findings, finding.CheckOnpremNASNoTLS) {
		t.Error("healthy environment should not have no-TLS finding")
	}
	if hasCheckID(findings, finding.CheckOnpremNASDefaultAdmin) {
		t.Error("healthy environment should not have default admin finding")
	}
	if hasCheckID(findings, finding.CheckOnpremNASSSHRoot) {
		t.Error("healthy environment should not have SSH root finding")
	}
}

// --------------------------------------------------------------------------
// All findings have ProofCommand and Evidence
// --------------------------------------------------------------------------

func TestAllFindings_HaveProofCommandAndEvidence(t *testing.T) {
	mock := defaultSynologyMock()
	mock.DSMInfo = map[string]any{
		"data": map[string]any{
			"version_string": "6.2.4-25556",
			"model":          "DS218+",
			"smb_enabled":    true,
			"smb1_enabled":   true,
			"ssh_enabled":    true,
		},
		"success": true,
	}
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	findings, err := runScanner(t, ts, "synology")
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
	mock := defaultSynologyMock()
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := nas.Config{
		Endpoint: ts.URL,
		NASType:  "synology",
	}
	s := nas.New(cfg, ts.Client())
	_, _ = s.Run(ctx, "test-nas", module.ScanDeep) // must not panic
}

// --------------------------------------------------------------------------
// Scanner name
// --------------------------------------------------------------------------

func TestScannerName(t *testing.T) {
	s := nas.New(nas.Config{}, nil)
	if s.Name() != "onprem/nas" {
		t.Errorf("expected scanner name 'onprem/nas', got %q", s.Name())
	}
}
