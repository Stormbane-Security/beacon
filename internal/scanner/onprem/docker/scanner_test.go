package docker_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	dockerscanner "github.com/stormbane-security/beacon/internal/scanner/onprem/docker"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func countCheckID(findings []finding.Finding, id finding.CheckID) int {
	n := 0
	for _, f := range findings {
		if f.CheckID == id {
			n++
		}
	}
	return n
}

// containerJSON builds a minimal inspect response for testing. The caller can
// override fields via the opts function.
type inspectOpts func(*inspectBody)

type inspectBody struct {
	ID         string     `json:"Id"`
	Name       string     `json:"Name"`
	Image      string     `json:"Image"`
	Created    string     `json:"Created"`
	HostConfig hostConfig `json:"HostConfig"`
	Config     configBody `json:"Config"`
}

type hostConfig struct {
	Privileged     bool     `json:"Privileged"`
	NetworkMode    string   `json:"NetworkMode"`
	PidMode        string   `json:"PidMode"`
	IpcMode        string   `json:"IpcMode"`
	CapAdd         []string `json:"CapAdd"`
	ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
	Binds          []string `json:"Binds"`
	Memory         int64    `json:"Memory"`
	NanoCpus       int64    `json:"NanoCpus"`
}

type configBody struct {
	User        string      `json:"User"`
	Healthcheck interface{} `json:"Healthcheck"`
}

func secureDefaults() inspectBody {
	return inspectBody{
		ID:      "abc123def456",
		Name:    "/secure-app",
		Image:   "myapp:latest",
		Created: time.Now().Add(-24 * time.Hour).Format(time.RFC3339Nano),
		HostConfig: hostConfig{
			Privileged:     false,
			NetworkMode:    "bridge",
			PidMode:        "",
			IpcMode:        "",
			CapAdd:         nil,
			ReadonlyRootfs: true,
			Binds:          nil,
			Memory:         536870912, // 512 MB
			NanoCpus:       1000000000,
		},
		Config: configBody{
			User:        "1000",
			Healthcheck: map[string]interface{}{"Test": []string{"CMD", "true"}},
		},
	}
}

// dockerMux returns an http.ServeMux that simulates the Docker Engine API.
// It serves a single container with the given inspect body.
func dockerMux(body inspectBody) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"Version":    "24.0.7",
			"ApiVersion": "1.43",
		})
	})

	listResp, _ := json.Marshal([]map[string]interface{}{
		{
			"Id":    body.ID,
			"Names": []string{body.Name},
			"Image": body.Image,
			"State": "running",
		},
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(listResp)
	})

	inspectResp, _ := json.Marshal(body)
	mux.HandleFunc("/containers/"+body.ID+"/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(inspectResp)
	})

	return mux
}

// runScanner creates a test server from the mux and runs the scanner against it.
func runScanner(t *testing.T, mux *http.ServeMux, scanType module.ScanType) ([]finding.Finding, error) {
	t.Helper()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := dockerscanner.Config{Endpoint: ts.URL}
	s := dockerscanner.New(cfg, ts.Client())
	asset := strings.TrimPrefix(ts.URL, "http://")
	return s.Run(context.Background(), asset, scanType)
}

// --------------------------------------------------------------------------
// Surface mode: exposed API check
// --------------------------------------------------------------------------

func TestExposedAPI_Detected(t *testing.T) {
	body := secureDefaults()
	mux := dockerMux(body)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := dockerscanner.Config{Endpoint: ts.URL}
	s := dockerscanner.New(cfg, ts.Client())
	asset := strings.TrimPrefix(ts.URL, "http://")

	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerExposedAPI) {
		t.Error("expected CheckOnpremDockerExposedAPI when API is reachable over HTTP")
	}
}

func TestExposedAPI_NotDetected_HTTPS(t *testing.T) {
	// An HTTPS endpoint should not trigger the exposed API check.
	body := secureDefaults()
	mux := dockerMux(body)
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	cfg := dockerscanner.Config{Endpoint: ts.URL}
	s := dockerscanner.New(cfg, ts.Client())
	asset := strings.TrimPrefix(ts.URL, "https://")

	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerExposedAPI) {
		t.Error("should NOT emit CheckOnpremDockerExposedAPI for HTTPS endpoint")
	}
}

func TestSurfaceMode_NoDeepChecks(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Privileged = true // insecure, but surface mode should not inspect containers
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have the exposed API finding but NOT the privileged container finding.
	if hasCheckID(findings, finding.CheckOnpremDockerPrivilegedContainer) {
		t.Error("surface mode must not produce deep-only findings like privileged container")
	}
}

// --------------------------------------------------------------------------
// Secure container: no findings except exposed API and writable rootfs
// --------------------------------------------------------------------------

func TestSecureContainer_NoDeepFindings(t *testing.T) {
	body := secureDefaults()
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	deepChecks := []finding.CheckID{
		finding.CheckOnpremDockerPrivilegedContainer,
		finding.CheckOnpremDockerHostNetwork,
		finding.CheckOnpremDockerRootUser,
		finding.CheckOnpremDockerNoResourceLimits,
		finding.CheckOnpremDockerHostMount,
		finding.CheckOnpremDockerNoHealthcheck,
		finding.CheckOnpremDockerCapSysAdmin,
		finding.CheckOnpremDockerHostPID,
		finding.CheckOnpremDockerHostIPC,
		finding.CheckOnpremDockerOutdatedImage,
		finding.CheckOnpremDockerWritableRootFS,
	}
	for _, check := range deepChecks {
		if hasCheckID(findings, check) {
			t.Errorf("secure container should not emit %s", check)
		}
	}
}

// --------------------------------------------------------------------------
// Privileged container
// --------------------------------------------------------------------------

func TestPrivilegedContainer_Detected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Privileged = true
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerPrivilegedContainer) {
		t.Error("expected CheckOnpremDockerPrivilegedContainer when Privileged=true")
	}
}

func TestPrivilegedContainer_NotDetected_WhenFalse(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Privileged = false
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerPrivilegedContainer) {
		t.Error("should NOT emit CheckOnpremDockerPrivilegedContainer when Privileged=false")
	}
}

// --------------------------------------------------------------------------
// Host network
// --------------------------------------------------------------------------

func TestHostNetwork_Detected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.NetworkMode = "host"
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerHostNetwork) {
		t.Error("expected CheckOnpremDockerHostNetwork when NetworkMode=host")
	}
}

func TestHostNetwork_NotDetected_Bridge(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.NetworkMode = "bridge"
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerHostNetwork) {
		t.Error("should NOT emit CheckOnpremDockerHostNetwork when NetworkMode=bridge")
	}
}

// --------------------------------------------------------------------------
// Root user
// --------------------------------------------------------------------------

func TestRootUser_EmptyString(t *testing.T) {
	body := secureDefaults()
	body.Config.User = ""
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerRootUser) {
		t.Error("expected CheckOnpremDockerRootUser when User is empty string")
	}
}

func TestRootUser_Zero(t *testing.T) {
	body := secureDefaults()
	body.Config.User = "0"
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerRootUser) {
		t.Error("expected CheckOnpremDockerRootUser when User=0")
	}
}

func TestRootUser_Root(t *testing.T) {
	body := secureDefaults()
	body.Config.User = "root"
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerRootUser) {
		t.Error("expected CheckOnpremDockerRootUser when User=root")
	}
}

func TestRootUser_NotDetected_NonRoot(t *testing.T) {
	body := secureDefaults()
	body.Config.User = "1000"
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerRootUser) {
		t.Error("should NOT emit CheckOnpremDockerRootUser when User=1000")
	}
}

// --------------------------------------------------------------------------
// No resource limits
// --------------------------------------------------------------------------

func TestNoResourceLimits_Detected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Memory = 0
	body.HostConfig.NanoCpus = 0
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerNoResourceLimits) {
		t.Error("expected CheckOnpremDockerNoResourceLimits when Memory=0 and NanoCpus=0")
	}
}

func TestNoResourceLimits_NotDetected_MemorySet(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Memory = 536870912 // 512 MB
	body.HostConfig.NanoCpus = 0
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerNoResourceLimits) {
		t.Error("should NOT emit CheckOnpremDockerNoResourceLimits when Memory is set")
	}
}

func TestNoResourceLimits_NotDetected_CPUSet(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Memory = 0
	body.HostConfig.NanoCpus = 1000000000
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerNoResourceLimits) {
		t.Error("should NOT emit CheckOnpremDockerNoResourceLimits when NanoCpus is set")
	}
}

// --------------------------------------------------------------------------
// Sensitive host mounts
// --------------------------------------------------------------------------

func TestHostMount_RootMount(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Binds = []string{"/:/host:rw"}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerHostMount) {
		t.Error("expected CheckOnpremDockerHostMount when / is mounted")
	}
}

func TestHostMount_DockerSocket(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Binds = []string{"/var/run/docker.sock:/var/run/docker.sock:rw"}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerHostMount) {
		t.Error("expected CheckOnpremDockerHostMount when docker socket is mounted")
	}
}

func TestHostMount_Etc(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Binds = []string{"/etc:/container-etc:ro"}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerHostMount) {
		t.Error("expected CheckOnpremDockerHostMount when /etc is mounted")
	}
}

func TestHostMount_Proc(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Binds = []string{"/proc:/host-proc:ro"}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerHostMount) {
		t.Error("expected CheckOnpremDockerHostMount when /proc is mounted")
	}
}

func TestHostMount_Safe_AppData(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Binds = []string{"/data/app:/app:ro"}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerHostMount) {
		t.Error("should NOT emit CheckOnpremDockerHostMount for safe path /data/app")
	}
}

func TestHostMount_MultipleMounts(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.Binds = []string{
		"/etc/passwd:/etc/passwd:ro",
		"/var/run/docker.sock:/var/run/docker.sock:rw",
	}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := countCheckID(findings, finding.CheckOnpremDockerHostMount)
	if count != 2 {
		t.Errorf("expected 2 host mount findings for /etc/passwd and docker.sock, got %d", count)
	}
}

// --------------------------------------------------------------------------
// No healthcheck
// --------------------------------------------------------------------------

func TestNoHealthcheck_Detected(t *testing.T) {
	body := secureDefaults()
	body.Config.Healthcheck = nil
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerNoHealthcheck) {
		t.Error("expected CheckOnpremDockerNoHealthcheck when Healthcheck is nil")
	}
}

func TestNoHealthcheck_NotDetected(t *testing.T) {
	body := secureDefaults()
	body.Config.Healthcheck = map[string]interface{}{"Test": []string{"CMD", "true"}}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerNoHealthcheck) {
		t.Error("should NOT emit CheckOnpremDockerNoHealthcheck when healthcheck is configured")
	}
}

// --------------------------------------------------------------------------
// Dangerous capabilities
// --------------------------------------------------------------------------

func TestCapSysAdmin_Detected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.CapAdd = []string{"SYS_ADMIN"}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerCapSysAdmin) {
		t.Error("expected CheckOnpremDockerCapSysAdmin when CAP_SYS_ADMIN is added")
	}
}

func TestCapNetAdmin_Detected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.CapAdd = []string{"NET_ADMIN"}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerCapSysAdmin) {
		t.Error("expected CheckOnpremDockerCapSysAdmin for NET_ADMIN capability")
	}
}

func TestCapAll_Detected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.CapAdd = []string{"ALL"}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerCapSysAdmin) {
		t.Error("expected CheckOnpremDockerCapSysAdmin for ALL capabilities")
	}
}

func TestCapSafe_NotDetected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.CapAdd = []string{"CHOWN", "SETUID"}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerCapSysAdmin) {
		t.Error("should NOT emit CheckOnpremDockerCapSysAdmin for CHOWN/SETUID")
	}
}

func TestMultipleDangerousCaps(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.CapAdd = []string{"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN"}
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := countCheckID(findings, finding.CheckOnpremDockerCapSysAdmin)
	if count != 3 {
		t.Errorf("expected 3 capability findings for SYS_ADMIN+SYS_PTRACE+NET_ADMIN, got %d", count)
	}
}

// --------------------------------------------------------------------------
// Host PID namespace
// --------------------------------------------------------------------------

func TestHostPID_Detected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.PidMode = "host"
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerHostPID) {
		t.Error("expected CheckOnpremDockerHostPID when PidMode=host")
	}
}

func TestHostPID_NotDetected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.PidMode = ""
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerHostPID) {
		t.Error("should NOT emit CheckOnpremDockerHostPID when PidMode is empty")
	}
}

// --------------------------------------------------------------------------
// Host IPC namespace
// --------------------------------------------------------------------------

func TestHostIPC_Detected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.IpcMode = "host"
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerHostIPC) {
		t.Error("expected CheckOnpremDockerHostIPC when IpcMode=host")
	}
}

func TestHostIPC_NotDetected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.IpcMode = ""
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerHostIPC) {
		t.Error("should NOT emit CheckOnpremDockerHostIPC when IpcMode is empty")
	}
}

// --------------------------------------------------------------------------
// Outdated image
// --------------------------------------------------------------------------

func TestOutdatedImage_Detected(t *testing.T) {
	body := secureDefaults()
	body.Created = time.Now().Add(-100 * 24 * time.Hour).Format(time.RFC3339Nano)
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerOutdatedImage) {
		t.Error("expected CheckOnpremDockerOutdatedImage when Created >90 days ago")
	}
}

func TestOutdatedImage_NotDetected_Recent(t *testing.T) {
	body := secureDefaults()
	body.Created = time.Now().Add(-24 * time.Hour).Format(time.RFC3339Nano)
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerOutdatedImage) {
		t.Error("should NOT emit CheckOnpremDockerOutdatedImage for recent image")
	}
}

// --------------------------------------------------------------------------
// Writable root filesystem
// --------------------------------------------------------------------------

func TestWritableRootFS_Detected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.ReadonlyRootfs = false
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerWritableRootFS) {
		t.Error("expected CheckOnpremDockerWritableRootFS when ReadonlyRootfs=false")
	}
}

func TestWritableRootFS_NotDetected(t *testing.T) {
	body := secureDefaults()
	body.HostConfig.ReadonlyRootfs = true
	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(findings, finding.CheckOnpremDockerWritableRootFS) {
		t.Error("should NOT emit CheckOnpremDockerWritableRootFS when ReadonlyRootfs=true")
	}
}

// --------------------------------------------------------------------------
// Scan error handling
// --------------------------------------------------------------------------

func TestScanError_BadAPI(t *testing.T) {
	// Server that returns 500 for container listing.
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"Version": "24.0.7"})
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(findings, finding.CheckOnpremDockerScanError) {
		t.Error("expected CheckOnpremDockerScanError when API returns 500")
	}
}

// --------------------------------------------------------------------------
// ProofCommand and Evidence are always set
// --------------------------------------------------------------------------

func TestAllFindings_HaveProofAndEvidence(t *testing.T) {
	// Build a maximally-insecure container.
	body := secureDefaults()
	body.HostConfig.Privileged = true
	body.HostConfig.NetworkMode = "host"
	body.HostConfig.PidMode = "host"
	body.HostConfig.IpcMode = "host"
	body.HostConfig.CapAdd = []string{"SYS_ADMIN"}
	body.HostConfig.ReadonlyRootfs = false
	body.HostConfig.Memory = 0
	body.HostConfig.NanoCpus = 0
	body.HostConfig.Binds = []string{"/:/host:rw"}
	body.Config.User = ""
	body.Config.Healthcheck = nil
	body.Created = time.Now().Add(-100 * 24 * time.Hour).Format(time.RFC3339Nano)

	mux := dockerMux(body)

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding from insecure container")
	}

	for _, f := range findings {
		if f.ProofCommand == "" {
			t.Errorf("finding %s has empty ProofCommand", f.CheckID)
		}
		if f.Evidence == nil || len(f.Evidence) == 0 {
			t.Errorf("finding %s has empty Evidence", f.CheckID)
		}
	}
}

// --------------------------------------------------------------------------
// Multiple containers
// --------------------------------------------------------------------------

func TestMultipleContainers(t *testing.T) {
	secure := inspectBody{
		ID:      "sec111",
		Name:    "/secure",
		Image:   "secure:latest",
		Created: time.Now().Add(-24 * time.Hour).Format(time.RFC3339Nano),
		HostConfig: hostConfig{
			NetworkMode:    "bridge",
			ReadonlyRootfs: true,
			Memory:         536870912,
			NanoCpus:       1000000000,
		},
		Config: configBody{
			User:        "1000",
			Healthcheck: map[string]interface{}{"Test": []string{"CMD", "true"}},
		},
	}

	insecure := inspectBody{
		ID:      "bad222",
		Name:    "/insecure",
		Image:   "badapp:latest",
		Created: time.Now().Add(-24 * time.Hour).Format(time.RFC3339Nano),
		HostConfig: hostConfig{
			Privileged:     true,
			NetworkMode:    "bridge",
			ReadonlyRootfs: true,
			Memory:         536870912,
			NanoCpus:       1000000000,
		},
		Config: configBody{
			User:        "1000",
			Healthcheck: map[string]interface{}{"Test": []string{"CMD", "true"}},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"Version": "24.0.7"})
	})

	listResp, _ := json.Marshal([]map[string]interface{}{
		{"Id": secure.ID, "Names": []string{secure.Name}, "Image": secure.Image, "State": "running"},
		{"Id": insecure.ID, "Names": []string{insecure.Name}, "Image": insecure.Image, "State": "running"},
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(listResp)
	})

	secResp, _ := json.Marshal(secure)
	mux.HandleFunc("/containers/"+secure.ID+"/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(secResp)
	})

	insecResp, _ := json.Marshal(insecure)
	mux.HandleFunc("/containers/"+insecure.ID+"/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(insecResp)
	})

	findings, err := runScanner(t, mux, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the insecure container should produce a privileged finding.
	count := countCheckID(findings, finding.CheckOnpremDockerPrivilegedContainer)
	if count != 1 {
		t.Errorf("expected exactly 1 privileged finding from 2 containers, got %d", count)
	}
}

// --------------------------------------------------------------------------
// Scanner name
// --------------------------------------------------------------------------

func TestScannerName(t *testing.T) {
	s := dockerscanner.New(dockerscanner.Config{}, nil)
	if s.Name() != "onprem/docker" {
		t.Errorf("expected scanner name %q, got %q", "onprem/docker", s.Name())
	}
}
