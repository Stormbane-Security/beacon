package cmdinj

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/oob"
)

func TestCmdInj_SkipsSurface(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("CmdInj scanner should skip surface mode, got %d findings", len(findings))
	}
}

func TestCmdInj_DetectsTimeBased(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("cmd")
		if strings.Contains(param, "sleep 3") {
			time.Sleep(3 * time.Second)
		} else if strings.Contains(param, "sleep 5") {
			time.Sleep(5 * time.Second)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) == 0 {
		t.Fatal("expected command injection finding for vulnerable server")
	}

	f := findings[0]
	if f.CheckID != "web.command_injection" {
		t.Errorf("expected check ID web.command_injection, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
}

func TestCmdInj_NoFalsePositiveConstantTime(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for constant-time server, got %d", len(findings))
	}
}

func TestBuildPayload_CmdInj(t *testing.T) {
	p := payload{
		name:    "unix-semi",
		os:      "unix",
		prefix:  "; sleep ",
		sleepFn: "%d",
		suffix:  " #",
	}

	got := buildPayload(p, 3)
	want := "; sleep 3 #"
	if got != want {
		t.Errorf("buildPayload() = %q, want %q", got, want)
	}
}

func TestCmdInj_OOBIntegration(t *testing.T) {
	oobSrv := oob.NewServer("oob.test.com", "127.0.0.1:0")
	ctx := oob.WithOOB(context.Background(), oobSrv)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}
	// No findings expected since server doesn't execute commands
	_ = findings
}

func TestMeasureBaseline_CmdInj(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	baseline, err := measureBaseline(context.Background(), client, ts.URL, 5)
	if err != nil {
		t.Fatal(err)
	}

	if baseline > 100*time.Millisecond {
		t.Errorf("baseline %s too high for localhost", baseline)
	}
}

func TestCmdInj_ShellshockDetection(t *testing.T) {
	// Simulate a CGI endpoint vulnerable to Shellshock.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi-bin/vulnerable" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		ua := r.Header.Get("User-Agent")
		if strings.HasPrefix(ua, "() { :;};") {
			// Extract the command after "echo; "
			parts := strings.SplitN(ua, "echo; ", 2)
			if len(parts) == 2 {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, parts[1])
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()

	// ScanDeep should detect Shellshock but not post-exploit.
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) == 0 {
		t.Fatal("expected Shellshock finding for vulnerable CGI endpoint")
	}

	f := findings[0]
	if f.CheckID != finding.CheckWebCmdInjection {
		t.Errorf("expected check ID %s, got %s", finding.CheckWebCmdInjection, f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
	if !strings.Contains(f.Title, "Shellshock") {
		t.Errorf("expected title to mention Shellshock, got %q", f.Title)
	}
	ev := f.Evidence
	if ev["cve"] != "CVE-2014-6271" {
		t.Errorf("expected CVE-2014-6271 in evidence, got %v", ev["cve"])
	}
}

func TestCmdInj_ShellshockPostExploit(t *testing.T) {
	// Simulate a Shellshock-vulnerable endpoint that can also execute recon commands.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi-bin/vulnerable" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		ua := r.Header.Get("User-Agent")
		if !strings.HasPrefix(ua, "() { :;};") {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Simulate command execution based on the payload.
		w.WriteHeader(http.StatusOK)

		// Extract the bash -c 'CMD' portion.
		if strings.Contains(ua, "/bin/bash -c '") {
			start := strings.Index(ua, "/bin/bash -c '") + len("/bin/bash -c '")
			end := strings.LastIndex(ua, "'")
			if end > start {
				cmd := ua[start:end]
				switch {
				case cmd == "cat /etc/hosts 2>/dev/null":
					fmt.Fprint(w, "127.0.0.1 localhost\n172.18.0.3 cache\n172.18.0.4 search\n")
				case cmd == "cat /proc/net/arp 2>/dev/null":
					fmt.Fprint(w, "IP address       HW type     Flags       HW address            Mask     Device\n172.18.0.3       0x1         0x2         02:42:ac:12:00:03     *        eth0\n172.18.0.4       0x1         0x2         02:42:ac:12:00:04     *        eth0\n")
				case strings.HasPrefix(cmd, "ip addr") || strings.HasPrefix(cmd, "ifconfig"):
					fmt.Fprint(w, "inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0\n")
				case cmd == "cat /etc/resolv.conf 2>/dev/null":
					fmt.Fprint(w, "nameserver 127.0.0.11\n")
				case cmd == "env 2>/dev/null":
					fmt.Fprint(w, "HOME=/root\nPATH=/usr/local/sbin:/usr/local/bin\nDB_PASSWORD=secret123\n")
				default:
					fmt.Fprint(w, "")
				}
				return
			}
		}

		// Simple echo marker detection.
		if strings.Contains(ua, "echo "+shellshockMark) {
			fmt.Fprint(w, shellshockMark)
		}
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()

	// ScanAuthorized triggers post-exploitation.
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}

	// Should have at least: Shellshock detection + internal network discovered + env creds.
	checkIDs := make(map[finding.CheckID]bool)
	for _, f := range findings {
		checkIDs[f.CheckID] = true
	}

	if !checkIDs[finding.CheckWebCmdInjection] {
		t.Error("expected web.command_injection finding")
	}
	if !checkIDs[finding.CheckExploitInternalNetDiscovered] {
		t.Error("expected exploit.internal_network_discovered finding")
	}
	if !checkIDs[finding.CheckExploitCredentialHarvest] {
		t.Error("expected exploit.credential_harvest finding (from env vars)")
	}

	// Verify internal network finding has hosts.
	for _, f := range findings {
		if f.CheckID == finding.CheckExploitInternalNetDiscovered {
			hostsFound, ok := f.Evidence["hosts_found"]
			if !ok {
				t.Error("internal network finding missing hosts_found evidence")
			}
			if hosts, ok := hostsFound.([]string); ok && len(hosts) == 0 {
				t.Error("hosts_found is empty")
			}
			break
		}
	}
}

func TestCmdInj_ShellshockNoFalsePositive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Normal page"))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if strings.Contains(f.Title, "Shellshock") {
			t.Error("false positive: Shellshock finding on non-vulnerable server")
		}
	}
}

func TestParseRedisKeys(t *testing.T) {
	output := "*3\r\n$10\r\napp:db_url\r\n$14\r\napp:api_secret\r\n$8\r\nsessions\r\n"
	keys := parseRedisKeys(output)
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d: %v", len(keys), keys)
	}
}

func TestParseEtcHosts(t *testing.T) {
	data := `127.0.0.1 localhost
172.18.0.3 cache
172.18.0.4 search db-primary`
	hosts := make(map[string][]string)
	parseEtcHosts(data, hosts)

	if _, ok := hosts["172.18.0.3"]; !ok {
		t.Error("expected 172.18.0.3 in hosts")
	}
	if _, ok := hosts["cache"]; !ok {
		t.Error("expected cache hostname in hosts")
	}
	if _, ok := hosts["172.18.0.4"]; !ok {
		t.Error("expected 172.18.0.4 in hosts")
	}
	names := hosts["172.18.0.4"]
	found := false
	for _, n := range names {
		if n == "db-primary" {
			found = true
		}
	}
	if !found {
		t.Error("expected db-primary alias for 172.18.0.4")
	}
}

func TestExtractEnvSecrets(t *testing.T) {
	envOutput := `HOME=/root
PATH=/usr/bin
DATABASE_PASSWORD=hunter2
REDIS_AUTH_TOKEN=abc123
API_KEY=sk-12345
NORMAL_VAR=hello`

	creds := extractEnvSecrets(envOutput)
	if len(creds) < 2 {
		t.Errorf("expected at least 2 env secrets, got %d", len(creds))
	}

	foundDB := false
	for _, c := range creds {
		if c.Value == "hunter2" {
			foundDB = true
		}
	}
	if !foundDB {
		t.Error("expected to find DATABASE_PASSWORD=hunter2")
	}
}
