package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/craigderington/trml-daemon/internal/config"
)

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Label}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.Executable}}</string>
        <string>start</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{{.LogDir}}/trml-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>{{.LogDir}}/trml-daemon.err</string>
</dict>
</plist>
`

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", config.LaunchdLabel+".plist"), nil
}

func logDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Library", "Logs", "trml")
	return dir, os.MkdirAll(dir, 0755)
}

// InstallLaunchd writes the plist and loads it with launchctl.
func InstallLaunchd(executablePath string) error {
	path, err := plistPath()
	if err != nil {
		return fmt.Errorf("launchd plist path: %w", err)
	}
	logD, err := logDir()
	if err != nil {
		return fmt.Errorf("log dir: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir LaunchAgents: %w", err)
	}

	data := struct {
		Label      string
		Executable string
		LogDir     string
	}{
		Label:      config.LaunchdLabel,
		Executable: executablePath,
		LogDir:     logD,
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create plist: %w", err)
	}
	defer f.Close()

	tmpl := template.Must(template.New("plist").Parse(plistTemplate))
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("render plist: %w", err)
	}

	out, err := exec.Command("launchctl", "load", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl load: %w\n%s", err, out)
	}
	fmt.Printf("Installed and loaded %s\n", config.LaunchdLabel)
	fmt.Printf("Plist: %s\n", path)
	return nil
}

// UninstallLaunchd unloads and removes the plist.
func UninstallLaunchd() error {
	path, err := plistPath()
	if err != nil {
		return err
	}

	out, err := exec.Command("launchctl", "unload", path).CombinedOutput()
	if err != nil {
		// Don't fail if not loaded
		fmt.Printf("launchctl unload: %s\n", out)
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}
	fmt.Printf("Uninstalled %s\n", config.LaunchdLabel)
	return nil
}
