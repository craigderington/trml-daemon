package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/craigderington/trml-daemon/internal/config"
)

const systemdUnitTemplate = `[Unit]
Description=trml daemon — terminal over iPhone relay
After=network.target

[Service]
ExecStart={{.Executable}} start
PIDFile={{.PIDPath}}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`

func systemdUnitPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "systemd", "user", config.SystemdUnitName+".service"), nil
}

// InstallSystemd writes the unit file and enables/starts it.
func InstallSystemd(executablePath string) error {
	path, err := systemdUnitPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir systemd user: %w", err)
	}

	data := struct{ Executable, PIDPath string }{
		Executable: executablePath,
		PIDPath:    config.PIDPath(),
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create unit: %w", err)
	}
	defer f.Close()

	tmpl := template.Must(template.New("unit").Parse(systemdUnitTemplate))
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("render unit: %w", err)
	}

	for _, args := range [][]string{
		{"--user", "daemon-reload"},
		{"--user", "enable", config.SystemdUnitName},
		{"--user", "start", config.SystemdUnitName},
	} {
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl %v: %w\n%s", args, err, out)
		}
	}
	fmt.Printf("Installed and started %s\n", config.SystemdUnitName)
	fmt.Printf("Unit: %s\n", path)
	return nil
}

// UninstallSystemd stops, disables, and removes the unit.
func UninstallSystemd() error {
	path, err := systemdUnitPath()
	if err != nil {
		return err
	}

	for _, args := range [][]string{
		{"--user", "stop", config.SystemdUnitName},
		{"--user", "disable", config.SystemdUnitName},
	} {
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		if err != nil {
			fmt.Printf("systemctl %v: %s\n", args, out)
		}
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit: %w", err)
	}
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	fmt.Printf("Uninstalled %s\n", config.SystemdUnitName)
	return nil
}
