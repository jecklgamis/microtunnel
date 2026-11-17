package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"

	"github.com/jecklgamis/microtunnel/internal/setup"
)

// How a configured machine is started as a service. Linux uses the systemd units
// the packages install (microtunnel, microtunnel@<name>); macOS uses a launchd
// job (see setup.LaunchdPlist), which `-start` writes if it is missing.

// serviceName is what messages call the service for the instance called name.
func serviceName(name string) string {
	if runtime.GOOS == "darwin" {
		return setup.Label(name)
	}
	return setup.Unit(name)
}

// startHint is the command that starts the service for the instance called name.
func startHint(name, configFile, dir string) string {
	return startHintOS(runtime.GOOS, name, configFile, dir, fileExists(setup.PlistPath(name)))
}

func startHintOS(goos, name, configFile, dir string, plistExists bool) string {
	if goos == "darwin" {
		if plistExists {
			return "sudo launchctl bootstrap system " + setup.PlistPath(name)
		}
		return "sudo microtunnel -c " + configFile + "   # foreground; add -start to install it as a launchd service"
	}
	if isDefaultDir(dir) {
		return "sudo systemctl enable --now " + setup.Unit(name)
	}
	return "sudo microtunnel -c " + configFile
}

// canStartService reports whether `-start` can work for a config in dir. systemd
// units read the fixed /etc/microtunnel/<name>.yaml; a launchd job is generated
// for whatever config was written, so any directory works.
func canStartService(dir string) bool {
	return runtime.GOOS == "darwin" || isDefaultDir(dir)
}

// startService enables and starts the service for the instance called name.
func startService(name, configFile string, stderr io.Writer) error {
	if runtime.GOOS == "darwin" {
		return launchdStart(name, configFile, stderr)
	}
	return systemctlEnableNow(setup.Unit(name), stderr)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func systemctlEnableNow(unit string, stderr io.Writer) error {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return fmt.Errorf("-start needs systemd, but systemctl was not found; start it yourself with `microtunnel -c <config>`")
	}
	cmd := exec.Command(path, "enable", "--now", unit)
	cmd.Stdout, cmd.Stderr = stderr, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl enable --now %s: %w (config and keys were written; fix the cause and run it yourself)", unit, err)
	}
	return nil
}

// launchdStart writes the launchd job if it is not there yet, then (re)loads it so
// the daemon picks up the config that was just written. RunAtLoad starts it.
func launchdStart(name, configFile string, stderr io.Writer) error {
	plist := setup.PlistPath(name)
	if !fileExists(plist) {
		bin, err := os.Executable()
		if err != nil {
			bin = "/usr/local/bin/microtunnel"
		}
		if err := os.WriteFile(plist, []byte(setup.LaunchdPlist(name, bin, configFile)), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w (run with sudo)", plist, err)
		}
	}
	// Ignore the result: the job is usually not loaded yet.
	_ = exec.Command("launchctl", "bootout", "system/"+setup.Label(name)).Run()
	cmd := exec.Command("launchctl", "bootstrap", "system", plist)
	cmd.Stdout, cmd.Stderr = stderr, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("launchctl bootstrap system %s: %w (config and keys were written; fix the cause and run it yourself)", plist, err)
	}
	return nil
}
