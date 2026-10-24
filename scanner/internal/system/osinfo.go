// Package system reads the host's OS identity and installed packages. Every
// read is relative to Root so tests (and offline image scans) can point it at
// an extracted filesystem. Nothing here writes to disk.
package system

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ly2u/sec/scanner/internal/version"
)

// Host is the filesystem being scanned.
type Host struct {
	Root   string // "/" for the live system
	NoExec bool   // forbid running any external program
	fsys   *confined
}

// ContainerHost reads a container's root filesystem (normally
// /proc/PID/root) with every path resolved inside it, never executing
// anything. Close it when done.
func ContainerHost(root string) (Host, error) {
	c, err := openConfined(root)
	if err != nil {
		return Host{}, err
	}
	return Host{Root: root, NoExec: true, fsys: c}, nil
}

// Close releases a ContainerHost.
func (h Host) Close() {
	if h.fsys != nil {
		h.fsys.close()
	}
}

// Open opens a file of the scanned system for reading.
func (h Host) Open(p string) (*os.File, error) {
	if h.fsys != nil {
		return h.fsys.open(p)
	}
	return os.Open(h.Path(p))
}

// ReadDir lists a directory of the scanned system.
func (h Host) ReadDir(p string) ([]os.DirEntry, error) {
	f, err := h.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, err
}

// Live reports whether Host is the running system (so /proc and exec apply).
func (h Host) Live() bool { return filepath.Clean(h.Root) == "/" }

// Path joins p onto the scanned root.
func (h Host) Path(p string) string { return filepath.Join(h.Root, p) }

// ReadFile reads a file of the scanned system (at most 256 MiB).
func (h Host) ReadFile(p string) ([]byte, error) {
	f, err := h.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 256<<20))
}

// OS identifies the distribution and the bundle that covers it.
type OS struct {
	ID         string
	VersionID  string
	PrettyName string
	Distro     string // bundle distro slug: debian, ubuntu, rocky, alma, alpine
	Release    string // bundle release: 12, 24.04, 9, 3.22
	Kind       version.Kind
	Supported  bool
}

// Supported releases mirror collector/distros.py on the server.
var supported = map[string][]string{
	"debian": {"11", "12", "13"},
	"ubuntu": {"20.04", "22.04", "24.04"},
	"rocky":  {"8", "9"},
	"alma":   {"8", "9"},
	"alpine": {"3.22", "3.23", "3.24"},
}

// ParseOSRelease parses /etc/os-release key=value pairs.
func ParseOSRelease(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

// DetectOS identifies the scanned system from os-release.
func DetectOS(h Host) (OS, error) {
	data, err := h.ReadFile("etc/os-release")
	if err != nil {
		data, err = h.ReadFile("usr/lib/os-release")
	}
	if err != nil {
		return OS{}, fmt.Errorf("cannot read os-release: %w", err)
	}
	f := ParseOSRelease(data)
	o := OS{ID: f["ID"], VersionID: f["VERSION_ID"], PrettyName: f["PRETTY_NAME"]}
	switch o.ID {
	case "debian":
		o.Distro, o.Release, o.Kind = "debian", o.VersionID, version.Deb
		if o.Release == "" {
			// testing/sid have no VERSION_ID; there is no bundle for them.
			o.Release = "testing"
		}
	case "ubuntu":
		o.Distro, o.Release, o.Kind = "ubuntu", o.VersionID, version.Deb
	case "rocky":
		o.Distro, o.Release, o.Kind = "rocky", major(o.VersionID), version.RPM
	case "almalinux":
		o.Distro, o.Release, o.Kind = "alma", major(o.VersionID), version.RPM
	case "alpine":
		o.Distro, o.Release, o.Kind = "alpine", majorMinor(o.VersionID), version.APK
	}
	for _, r := range supported[o.Distro] {
		if r == o.Release {
			o.Supported = true
		}
	}
	return o, nil
}

func major(v string) string {
	m, _, _ := strings.Cut(v, ".")
	return m
}

func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}
