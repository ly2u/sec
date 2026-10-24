package gobin

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/version"
)

func TestGoSemver(t *testing.T) {
	for in, want := range map[string]string{
		"go1.21.5":                   "1.21.5",
		"go1.20":                     "1.20.0",
		"go1.22rc1":                  "1.22.0-rc.1",
		"go1.21.5 X:boringcrypto":    "1.21.5",
		"devel go1.23-abc +0000 UTC": "",
	} {
		if got := GoSemver(in); got != want {
			t.Errorf("GoSemver(%q) = %q, want %q", in, got, want)
		}
	}
}

func entry(id, fixed string) bundle.Entry {
	cvss := 7.5
	return bundle.Entry{ID: id, CVEIDs: []string{id}, CVSS: &cvss, Ref: "https://pkg.go.dev/vuln/GO-2099-0001",
		Ranges: []bundle.Range{{Type: "SEMVER", Events: []version.Event{{Introduced: "0"}, {Fixed: fixed}}}}}
}

// secwatch itself is a real Go program: its build info has the Go version and
// the modules linked into it (klauspost/compress via the bundle package).
func secwatchBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "secwatch")
	cmd := exec.Command("go", "build", "-o", out, "github.com/ly2u/sec/scanner/cmd/secwatch")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

func TestInspectAndEvaluateRealBinary(t *testing.T) {
	prog, ok := Inspect(secwatchBinary(t), "/usr/local/bin/tool")
	if !ok {
		t.Fatal("the test binary is a Go program")
	}
	if prog.Name != "tool" || prog.GoVersion != GoSemver(runtime.Version()) {
		t.Errorf("program: %+v", prog)
	}
	var compress Module
	for _, d := range prog.Deps {
		if d.Path == "github.com/klauspost/compress" {
			compress = d
		}
	}
	if compress.Version == "" {
		t.Fatalf("dependency versions are read without the leading v: %+v", prog.Deps)
	}
	b := &bundle.Bundle{SourcePackages: map[string][]bundle.Entry{
		"github.com/klauspost/compress": {entry("CVE-2099-0001", "99.0.0")},
		"stdlib":                        {entry("CVE-2099-0002", "99.0.0"), entry("CVE-2099-0003", "1.0.0")},
	}}
	fs := Evaluate([]Program{prog}, b, func(Program) bool { return true })
	if len(fs) != 2 {
		t.Fatalf("one dependency and one stdlib finding (the stdlib issue fixed in 1.0.0 does not apply): %+v", fs)
	}
	for _, f := range fs {
		if f.Status != match.PotentiallyAffected || f.Component == "" || f.Package != "tool" || !f.Exposed || f.Method != "go" {
			t.Errorf("bundled code is potentially affected and labelled: %+v", f)
		}
	}
	if !strings.HasPrefix(fs[1].Component, "Go ") || !strings.HasSuffix(fs[1].Component, "标准库") {
		t.Errorf("stdlib label: %q", fs[1].Component)
	}
}

// xcaddy builds have main module "caddy" without a version; the program's own
// module is the dependency named like the binary.
func TestCoreModuleIsConfirmed(t *testing.T) {
	p := Program{Path: "/usr/bin/caddy", Name: "caddy", Package: "caddy", Core: Module{Path: "github.com/caddyserver/caddy/v2", Version: "2.10.2"}}
	b := &bundle.Bundle{SourcePackages: map[string][]bundle.Entry{"github.com/caddyserver/caddy/v2": {entry("CVE-2099-0004", "2.10.3")}}}
	fs := Evaluate([]Program{p}, b, nil)
	if len(fs) != 1 {
		t.Fatal(fs)
	}
	f := fs[0]
	if f.Status != match.ConfirmedAffected || f.Component != "" || f.FixedVersion != "2.10.3" || f.InstalledVersion != "2.10.2" {
		t.Errorf("%+v", f)
	}
	if f.Method != "package" || len(f.Binaries) != 1 || f.Binaries[0] != "caddy" {
		t.Error("a program from a third-party package is upgraded with its package manager")
	}
}

func TestCollectSkipsOfficialAndNonGoFiles(t *testing.T) {
	dir := t.TempDir()
	exe, _ := os.Executable()
	data, _ := os.ReadFile(exe)
	os.WriteFile(filepath.Join(dir, "frpc"), data, 0o755)
	os.WriteFile(filepath.Join(dir, "docker"), data, 0o755)
	os.WriteFile(filepath.Join(dir, "script.sh"), []byte("#!/bin/sh\n"+strings.Repeat("x", 2000)), 0o755)
	cands := []Candidate{
		{Open: filepath.Join(dir, "frpc"), Path: "/usr/local/bin/frpc"},
		{Open: filepath.Join(dir, "frpc"), Path: "/usr/local/bin/frpc", Running: true},
		{Open: filepath.Join(dir, "docker"), Path: "/usr/bin/docker"},
		{Open: filepath.Join(dir, "script.sh"), Path: "/usr/local/bin/script.sh"},
	}
	owner := func(p string) (string, bool) {
		if p == "/usr/bin/docker" {
			return "docker.io", true // the distro's own data covers it
		}
		return "", false
	}
	got := Collect(cands, owner)
	if len(got) != 1 || got[0].Name != "frpc" || !got[0].Running {
		t.Fatalf("%+v", got)
	}
}

func TestProcessesFindsOwnExecutable(t *testing.T) {
	exe, _ := os.Executable()
	if len(ContainerProcesses("/proc", nil)) != 0 {
		t.Error("a container without processes has no programs")
	}
	for _, c := range HostProcesses("/proc") {
		if c.Path == exe {
			return
		}
	}
	t.Error("the test process itself must be listed")
}

func TestProjectAndUnit(t *testing.T) {
	for core, want := range map[string]string{
		"github.com/komari-monitor/komari-agent": "https://github.com/komari-monitor/komari-agent/releases",
		"github.com/caddyserver/caddy/v2":        "https://github.com/caddyserver/caddy/releases",
		"gitlab.com/group/tool/cmd/x":            "https://gitlab.com/group/tool/-/releases",
		"example.com/private/thing":              "",
		"github.com/x/..":                        "",
		"github.com/bad;owner/repo":              "",
	} {
		if got := (Program{Core: Module{Path: core}}).Project(); got != want {
			t.Errorf("Project(%s) = %q, want %q", core, got, want)
		}
	}
	dir := t.TempDir()
	for name, cg := range map[string]string{
		"1": "0::/system.slice/komari-agent.service\n",
		"2": "0::/user.slice/user-0.slice/session-3.scope\n",
		"3": "0::/system.slice/system-getty.slice/getty@tty1.service\n",
		"4": "0::/system.slice/evil;rm.service\n",
	} {
		os.MkdirAll(filepath.Join(dir, name), 0o755)
		os.WriteFile(filepath.Join(dir, name, "cgroup"), []byte(cg), 0o644)
	}
	for pid, want := range map[string]string{"1": "komari-agent.service", "2": "", "3": "getty@tty1.service", "4": ""} {
		if got := unitOf(filepath.Join(dir, pid)); got != want {
			t.Errorf("unitOf(%s) = %q, want %q", pid, got, want)
		}
	}
}
