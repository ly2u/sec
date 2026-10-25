// Package gobin finds Go-compiled programs and matches the modules and Go
// version recorded in them (what `go version -m` prints) against the Go
// vulnerability database. Like Trivy and Grype, it needs no package manager:
// Caddy, frp, Xray, Alist or a self-built service are judged from the binary.
//
// Files are only opened and read; nothing is executed.
package gobin

import (
	"bytes"
	"debug/buildinfo"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/container"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/system"
	"github.com/ly2u/sec/scanner/internal/version"
)

// Module is a Go module and its version without the leading "v".
type Module struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
}

// Program is one Go binary.
type Program struct {
	Path      string   `json:"path"`
	Name      string   `json:"name"`
	GoVersion string   `json:"go_version,omitempty"` // semver, e.g. 1.21.5
	Core      Module   `json:"module"`               // the module that is the program itself
	Deps      []Module `json:"-"`
	Running   bool     `json:"running,omitempty"`
	Package   string   `json:"package,omitempty"` // owning third-party package, if any
	MainPath  string   `json:"main_module,omitempty"`
	Unit      string   `json:"unit,omitempty"` // systemd service running it
}

var (
	githubRe = regexp.MustCompile(`^github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})(?:/|$)`)
	gitlabRe = regexp.MustCompile(`^gitlab\.com/([A-Za-z0-9][A-Za-z0-9_.-]{0,99})/([A-Za-z0-9._-]{1,100})(?:/|$)`)
	unitRe   = regexp.MustCompile(`(?m)/system\.slice/(?:[A-Za-z0-9@._-]+\.slice/)*([A-Za-z0-9@._-]{1,128}\.service)(?:/|$)`)
)

// Project is where new releases of the program are published, derived from
// its module path (GitHub and GitLab only); "" if unknown.
func (p Program) Project() string {
	for _, m := range []string{p.Core.Path, p.MainPath} {
		if g := githubRe.FindStringSubmatch(m); g != nil && g[2] != "." && g[2] != ".." {
			return "https://github.com/" + g[1] + "/" + strings.TrimSuffix(g[2], ".git") + "/releases"
		}
		if g := gitlabRe.FindStringSubmatch(m); g != nil && g[2] != "." && g[2] != ".." {
			return "https://gitlab.com/" + g[1] + "/" + strings.TrimSuffix(g[2], ".git") + "/-/releases"
		}
	}
	return ""
}

// Display is the name shown in reports: the project's repository name when the
// file name is a generic part of it ("agent" from komari-agent), else the file
// name (frpc stays frpc, caddy stays caddy).
func (p Program) Display() string {
	for _, m := range []string{p.Core.Path, p.MainPath} {
		g := githubRe.FindStringSubmatch(m)
		if g == nil {
			g = gitlabRe.FindStringSubmatch(m)
		}
		if g == nil {
			continue
		}
		repo := strings.TrimSuffix(g[2], ".git")
		if repo != p.Name && len(repo) <= 40 && strings.Contains(strings.ToLower(repo), strings.ToLower(p.Name)) {
			return repo
		}
		break
	}
	return p.Name
}

// unitOf returns the systemd service of a process from its cgroup, or "".
func unitOf(procPid string) string {
	data, err := os.ReadFile(filepath.Join(procPid, "cgroup"))
	if err != nil {
		return ""
	}
	if m := unitRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

const (
	maxSize       = 512 << 20
	maxCandidates = 400
)

// readInfo parses the build info of an open file; nil if it is not a Go
// program. The parser is the standard library's, guarded against panics on
// crafted files.
func readInfo(f *os.File) (bi *buildinfo.BuildInfo) {
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1024 || st.Size() > maxSize {
		return nil
	}
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil || !bytes.Equal(magic, []byte("\x7fELF")) {
		return nil
	}
	defer func() {
		if recover() != nil {
			bi = nil
		}
	}()
	info, err := buildinfo.Read(f)
	if err != nil {
		return nil
	}
	return info
}

var goRelease = regexp.MustCompile(`^go([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:(rc|beta)([0-9]+))?$`)

// GoSemver turns "go1.21.5" into "1.21.5" and "go1.22rc1" into
// "1.22.0-rc.1", the form the Go vulnerability database uses. Development
// builds return "".
func GoSemver(v string) string {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return ""
	}
	m := goRelease.FindStringSubmatch(fields[0])
	if m == nil {
		return ""
	}
	patch := m[3]
	if patch == "" {
		patch = "0"
	}
	s := m[1] + "." + m[2] + "." + patch
	if m[4] != "" {
		s += "-" + m[4] + "." + m[5]
	}
	return s
}

func moduleVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	if v == "" || v == "(devel)" {
		return ""
	}
	if _, err := version.Compare(version.Go, v, v); err != nil {
		return ""
	}
	return v
}

var majorSuffix = regexp.MustCompile(`/v[0-9]+$`)

// program builds a Program from build info. The core module is the main
// module when it has a version; otherwise (xcaddy-style builds) the dependency
// named like the binary, e.g. github.com/caddyserver/caddy/v2 for "caddy".
func program(p, name string, bi *buildinfo.BuildInfo) Program {
	prog := Program{Path: p, Name: name, GoVersion: GoSemver(bi.GoVersion), MainPath: bi.Main.Path}
	mod := func(m *debug.Module) Module {
		if m.Replace != nil {
			return Module{Path: m.Replace.Path, Version: moduleVersion(m.Replace.Version)}
		}
		return Module{Path: m.Path, Version: moduleVersion(m.Version)}
	}
	main := Module{Path: bi.Main.Path, Version: moduleVersion(bi.Main.Version)}
	prog.Core = main
	for _, d := range bi.Deps {
		m := mod(d)
		prog.Deps = append(prog.Deps, m)
		if main.Version == "" && path.Base(majorSuffix.ReplaceAllString(d.Path, "")) == name {
			prog.Core = m
		}
	}
	return prog
}

// Inspect reads one file; ok is false if it is not a Go program.
func Inspect(file, display string) (Program, bool) {
	f, err := os.Open(file)
	if err != nil {
		return Program{}, false
	}
	defer f.Close()
	bi := readInfo(f)
	if bi == nil {
		return Program{}, false
	}
	return program(display, filepath.Base(display), bi), true
}

var pidDir = regexp.MustCompile(`^[0-9]+$`)

// Candidate is a file that may be a Go program.
type Candidate struct {
	Open    string // path to open (may be /proc/PID/exe)
	Path    string // path as the system sees it
	Running bool
	Unit    string // systemd service, for running host programs
}

// HostProcesses lists the executables of running processes in the scanner's
// own mount namespace (the host).
func HostProcesses(proc string) []Candidate { return processes(proc, nil, true) }

// ContainerProcesses lists the executables of the given processes (one
// container); /proc/PID/exe opens the file inside the container.
func ContainerProcesses(proc string, pids []int) []Candidate { return processes(proc, pids, false) }

func processes(proc string, pids []int, host bool) []Candidate {
	var dirs []string
	if host {
		entries, _ := os.ReadDir(proc)
		for _, e := range entries {
			if pidDir.MatchString(e.Name()) {
				dirs = append(dirs, e.Name())
			}
		}
	} else {
		for _, p := range pids {
			dirs = append(dirs, strconv.Itoa(p))
		}
	}
	seen := map[string]bool{}
	var out []Candidate
	for _, d := range dirs {
		base := filepath.Join(proc, d)
		// Containers are scanned separately. A different mount namespace alone
		// does not mean a container: systemd services with ProtectSystem or
		// PrivateTmp (Caddy, MariaDB, nginx…) have one too.
		if host && container.ID(base) != "" {
			continue
		}
		exe, err := os.Readlink(filepath.Join(base, "exe"))
		if err != nil {
			continue
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		if seen[exe] {
			continue
		}
		seen[exe] = true
		c := Candidate{Open: filepath.Join(base, "exe"), Path: exe, Running: true}
		if host {
			c.Unit = unitOf(base)
		}
		out = append(out, c)
	}
	return out
}

// Files lists executables in the usual places for software installed by hand
// (/usr/local/bin, /usr/local/sbin, /opt/*, /opt/*/bin) plus extra paths.
func Files(h system.Host, extra []string) []Candidate {
	var paths []string
	for _, dir := range []string{"usr/local/bin", "usr/local/sbin"} {
		paths = append(paths, listDir(h, dir)...)
	}
	for _, sub := range listDirs(h, "opt") {
		paths = append(paths, listDir(h, sub)...)
		paths = append(paths, listDir(h, sub+"/bin")...)
	}
	paths = append(paths, extra...)
	var out []Candidate
	for _, p := range paths {
		out = append(out, Candidate{Open: h.Path(p), Path: "/" + strings.TrimPrefix(p, "/")})
	}
	return out
}

func listDir(h system.Host, dir string) []string {
	entries, err := os.ReadDir(h.Path(dir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			out = append(out, dir+"/"+e.Name())
		}
	}
	return out
}

func listDirs(h system.Host, dir string) []string {
	entries, err := os.ReadDir(h.Path(dir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, dir+"/"+e.Name())
		}
	}
	return out
}

// DebFiles lists the executables a third-party Debian package installed in
// the usual binary directories (from /var/lib/dpkg/info/<pkg>.list).
func DebFiles(h system.Host, pkgs []string) []string {
	var out []string
	for _, p := range pkgs {
		for _, name := range []string{p + ".list", p + ":amd64.list", p + ":arm64.list"} {
			data, err := h.ReadFile("var/lib/dpkg/info/" + name)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				dir := path.Dir(line)
				switch dir {
				case "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin":
					out = append(out, strings.TrimPrefix(line, "/"))
				}
			}
			break
		}
	}
	return out
}

// Owner reports the package owning a path and whether that package comes
// from the distribution (whose own data already covers it).
type Owner func(path string) (pkg string, official bool)

// Collect inspects candidates, skipping files owned by official packages and
// duplicates (the same file seen running and on disk).
func Collect(cands []Candidate, owner Owner) []Program {
	byPath := map[string]int{}
	var out []Program
	for _, c := range cands {
		if i, ok := byPath[c.Path]; ok {
			if i >= 0 {
				out[i].Running = out[i].Running || c.Running
				if out[i].Unit == "" {
					out[i].Unit = c.Unit
				}
			}
			continue
		}
		pkg, official := "", false
		if owner != nil {
			pkg, official = owner(c.Path)
		}
		if official {
			continue
		}
		if len(out) >= maxCandidates {
			break
		}
		prog, ok := Inspect(c.Open, c.Path)
		if !ok {
			byPath[c.Path] = -1
			continue
		}
		prog.Running, prog.Package, prog.Unit = c.Running, pkg, c.Unit
		byPath[c.Path] = len(out)
		out = append(out, prog)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Evaluate matches programs against the golang-1 bundle. Findings about the
// program's own module are confirmed; findings about bundled dependencies and
// the Go standard library are "potentially affected" (whether the vulnerable
// code is reachable is not checked) and carry a Component label.
func Evaluate(progs []Program, b *bundle.Bundle, exposed func(Program) bool) []match.Finding {
	var out []match.Finding
	for _, p := range progs {
		type target struct {
			mod       Module
			component string
		}
		targets := []target{}
		if p.Core.Version != "" {
			targets = append(targets, target{p.Core, ""})
		}
		for _, d := range p.Deps {
			if d.Path != p.Core.Path && d.Version != "" {
				targets = append(targets, target{d, "依赖 " + d.Path + " " + d.Version})
			}
		}
		if p.GoVersion != "" {
			targets = append(targets, target{Module{Path: "stdlib", Version: p.GoVersion}, "Go " + p.GoVersion + " 标准库"})
		}
		isExposed := exposed != nil && exposed(p)
		for _, t := range targets {
			byVuln := map[string][]bundle.Entry{}
			var keys []string
			for _, e := range b.SourcePackages[t.mod.Path] {
				k := match.VulnKey(e)
				if _, ok := byVuln[k]; !ok {
					keys = append(keys, k)
				}
				byVuln[k] = append(byVuln[k], e)
			}
			sort.Strings(keys)
			for _, k := range keys {
				f, ok := evaluate(p, t.mod, t.component, k, byVuln[k])
				if ok {
					f.Exposed = isExposed
					out = append(out, f)
				}
			}
		}
	}
	return out
}

func evaluate(p Program, m Module, component, key string, entries []bundle.Entry) (match.Finding, bool) {
	installed := p.Core.Version
	if installed == "" {
		installed = "版本未知"
	}
	f := match.Finding{
		ID: key, Package: p.Display(), InstalledVersion: installed, Layer: "L2", Method: "go",
		Path: p.Path, Component: component, Module: m.Path, ModuleVersion: m.Version, Project: p.Project(), Unit: p.Unit,
	}
	if p.Package != "" {
		f.Method, f.Binaries = "package", []string{p.Package}
	}
	var events []version.Event
	affected := false
	for _, e := range entries {
		for _, r := range e.Ranges {
			if r.Type != "SEMVER" {
				continue
			}
			a, err := version.Affected(version.Go, m.Version, r.Events)
			if err != nil {
				return f, false
			}
			events = append(events, r.Events...)
			affected = affected || a
		}
	}
	if !affected {
		return f, false
	}
	match.Enrich(&f, entries)
	f.Status = match.ConfirmedAffected
	if component != "" {
		f.Status = match.PotentiallyAffected
	}
	fix, err := version.FirstFixAbove(version.Go, m.Version, events)
	if err != nil || fix == "" {
		f.Fix, f.DistroStatus = match.FixNone, "unfixed"
	} else {
		f.Fix, f.FixedVersion = match.FixUpgrade, fix
	}
	return f, true
}

// Describe is a short line for listings: "Go 程序，caddy 2.10.2，Go 1.25.1".
func (p Program) Describe() string {
	s := "Go 程序"
	if p.Core.Version != "" {
		s += fmt.Sprintf("，%s %s", path.Base(majorSuffix.ReplaceAllString(p.Core.Path, "")), p.Core.Version)
	}
	if p.GoVersion != "" {
		s += "，Go " + p.GoVersion
	}
	return s
}
