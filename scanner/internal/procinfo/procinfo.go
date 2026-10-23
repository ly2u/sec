// Package procinfo implements layers L3 (is the fix in effect?) and L4 (is the
// software reachable from the network?) by reading /proc. It never executes
// programs except `rpm -qf` with a fixed argument shape on RPM systems.
package procinfo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ly2u/sec/scanner/internal/system"
	"github.com/ly2u/sec/scanner/internal/version"
)

// StaleProcess is a process still using a library that was replaced on disk.
type StaleProcess struct {
	Name      string   `json:"name"`
	Unit      string   `json:"unit,omitempty"`
	PIDs      []int    `json:"pids"`
	Libraries []string `json:"libraries"`
	Packages  []string `json:"packages"` // source packages owning those libraries
}

// Listener is a listening TCP socket.
type Listener struct {
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	Public   bool     `json:"public"`
	Process  string   `json:"process,omitempty"`
	Exe      string   `json:"exe,omitempty"`
	Unit     string   `json:"unit,omitempty"`
	PID      int      `json:"pid,omitempty"`
	Packages []string `json:"packages,omitempty"` // source packages loaded by the process
}

// Report is everything L3/L4 found.
type Report struct {
	RunningKernel  string         `json:"running_kernel,omitempty"`
	RebootRequired bool           `json:"reboot_required"`
	RebootPackages []string       `json:"reboot_packages,omitempty"`
	Stale          []StaleProcess `json:"stale_processes"`
	Listeners      []Listener     `json:"listeners"`
	// Exposed holds source AND binary package names loaded by publicly
	// listening processes (bundles key on either, depending on the distro).
	Exposed  map[string]bool `json:"-"`
	Complete bool            `json:"complete"` // false when /proc was only partly readable
	Notes    []string        `json:"notes,omitempty"`
}

var pidDir = regexp.MustCompile(`^[0-9]+$`)

// Collect gathers L3/L4 facts. On a non-live root only file-based facts apply.
func Collect(h system.Host, o system.OS, inv *system.Inventory) *Report {
	r := &Report{Exposed: map[string]bool{}, Complete: true}
	if data, err := h.ReadFile("var/run/reboot-required"); err == nil && len(data) > 0 {
		r.RebootRequired = true
		if pk, err := h.ReadFile("var/run/reboot-required.pkgs"); err == nil {
			r.RebootPackages = uniqueLines(pk)
		}
	}
	if !h.Live() {
		r.Complete = false
		r.Notes = append(r.Notes, "未在目标系统上运行，无法检查运行中的内核、进程与监听端口。")
		return r
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		r.RunningKernel = strings.TrimSpace(string(data))
	}

	binToSource := map[string]string{}
	for _, p := range inv.Packages {
		binToSource[p.Name] = p.Source
	}
	owners := newOwnerIndex(h, o, inv)

	procs := listPIDs()
	denied := 0
	stale := map[string]*StaleProcess{}
	inodes := listeningSockets(r)
	socketPID := map[uint64]int{}

	for _, pid := range procs {
		base := filepath.Join("/proc", strconv.Itoa(pid))
		maps, err := os.ReadFile(filepath.Join(base, "maps"))
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		if libs := deletedLibraries(maps); len(libs) > 0 {
			name := comm(base)
			unit := unitOf(base)
			key := unit
			if key == "" {
				key = "comm:" + name
			}
			sp := stale[key]
			if sp == nil {
				sp = &StaleProcess{Name: name, Unit: unit}
				stale[key] = sp
			}
			sp.PIDs = append(sp.PIDs, pid)
			sp.Libraries = mergeSorted(sp.Libraries, libs)
		}
		if len(inodes) > 0 {
			fds, _ := os.ReadDir(filepath.Join(base, "fd"))
			for _, fd := range fds {
				link, err := os.Readlink(filepath.Join(base, "fd", fd.Name()))
				if err != nil || !strings.HasPrefix(link, "socket:[") {
					continue
				}
				ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
				if err == nil {
					if _, ok := inodes[ino]; ok {
						if _, seen := socketPID[ino]; !seen {
							socketPID[ino] = pid
						}
					}
				}
			}
		}
	}
	if denied > 0 {
		r.Complete = false
		r.Notes = append(r.Notes, fmt.Sprintf("有 %d 个进程的信息无权读取；以 root 运行才能完整检查补丁生效状态和暴露面。", denied))
	}

	for _, sp := range stale {
		sp.Packages = owners.sources(sp.Libraries, binToSource)
		sort.Ints(sp.PIDs)
		r.Stale = append(r.Stale, *sp)
	}
	sort.Slice(r.Stale, func(i, j int) bool { return r.Stale[i].Name < r.Stale[j].Name })

	for ino, l := range inodes {
		pid, ok := socketPID[ino]
		if ok {
			base := filepath.Join("/proc", strconv.Itoa(pid))
			l.PID, l.Process, l.Unit = pid, comm(base), unitOf(base)
			files := mappedFiles(base)
			if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
				l.Exe = strings.TrimSuffix(exe, " (deleted)")
				files = append(files, l.Exe)
			}
			l.Packages = owners.sources(files, binToSource)
			if l.Public {
				for _, s := range l.Packages {
					r.Exposed[s] = true
				}
				for _, b := range owners.binaries(files) {
					r.Exposed[b] = true
				}
			}
		}
		r.Listeners = append(r.Listeners, *l)
	}
	sort.Slice(r.Listeners, func(i, j int) bool {
		if r.Listeners[i].Public != r.Listeners[j].Public {
			return r.Listeners[i].Public
		}
		return r.Listeners[i].Port < r.Listeners[j].Port
	})
	return r
}

func listPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		if pidDir.MatchString(e.Name()) {
			if n, err := strconv.Atoi(e.Name()); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

func comm(base string) string {
	data, err := os.ReadFile(filepath.Join(base, "comm"))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}

var unitName = regexp.MustCompile(`([A-Za-z0-9@._\\-]+\.service)`)

// unitOf extracts the systemd service from /proc/PID/cgroup.
func unitOf(base string) string {
	data, err := os.ReadFile(filepath.Join(base, "cgroup"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if m := unitName.FindAllString(line, -1); len(m) > 0 {
			return m[len(m)-1]
		}
	}
	return ""
}

var sharedObject = regexp.MustCompile(`\.so(\.[0-9.]+)?$`)

// deletedLibraries returns shared libraries mapped from files that were
// deleted or replaced on disk (an upgrade happened, the process kept the old copy).
func deletedLibraries(maps []byte) []string {
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(maps))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasSuffix(line, " (deleted)") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		path := strings.Join(fields[5:len(fields)-1], " ")
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "/memfd:") ||
			strings.HasPrefix(path, "/dev/") || strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/run/") {
			continue
		}
		if sharedObject.MatchString(path) || strings.Contains(path, "/lib/") {
			seen[path] = true
		}
	}
	return sortedKeys(seen)
}

func mappedFiles(base string) []string {
	data, err := os.ReadFile(filepath.Join(base, "maps"))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 6 && strings.HasPrefix(fields[5], "/") {
			path := strings.TrimSuffix(strings.Join(fields[5:], " "), " (deleted)")
			if sharedObject.MatchString(path) {
				seen[path] = true
			}
		}
	}
	return sortedKeys(seen)
}

// listeningSockets parses /proc/net/tcp{,6} for LISTEN sockets.
func listeningSockets(r *Report) map[uint64]*Listener {
	out := map[uint64]*Listener{}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if i == 0 {
				continue
			}
			l, ino, ok := ParseProcNetLine(line)
			if ok {
				out[ino] = l
			}
		}
	}
	return out
}

// ParseProcNetLine parses one /proc/net/tcp line, returning LISTEN sockets only.
func ParseProcNetLine(line string) (*Listener, uint64, bool) {
	f := strings.Fields(line)
	if len(f) < 10 || f[3] != "0A" {
		return nil, 0, false
	}
	hostHex, portHex, ok := strings.Cut(f[1], ":")
	if !ok {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	raw, err := hex.DecodeString(hostHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, false
	}
	// /proc stores addresses as host-endian 32-bit words.
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	ino, err := strconv.ParseUint(f[9], 10, 64)
	if err != nil || ino == 0 {
		return nil, 0, false
	}
	l := &Listener{Address: ip.String(), Port: int(port)}
	l.Public = !ip.IsLoopback()
	if v4 := ip.To4(); v4 != nil && len(raw) == 16 && v4.IsLoopback() {
		l.Public = false
	}
	return l, ino, true
}

// ---------------------------------------------------------------- file owners

type ownerIndex struct {
	byPath map[string]string // normalised path -> binary package
	rpm    string            // rpm binary for on-demand lookups
	cache  map[string]string
}

// normalise folds usr-merge aliases: /usr/lib/x and /lib/x are the same file.
func normalise(p string) string {
	p = filepath.Clean(p)
	for _, d := range []string{"/usr/lib", "/usr/lib64", "/usr/bin", "/usr/sbin"} {
		if rest, ok := strings.CutPrefix(p, d+"/"); ok {
			return strings.TrimPrefix(d, "/usr") + "/" + rest
		}
	}
	return p
}

func newOwnerIndex(h system.Host, o system.OS, inv *system.Inventory) *ownerIndex {
	idx := &ownerIndex{byPath: map[string]string{}, cache: map[string]string{}}
	switch o.Kind {
	case version.Deb:
		dir := h.Path("var/lib/dpkg/info")
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			name, ok := strings.CutSuffix(e.Name(), ".list")
			if !ok {
				continue
			}
			pkg, _, _ := strings.Cut(name, ":")
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if sharedObject.MatchString(line) || strings.Contains(line, "/bin/") || strings.Contains(line, "/sbin/") {
					idx.byPath[normalise(line)] = pkg
				}
			}
		}
	case version.APK:
		data, err := h.ReadFile("lib/apk/db/installed")
		if err == nil {
			pkg, dir := "", ""
			for _, line := range strings.Split(string(data), "\n") {
				switch {
				case strings.HasPrefix(line, "P:"):
					pkg = line[2:]
				case strings.HasPrefix(line, "F:"):
					dir = "/" + line[2:]
				case strings.HasPrefix(line, "R:"):
					idx.byPath[normalise(dir+"/"+line[2:])] = pkg
				}
			}
		}
	case version.RPM:
		if !h.NoExec {
			for _, c := range []string{"/usr/bin/rpm", "/bin/rpm"} {
				if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
					idx.rpm = c
					break
				}
			}
		}
	}
	return idx
}

// Owners maps files to the installed package that owns them.
type Owners struct{ idx *ownerIndex }

// NewOwners builds a file-owner lookup for the scanned system.
func NewOwners(h system.Host, o system.OS, inv *system.Inventory) *Owners {
	return &Owners{idx: newOwnerIndex(h, o, inv)}
}

// Owner returns the binary package owning path, or "" if none does.
func (o *Owners) Owner(path string) string { return o.idx.owner(path) }

var safePath = regexp.MustCompile(`^/[A-Za-z0-9._+/@-]+$`)

func (idx *ownerIndex) owner(path string) string {
	if p, ok := idx.byPath[normalise(path)]; ok {
		return p
	}
	if idx.rpm == "" || !safePath.MatchString(path) {
		return ""
	}
	if p, ok := idx.cache[path]; ok {
		return p
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, idx.rpm, "-qf", "--qf", "%{NAME}\n", "--", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	owner := ""
	if err == nil {
		owner = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		if strings.Contains(owner, " ") {
			owner = ""
		}
	}
	idx.cache[path] = owner
	return owner
}

func (idx *ownerIndex) binaries(paths []string) []string {
	set := map[string]bool{}
	for _, p := range paths {
		if bin := idx.owner(p); bin != "" {
			set[bin] = true
		}
	}
	return sortedKeys(set)
}

func (idx *ownerIndex) sources(paths []string, binToSource map[string]string) []string {
	set := map[string]bool{}
	for _, p := range paths {
		if bin := idx.owner(p); bin != "" {
			if src, ok := binToSource[bin]; ok {
				set[src] = true
			} else {
				set[bin] = true
			}
		}
	}
	return sortedKeys(set)
}

// ---------------------------------------------------------------- helpers

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mergeSorted(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		set[x] = true
	}
	return sortedKeys(set)
}

func uniqueLines(data []byte) []string {
	set := map[string]bool{}
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			set[l] = true
		}
	}
	return sortedKeys(set)
}
