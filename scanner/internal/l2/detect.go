package l2

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ly2u/sec/scanner/internal/container"
	"github.com/ly2u/sec/scanner/internal/system"
)

// Install is one piece of software found outside the distribution's packages.
type Install struct {
	Product       string   `json:"product"`
	ProductName   string   `json:"product_name"`
	Version       string   `json:"version,omitempty"`
	Method        string   `json:"method"`         // baota, lnmp, source, binary, nvm, fnm, volta, n, process, package
	Path          string   `json:"path,omitempty"` // program path (empty for packages)
	Packages      []string `json:"packages,omitempty"`
	OriginLabel   string   `json:"origin_label,omitempty"`
	VersionSource string   `json:"version_source"` // exec, path, package
	BundledIn     string   `json:"bundled_in,omitempty"`
	Running       bool     `json:"running"`
	Stale         bool     `json:"stale,omitempty"` // a running process uses a replaced binary
	Note          string   `json:"note,omitempty"`
}

// ContainerProcess is a relevant program running inside a container; its
// filesystem is not inspected in this version.
type ContainerProcess struct {
	Product   string `json:"product"`
	Name      string `json:"name"`
	PID       int    `json:"pid"`
	Container string `json:"container,omitempty"`
}

// Env is what discovery needs from the rest of the scanner.
type Env struct {
	Host      system.Host
	Inventory *system.Inventory
	Owner     func(path string) string // package owning a file, "" if none
}

// Result of L2 discovery.
type Result struct {
	Installs   []Install          `json:"installs"`
	Containers []ContainerProcess `json:"container_processes"`
	Notes      []string           `json:"notes,omitempty"`
}

// Discover finds non-package installs and third-party repository packages.
func Discover(env Env, rules []*Rule) Result {
	d := &discovery{env: env, rules: rules, seen: map[string]bool{}, byName: map[string]*Rule{}}
	for _, r := range rules {
		d.byName[r.Slug] = r
	}
	d.packages()
	d.paths()
	if env.Host.Live() {
		d.processes()
	}
	sort.SliceStable(d.res.Installs, func(i, j int) bool {
		a, b := d.res.Installs[i], d.res.Installs[j]
		if a.Product != b.Product {
			return a.Product < b.Product
		}
		return a.Path+strings.Join(a.Packages, ",") < b.Path+strings.Join(b.Packages, ",")
	})
	return d.res
}

type discovery struct {
	env    Env
	rules  []*Rule
	byName map[string]*Rule
	seen   map[string]bool // resolved paths already handled
	res    Result
}

// packages maps third-party repository packages (nginx.org, Docker, NodeSource,
// sury, PGDG…) to products. Official packages are layer L1's job.
func (d *discovery) packages() {
	type key struct{ product, version string }
	found := map[key]*Install{}
	var order []key
	for _, p := range d.env.Inventory.Packages {
		if p.Origin != system.ThirdParty {
			continue
		}
		for _, r := range d.rules {
			if !r.ownsPackage(p) {
				continue
			}
			re := r.packageVersionRe
			if re == nil {
				re = defaultPackageVersion
			}
			v := ""
			if m := re.FindStringSubmatch(p.Version); m != nil {
				v = m[1]
			}
			k := key{r.Slug, v}
			in := found[k]
			if in == nil {
				in = &Install{Product: r.Slug, ProductName: r.Name, Version: v, Method: "package",
					VersionSource: "package", OriginLabel: p.OriginLabel}
				if v == "" {
					in.Note = "无法从软件包版本 " + p.Version + " 中识别上游版本"
				}
				found[k] = in
				order = append(order, k)
			}
			in.Packages = append(in.Packages, p.Name)
			break
		}
	}
	for _, k := range order {
		sort.Strings(found[k].Packages)
		d.res.Installs = append(d.res.Installs, *found[k])
	}
}

func (r *Rule) ownsPackage(p system.Package) bool {
	for _, n := range r.Detect.Packages.Names {
		if p.Name == n || p.Source == n {
			return true
		}
	}
	return r.sourceRe != nil && (r.sourceRe.MatchString(p.Source) || r.sourceRe.MatchString(p.Name))
}

// paths checks the fixed install locations of every rule.
func (d *discovery) paths() {
	for _, r := range d.rules {
		for _, b := range r.Detect.Binaries {
			matches, _ := filepath.Glob(d.env.Host.Path(b.Glob))
			sort.Strings(matches)
			for _, m := range matches {
				rel := "/" + strings.TrimPrefix(m, filepath.Clean(d.env.Host.Root))
				rel = filepath.Clean(rel)
				d.probe(r, rel, m, b.Method, false)
			}
		}
	}
}

// probe determines the version of one program (logical path rel, real path
// on disk real) unless it belongs to a package or was already handled.
func (d *discovery) probe(r *Rule, rel, real, method string, running bool) {
	info, err := os.Stat(real)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	key := real
	if resolved, err := filepath.EvalSymlinks(real); err == nil {
		key = resolved
	}
	if d.seen[key] {
		if running {
			d.markRunning(key)
		}
		return
	}
	if d.env.Owner != nil && d.env.Owner(rel) != "" {
		return // managed by the package manager: L1 / third-party package handling
	}
	d.seen[key] = true

	in := Install{Product: r.Slug, ProductName: r.Name, Method: method, Path: rel, Running: running}
	if r.pathVersionRe != nil {
		if m := r.pathVersionRe.FindStringSubmatch(rel); m != nil {
			in.Version, in.VersionSource = m[1], "path"
		}
	}
	var output string
	if in.Version == "" || len(r.Detect.Bundled) > 0 || len(r.Detect.Variants) > 0 {
		switch {
		case d.env.Host.NoExec:
			if in.Version == "" {
				in.Note = "--no-exec 模式下未执行程序，无法读取版本"
			}
		case !d.env.Host.Live():
			if in.Version == "" {
				in.Note = "扫描挂载的文件系统时不执行其中的程序，无法读取版本"
			}
		default:
			out, err := runVersion(real, r.Detect.VersionArgs)
			switch {
			case err == nil:
				output = out
			case in.Version == "":
				in.Note = "出于安全原因未执行该程序：" + reason(err)
			}
		}
	}
	product := r
	if output != "" {
		re := r.versionRe
		for _, v := range r.Detect.Variants {
			if strings.Contains(output, v.Contains) {
				if alt := d.byName[v.Product]; alt != nil {
					product, re = alt, v.re
				}
			}
		}
		if m := re.FindStringSubmatch(output); m != nil {
			in.Version, in.VersionSource = m[1], "exec"
		} else if in.Version == "" {
			in.Note = "已执行，但未能从输出中识别版本号"
		}
		in.Product, in.ProductName = product.Slug, product.Name
		for _, b := range r.Detect.Bundled {
			if m := b.re.FindStringSubmatch(output); m != nil {
				if br := d.byName[b.Product]; br != nil {
					d.res.Installs = append(d.res.Installs, Install{
						Product: br.Slug, ProductName: br.Name, Version: m[1], Method: method,
						Path: rel, VersionSource: "exec", BundledIn: r.Name, Running: running,
					})
				}
			}
		}
	}
	d.res.Installs = append(d.res.Installs, in)
}

func (d *discovery) markRunning(key string) {
	for i := range d.res.Installs {
		p := d.res.Installs[i].Path
		if r, err := filepath.EvalSymlinks(d.env.Host.Path(p)); err == nil && r == key {
			d.res.Installs[i].Running = true
		}
	}
}

func reason(err error) string {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, errUnsafe.Error()+": ")
	switch {
	case strings.Contains(msg, "not owned by root"):
		return "程序或其所在目录不属于 root（" + msg + "）"
	case strings.Contains(msg, "writable by other users"):
		return "程序或其所在目录可被其他用户修改（" + msg + "）"
	}
	return msg
}

var pidDir = regexp.MustCompile(`^[0-9]+$`)

// processes inspects running programs: it finds installs in unusual locations
// and notes relevant programs running inside containers.
func (d *discovery) processes() {
	self, _ := os.Readlink("/proc/self/ns/mnt")
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	names := map[string]*Rule{}
	for _, r := range d.rules {
		for _, n := range r.Detect.ProcessNames {
			names[n] = r
		}
	}
	for _, e := range entries {
		if !pidDir.MatchString(e.Name()) {
			continue
		}
		pid, _ := strconv.Atoi(e.Name())
		base := filepath.Join("/proc", e.Name())
		exe, err := os.Readlink(filepath.Join(base, "exe"))
		if err != nil {
			continue
		}
		deleted := strings.HasSuffix(exe, " (deleted)")
		exe = strings.TrimSuffix(exe, " (deleted)")
		r := names[filepath.Base(exe)]
		if r == nil {
			continue
		}
		if ns, err := os.Readlink(filepath.Join(base, "ns/mnt")); err == nil && self != "" && ns != self {
			d.res.Containers = append(d.res.Containers, ContainerProcess{
				Product: r.Slug, Name: filepath.Base(exe), PID: pid, Container: containerID(base),
			})
			continue
		}
		if deleted {
			d.res.Installs = append(d.res.Installs, Install{
				Product: r.Slug, ProductName: r.Name, Method: "process", Path: exe, Running: true, Stale: true,
				Note: fmt.Sprintf("进程 %d 运行的程序文件已被替换（通常是升级后未重启），实际运行的是旧版本，请重启该服务", pid),
			})
			continue
		}
		method := "process"
		for _, b := range r.Detect.Binaries {
			if ok, _ := filepath.Match(b.Glob, exe); ok {
				method = b.Method
			}
		}
		d.probe(r, exe, exe, method, true)
	}
	d.res.Containers = dedupeContainers(d.res.Containers)
}

func containerID(base string) string {
	if id := container.ID(base); id != "" {
		return id[:12]
	}
	return ""
}

func dedupeContainers(in []ContainerProcess) []ContainerProcess {
	seen := map[string]bool{}
	var out []ContainerProcess
	for _, c := range in {
		k := c.Product + "/" + c.Container
		if c.Container == "" {
			k += "/" + strconv.Itoa(c.PID)
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	return out
}
