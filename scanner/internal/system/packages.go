package system

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"

	"github.com/ly2u/sec/scanner/internal/version"
)

// Origin classifies where an installed package came from.
type Origin string

const (
	// Official: from the distribution's own (security-supported) repositories.
	Official Origin = "official"
	// ThirdParty: another repository (nginx.org, Docker, NodeSource, sury, EPEL…)
	// or a locally installed file. Distro data does not cover it.
	ThirdParty Origin = "third_party"
	// Unverified: the origin cannot be determined (e.g. apt lists were deleted).
	Unverified Origin = "unverified"
)

// Package is one installed binary package.
type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
	Arch          string `json:"arch,omitempty"`
	Origin        Origin `json:"origin"`
	OriginLabel   string `json:"origin_label,omitempty"`
}

// ValidPackageName is the whitelist used before a name may appear in any
// suggested command.
var ValidPackageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,127}$`)

// ---------------------------------------------------------------- dpkg

type stanza map[string]string

func parseStanzas(r io.Reader, want map[string]bool, fn func(stanza)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	cur := stanza{}
	last := ""
	flush := func() {
		if len(cur) > 0 {
			fn(cur)
		}
		cur = stanza{}
		last = ""
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last != "" && want[last] {
				cur[last] += "\n" + strings.TrimSpace(line)
			}
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		last = k
		if want[k] {
			cur[k] = strings.TrimSpace(v)
		}
	}
	flush()
	return sc.Err()
}

// ParseDpkgStatus reads installed packages from a dpkg status file.
func ParseDpkgStatus(r io.Reader) ([]Package, error) {
	var pkgs []Package
	want := map[string]bool{"Package": true, "Status": true, "Version": true, "Source": true, "Architecture": true}
	err := parseStanzas(r, want, func(s stanza) {
		st := strings.Fields(s["Status"])
		if len(st) != 3 || st[2] != "installed" || s["Package"] == "" || s["Version"] == "" {
			return
		}
		p := Package{Name: s["Package"], Version: s["Version"], Arch: s["Architecture"]}
		p.Source, p.SourceVersion = p.Name, p.Version
		if src := s["Source"]; src != "" {
			name, rest, _ := strings.Cut(src, " ")
			p.Source = name
			// "Source: linux-signed-amd64 (6.1.106+3)" carries a different version (binNMU etc.).
			if v := strings.Trim(strings.TrimSpace(rest), "()"); v != "" {
				p.SourceVersion = v
			}
		}
		pkgs = append(pkgs, p)
	})
	return pkgs, err
}

// ---------------------------------------------------------------- apt origin

type aptIndex struct {
	versions map[string]map[string]Origin // name -> version -> origin
	labels   map[string]string            // name+"\x00"+version -> label
	official map[string][]string          // name -> versions in official lists
	third    map[string]bool              // name present in a third-party list
	// Source packages the official archive currently builds. Kernel images
	// (linux-image-6.1.0-9-amd64) get a new binary name with every ABI bump,
	// so an old official kernel is found by its source, not its name.
	officialSrc map[string]bool
	lists       int
	skipped     int
	esm         bool // Ubuntu Pro (ESM) repositories are configured
}

var officialOrigins = map[string]bool{
	"Debian": true, "Ubuntu": true, "UbuntuESM": true, "UbuntuESMApps": true,
}

func releaseOrigin(h Host, packagesFile string) (string, string) {
	i := strings.Index(packagesFile, "_dists_")
	if i < 0 {
		return "", ""
	}
	rest := packagesFile[i+len("_dists_"):]
	suite, _, _ := strings.Cut(rest, "_")
	prefix := packagesFile[:i] + "_dists_" + suite + "_"
	for _, name := range []string{"InRelease", "Release"} {
		data, err := h.ReadFile(filepath.Join("var/lib/apt/lists", prefix+name))
		if err != nil {
			continue
		}
		return parseReleaseOrigin(data)
	}
	return "", ""
}

// parseReleaseOrigin reads Origin/Label from a Release or InRelease file.
// InRelease is PGP clear-signed: an armor header ("Hash: SHA512") and a blank
// line precede the actual fields, which end at the next blank line.
func parseReleaseOrigin(data []byte) (string, string) {
	origin, label := "", ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	inArmor, started := false, false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "-----BEGIN PGP SIGNED MESSAGE-----") {
			inArmor = true
			continue
		}
		if inArmor {
			if line == "" {
				inArmor = false
			}
			continue
		}
		if line == "" {
			if started {
				break // end of the Release field paragraph
			}
			continue
		}
		started = true
		if v, ok := strings.CutPrefix(line, "Origin:"); ok {
			origin = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Label:"); ok {
			label = strings.TrimSpace(v)
		}
	}
	return origin, label
}

func loadAptIndex(h Host) *aptIndex {
	idx := &aptIndex{
		versions: map[string]map[string]Origin{}, labels: map[string]string{},
		official: map[string][]string{}, third: map[string]bool{}, officialSrc: map[string]bool{},
	}
	entries, err := h.ReadDir("var/lib/apt/lists")
	if err != nil {
		return idx
	}
	for _, e := range entries {
		idx.addList(h, e.Name())
	}
	return idx
}

// listSuffixes maps compressed index suffixes to their decoders. Docker images
// ship apt with Acquire::GzipIndexes, which keeps indexes compressed on disk.
var listSuffixes = map[string]func(io.Reader) (io.Reader, error){
	"":     func(r io.Reader) (io.Reader, error) { return r, nil },
	".gz":  func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) },
	".lz4": func(r io.Reader) (io.Reader, error) { return lz4.NewReader(r), nil },
	".xz":  func(r io.Reader) (io.Reader, error) { return xz.NewReader(r) },
	".bz2": func(r io.Reader) (io.Reader, error) { return bzip2.NewReader(r), nil },
	".zst": func(r io.Reader) (io.Reader, error) {
		d, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	},
}

func (idx *aptIndex) addList(h Host, name string) {
	i := strings.LastIndex(name, "_Packages")
	if i < 0 {
		return
	}
	suffix := name[i+len("_Packages"):]
	if strings.Contains(strings.ToLower(suffix), "diff") {
		return // pdiff bookkeeping, not an index
	}
	decode, ok := listSuffixes[suffix]
	if !ok {
		idx.skipped++ // unknown index compression; packages fall back to third-party
		return
	}
	f, err := h.Open(filepath.Join("var/lib/apt/lists", name))
	if err != nil {
		return
	}
	defer f.Close()
	reader, err := decode(f)
	if err != nil {
		idx.skipped++
		return
	}
	if c, ok := reader.(io.Closer); ok && reader != io.Reader(f) {
		defer c.Close()
	}
	name = strings.TrimSuffix(name, suffix)
	origin, label := releaseOrigin(h, name)
	cls := ThirdParty
	if officialOrigins[origin] {
		cls = Official
	}
	if label == "" {
		label = origin
	}
	if !readableLabel.MatchString(label) {
		// Some repositories publish placeholders (NodeSource ". nodistro",
		// "source=none"); the host the list came from is clearer.
		if host, _, ok := strings.Cut(name, "_"); ok && hostName.MatchString(host) {
			label = host
		}
	}
	if strings.HasPrefix(origin, "UbuntuESM") {
		idx.esm = true
	}
	idx.lists++
	_ = parseStanzas(reader, map[string]bool{"Package": true, "Version": true, "Source": true}, func(s stanza) {
		n, v := s["Package"], s["Version"]
		if n == "" || v == "" {
			return
		}
		if cls == Official {
			src, _, _ := strings.Cut(s["Source"], " ")
			if src == "" {
				src = n
			}
			idx.officialSrc[src] = true
		}
		if idx.versions[n] == nil {
			idx.versions[n] = map[string]Origin{}
		}
		if prev, ok := idx.versions[n][v]; !ok || prev != Official {
			idx.versions[n][v] = cls
			idx.labels[n+"\x00"+v] = label
		}
		if cls == Official {
			idx.official[n] = append(idx.official[n], v)
		} else {
			idx.third[n] = true
		}
	})
}

var (
	readableLabel = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 ._/+-]{0,47}$`)
	hostName      = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
)

// classify decides a dpkg package's origin. apt lists only hold the newest
// version of each package, so an outdated (and therefore likely vulnerable)
// official package will not match exactly; name membership and ordering
// against the newest official version decide those cases.
func (idx *aptIndex) classify(p Package) (Origin, string) {
	if idx.lists == 0 {
		return Unverified, ""
	}
	if o, ok := idx.versions[p.Name][p.Version]; ok {
		return o, idx.labels[p.Name+"\x00"+p.Version]
	}
	off, inThird := idx.official[p.Name], idx.third[p.Name]
	switch {
	case len(off) > 0 && !inThird:
		return Official, "官方源（已有更新版本）"
	case len(off) == 0 && inThird:
		return ThirdParty, "第三方源"
	case len(off) == 0 && !inThird && idx.officialSrc[p.Source]:
		// Renamed binary of a source the official archive still builds
		// (e.g. an old kernel ABI package): an outdated official package.
		return Official, "官方源（旧版本，软件源中已更名）"
	case len(off) == 0 && !inThird:
		return ThirdParty, "本地安装或已移除的软件源"
	}
	newest := off[0]
	for _, v := range off[1:] {
		if c, err := version.Compare(version.Deb, v, newest); err == nil && c > 0 {
			newest = v
		}
	}
	if c, err := version.Compare(version.Deb, p.Version, newest); err == nil && c <= 0 {
		return Official, "官方源（已有更新版本）"
	}
	return ThirdParty, "第三方源（版本高于官方源）"
}

// ---------------------------------------------------------------- rpm

// RPMQueryFormat is the only argument shape ever passed to rpm.
const RPMQueryFormat = `%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{VENDOR}\n`

// ParseRPMQuery parses the output of rpm -qa --qf RPMQueryFormat.
func ParseRPMQuery(out []byte, vendorMatch string) []Package {
	var pkgs []Package
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 7 || f[0] == "gpg-pubkey" || f[5] == "(none)" {
			continue
		}
		epoch := f[1]
		if epoch == "(none)" || epoch == "" {
			epoch = "0"
		}
		evr := epoch + ":" + f[2] + "-" + f[3]
		p := Package{Name: f[0], Version: evr, Arch: f[4], SourceVersion: evr, OriginLabel: f[6]}
		p.Source = sourceRPMName(f[5])
		if p.Source == "" {
			p.Source = p.Name
		}
		if vendorMatch != "" && strings.Contains(strings.ToLower(f[6]), vendorMatch) {
			p.Origin = Official
		} else {
			p.Origin = ThirdParty
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// sourceRPMName turns "openssl-3.2.2-6.el9_5.1.src.rpm" into "openssl".
func sourceRPMName(srpm string) string {
	s := strings.TrimSuffix(strings.TrimSuffix(srpm, ".rpm"), ".src")
	s = strings.TrimSuffix(s, ".nosrc")
	for i := 0; i < 2; i++ {
		j := strings.LastIndex(s, "-")
		if j <= 0 {
			return ""
		}
		s = s[:j]
	}
	return s
}

func findBinary(h Host, candidates ...string) (string, error) {
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
			return c, nil
		}
	}
	return "", fmt.Errorf("none of %v found", candidates)
}

// runFixed executes an absolute-path binary with fixed arguments, no shell,
// a minimal environment and a timeout.
func runFixed(bin string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(bin) {
		return nil, errors.New("refusing relative binary path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	cmd.Stdin = nil
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", filepath.Base(bin), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// ---------------------------------------------------------------- apk

// ParseAPKInstalled reads /lib/apk/db/installed.
func ParseAPKInstalled(r io.Reader) []Package {
	var pkgs []Package
	cur := Package{}
	flush := func() {
		if cur.Name != "" && cur.Version != "" {
			if cur.Source == "" {
				cur.Source = cur.Name
			}
			cur.SourceVersion = cur.Version
			// apk does not record the repository per package.
			cur.Origin, cur.OriginLabel = Official, "Alpine（无法区分软件源，按官方处理）"
			pkgs = append(pkgs, cur)
		}
		cur = Package{}
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		switch line[0] {
		case 'P':
			cur.Name = line[2:]
		case 'V':
			cur.Version = line[2:]
		case 'o':
			cur.Source = line[2:]
		case 'A':
			cur.Arch = line[2:]
		}
	}
	flush()
	return pkgs
}

// ---------------------------------------------------------------- entry point

// Inventory is everything known about installed packages.
type Inventory struct {
	Packages []Package
	Notes    []string
	// UbuntuPro is true when ESM repositories are configured, i.e. fixes that
	// require a Pro subscription are installable on this machine.
	UbuntuPro bool
}

// ReadPackages reads installed packages for the detected OS.
func ReadPackages(h Host, o OS) (*Inventory, error) {
	inv := &Inventory{}
	switch o.Kind {
	case version.Deb:
		f, err := h.Open("var/lib/dpkg/status")
		if err != nil {
			return nil, fmt.Errorf("read dpkg status: %w", err)
		}
		defer f.Close()
		pkgs, err := ParseDpkgStatus(f)
		if err != nil {
			return nil, err
		}
		idx := loadAptIndex(h)
		if idx.lists == 0 {
			inv.Notes = append(inv.Notes, NoteNoAptLists)
		}
		if idx.skipped > 0 {
			inv.Notes = append(inv.Notes, fmt.Sprintf("有 %d 个压缩格式的软件源索引未解析，相应软件包按第三方处理。", idx.skipped))
		}
		for i := range pkgs {
			pkgs[i].Origin, pkgs[i].OriginLabel = idx.classify(pkgs[i])
		}
		inv.UbuntuPro = idx.esm
		inv.Packages = pkgs
	case version.RPM:
		if !h.Live() || h.NoExec {
			return nil, errors.New("读取 RPM 数据库需要在本机运行 rpm（--root 扫描和 --no-exec 模式下不可用）")
		}
		bin, err := findBinary(h, "/usr/bin/rpm", "/bin/rpm")
		if err != nil {
			return nil, err
		}
		out, err := runFixed(bin, "-qa", "--qf", RPMQueryFormat)
		if err != nil {
			return nil, err
		}
		vendor := map[string]string{"rocky": "rocky", "alma": "almalinux"}[o.Distro]
		inv.Packages = ParseRPMQuery(out, vendor)
	case version.APK:
		f, err := h.Open("lib/apk/db/installed")
		if err != nil {
			return nil, fmt.Errorf("read apk database: %w", err)
		}
		defer f.Close()
		inv.Packages = ParseAPKInstalled(f)
		inv.Notes = append(inv.Notes, "Alpine 的包数据库不记录软件来源，所有软件包按官方仓库处理。")
	default:
		return nil, fmt.Errorf("unsupported package manager for %s", o.ID)
	}
	sort.Slice(inv.Packages, func(i, j int) bool { return inv.Packages[i].Name < inv.Packages[j].Name })
	return inv, nil
}

// NoteNoAptLists is added when /var/lib/apt/lists is empty (common in
// container images, which delete it to save space).
const NoteNoAptLists = "未找到 apt 软件源索引（/var/lib/apt/lists 为空，可能已被清理），无法核实软件包来源；结论会降级为“可能受影响”。执行 apt-get update 后重新扫描可获得确定结论。"
