// Package match evaluates installed distro packages against a verified bundle
// (layer L1 of docs/ARCHITECTURE.md D3).
package match

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/system"
	"github.com/ly2u/sec/scanner/internal/version"
)

// Status is one of the five verdicts defined in the PRD (9.3).
type Status string

const (
	ConfirmedAffected   Status = "CONFIRMED_AFFECTED"
	PotentiallyAffected Status = "POTENTIALLY_AFFECTED"
	Fixed               Status = "FIXED"
	NotApplicable       Status = "NOT_APPLICABLE"
	Unknown             Status = "UNKNOWN"
)

// FixKind tells the user what kind of action resolves a finding.
type FixKind string

const (
	FixUpgrade      FixKind = "upgrade"      // a standard update is available
	FixSubscription FixKind = "subscription" // only via Ubuntu Pro (ESM)
	FixNone         FixKind = "none"         // distro has not fixed it (yet)
	FixReboot       FixKind = "reboot"       // fixed kernel installed, not running
)

// Finding is one vulnerability affecting one source package.
type Finding struct {
	ID               string        `json:"id"`
	CVEs             []string      `json:"cve_ids"`
	Advisories       []string      `json:"advisories"`
	Package          string        `json:"package"`  // bundle key (source/origin/binary name)
	Binaries         []string      `json:"binaries"` // installed binary packages affected
	InstalledVersion string        `json:"installed_version"`
	FixedVersion     string        `json:"fixed_version,omitempty"`
	Status           Status        `json:"status"`
	Fix              FixKind       `json:"fix"`
	Kernel           bool          `json:"kernel,omitempty"`
	Severity         string        `json:"severity,omitempty"`
	CVSS             *float64      `json:"cvss,omitempty"`
	KEV              bool          `json:"kev"`
	EPSS             *float64      `json:"epss,omitempty"`
	Refs             []string      `json:"refs"`
	Origin           system.Origin `json:"origin"`
	Notes            []string      `json:"notes,omitempty"`
	Exposed          bool          `json:"exposed"`
	Priority         string        `json:"priority"`
	DistroStatus     string        `json:"distro_status,omitempty"`
	Urgency          string        `json:"urgency,omitempty"`
	// Layer is "L1" (distro package) or "L2" (installed outside the package
	// manager, or from a third-party repository).
	Layer string `json:"layer"`
	// L2 only: how it was installed, where, and how to upgrade it.
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	Guidance string `json:"guidance,omitempty"`
	// Minor: the distro rates this negligible (Debian "unimportant").
	Minor bool `json:"minor,omitempty"`
}

// Group is one source package version and the binaries built from it.
type Group struct {
	Key      string
	Alt      []string // extra bundle keys to consult (kernel signing remaps)
	Version  string
	Binaries []string
	Origin   system.Origin
	Label    string
	Kernel   bool
}

// Input bundles everything L1 needs.
type Input struct {
	OS        system.OS
	Inventory *system.Inventory
	Bundle    *bundle.Bundle
	// RunningKernel is /proc/sys/kernel/osrelease; empty if unknown.
	RunningKernel string
}

// Result is the L1 outcome.
type Result struct {
	Findings         []Finding
	ThirdParty       []system.Package // not covered by distro data
	PackagesScanned  int
	SourcesEvaluated int
	SourcesNoKnown   int // official sources with no entries in the bundle
	FixedCount       int // vulnerabilities already fixed by the installed version
	// MinorUnfixed counts unfixed issues the distro rates negligible
	// (Debian "unimportant" / "end-of-life"); they are not reported.
	MinorUnfixed int
	Kernel       KernelState
	Notes        []string
}

// KernelState summarises installed vs running kernels.
type KernelState struct {
	Running        string `json:"running"`
	RunningVersion string `json:"running_version,omitempty"`
	NewestVersion  string `json:"newest_version,omitempty"`
	NewerInstalled bool   `json:"newer_installed"`
	Known          bool   `json:"known"`
}

var (
	debKernelBinary = regexp.MustCompile(`^linux-(?:image|modules)-(?:unsigned-|extra-)?([0-9].*)$`)
	rpmKernelCore   = map[string]bool{"kernel": true, "kernel-core": true, "kernel-modules": true, "kernel-modules-core": true, "kernel-modules-extra": true}
	signedArch      = regexp.MustCompile(`^linux-signed(?:-(?:amd64|arm64|i386|armhf|ppc64el|s390x))?$`)
)

// debKernelSource maps signed-kernel source names to the source the security
// trackers actually use ("linux-signed-amd64" -> "linux").
func debKernelSource(src string) string {
	if signedArch.MatchString(src) {
		return "linux"
	}
	if rest, ok := strings.CutPrefix(src, "linux-signed-"); ok {
		return "linux-" + rest
	}
	return src
}

// buildGroups turns binary packages into evaluation groups, keeping only the
// running kernel's packages and dropping kernel-adjacent userspace packages
// (linux-libc-dev, kernel-headers…) that would otherwise misattribute kernel CVEs.
func buildGroups(in Input) ([]Group, KernelState) {
	key := in.Bundle.PackageKey
	ks := KernelState{Running: in.RunningKernel}
	type gk struct{ key, version string }
	groups := map[gk]*Group{}
	kernelSources := map[string]bool{}

	isDeb := in.OS.Kind == version.Deb
	isRPM := in.OS.Kind == version.RPM

	// Pass 1: find kernel packages and the sources they come from.
	type kpkg struct {
		p       system.Package
		release string
	}
	var kernels []kpkg
	for _, p := range in.Inventory.Packages {
		switch {
		case isDeb:
			if m := debKernelBinary.FindStringSubmatch(p.Name); m != nil {
				kernels = append(kernels, kpkg{p, strings.TrimSuffix(m[1], "-unsigned")})
				kernelSources[p.Source] = true
				kernelSources[debKernelSource(p.Source)] = true
			}
		case isRPM:
			if rpmKernelCore[p.Name] {
				_, vr, _ := strings.Cut(p.Version, ":")
				kernels = append(kernels, kpkg{p, vr + "." + p.Arch})
				kernelSources[p.Source] = true
			}
		}
	}
	// Running and newest kernel versions.
	for _, k := range kernels {
		if k.release == in.RunningKernel {
			ks.Known = true
			ks.RunningVersion = kernelVersion(in.OS.Kind, k.p)
		}
		v := kernelVersion(in.OS.Kind, k.p)
		if ks.NewestVersion == "" {
			ks.NewestVersion = v
		} else if c, err := version.Compare(in.OS.Kind, v, ks.NewestVersion); err == nil && c > 0 {
			ks.NewestVersion = v
		}
	}
	if ks.Known && ks.NewestVersion != "" {
		if c, err := version.Compare(in.OS.Kind, ks.NewestVersion, ks.RunningVersion); err == nil && c > 0 {
			ks.NewerInstalled = true
		}
	}

	add := func(k, v string, p system.Package, kernel bool, alt []string) {
		id := gk{k, v}
		g := groups[id]
		if g == nil {
			g = &Group{Key: k, Version: v, Origin: p.Origin, Label: p.OriginLabel, Kernel: kernel, Alt: alt}
			groups[id] = g
		}
		g.Binaries = append(g.Binaries, p.Name)
		// A group is only as trustworthy as its least-verified member.
		if rank(p.Origin) > rank(g.Origin) {
			g.Origin, g.Label = p.Origin, p.OriginLabel
		}
	}

	for _, p := range in.Inventory.Packages {
		kernelPkg := false
		release := ""
		switch {
		case isDeb:
			if m := debKernelBinary.FindStringSubmatch(p.Name); m != nil {
				kernelPkg, release = true, strings.TrimSuffix(m[1], "-unsigned")
			}
		case isRPM:
			if rpmKernelCore[p.Name] {
				_, vr, _ := strings.Cut(p.Version, ":")
				kernelPkg, release = true, vr+"."+p.Arch
			}
		}
		if kernelPkg {
			// Only the running kernel is exposed. If the running kernel is
			// unknown (offline root scan), evaluate the newest one instead.
			if ks.Known && release != in.RunningKernel {
				continue
			}
			if !ks.Known && kernelVersion(in.OS.Kind, p) != ks.NewestVersion {
				continue
			}
			v := kernelVersion(in.OS.Kind, p)
			switch {
			case isDeb:
				src := debKernelSource(p.Source)
				var alt []string
				if src != p.Source {
					alt = []string{p.Source}
				}
				add(src, v, p, true, alt)
			case key == "binary":
				add(p.Name, p.Version, p, true, nil)
			default:
				add(p.Source, p.SourceVersion, p, true, nil)
			}
			continue
		}
		if kernelSources[p.Source] {
			// linux-libc-dev, linux-headers-*, kernel-headers, kernel-tools…:
			// built from the kernel source but not the running kernel.
			continue
		}
		switch key {
		case "binary":
			add(p.Name, p.Version, p, false, nil)
		default: // "source" (dpkg/rpm) and "origin" (apk)
			add(p.Source, p.SourceVersion, p, false, nil)
		}
	}
	out := make([]Group, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.Binaries)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Version < out[j].Version
	})
	return out, ks
}

// kernelVersion is the version compared against the kernel source. For Debian
// signed images the binary version equals the "linux" source version (the
// Source field carries the linux-signed-* version instead).
func kernelVersion(_ version.Kind, p system.Package) string {
	return p.Version
}

func rank(o system.Origin) int {
	switch o {
	case system.Official:
		return 0
	case system.Unverified:
		return 1
	default:
		return 2
	}
}

// vulnKey groups entries that describe the same vulnerability.
func vulnKey(e bundle.Entry) string {
	if len(e.CVEIDs) == 1 {
		return e.CVEIDs[0]
	}
	return e.ID
}

type channelVerdict struct {
	present  bool
	affected bool
	fix      string
	unfixed  bool // affected and no fixed event at all
	wontFix  bool
}

func evaluateChannel(kind version.Kind, v string, entries []bundle.Entry) (channelVerdict, error) {
	var cv channelVerdict
	for _, e := range entries {
		cv.present = true
		for _, r := range e.Ranges {
			if r.Type != "ECOSYSTEM" {
				continue
			}
			aff, err := version.Affected(kind, v, r.Events)
			if err != nil {
				return cv, err
			}
			if !aff {
				continue
			}
			cv.affected = true
			fix, err := version.FirstFixAbove(kind, v, r.Events)
			if err != nil {
				return cv, err
			}
			if fix == "" {
				cv.unfixed = true
			} else if cv.fix == "" {
				cv.fix = fix
			} else if c, err := version.Compare(kind, fix, cv.fix); err == nil && c > 0 {
				// Several advisories for one CVE: the highest fix ends them all.
				cv.fix = fix
			}
		}
		if e.Status == "wont_fix" {
			cv.wontFix = true
		}
	}
	return cv, nil
}

// Evaluate runs L1 matching.
func Evaluate(in Input) Result {
	res := Result{PackagesScanned: len(in.Inventory.Packages)}
	groups, ks := buildGroups(in)
	res.Kernel = ks
	if in.RunningKernel != "" && !ks.Known && ks.NewestVersion != "" {
		res.Notes = append(res.Notes, "未找到与运行中内核 "+in.RunningKernel+" 对应的内核包，内核结论基于已安装的最新内核。")
	}
	thirdSeen := map[string]bool{}
	for _, p := range in.Inventory.Packages {
		if p.Origin == system.ThirdParty && !thirdSeen[p.Name] {
			thirdSeen[p.Name] = true
			res.ThirdParty = append(res.ThirdParty, p)
		}
	}

	for _, g := range groups {
		if g.Origin == system.ThirdParty {
			continue
		}
		entries := append([]bundle.Entry{}, in.Bundle.SourcePackages[g.Key]...)
		for _, a := range g.Alt {
			entries = append(entries, in.Bundle.SourcePackages[a]...)
		}
		res.SourcesEvaluated++
		if len(entries) == 0 {
			res.SourcesNoKnown++
			continue
		}
		byVuln := map[string][]bundle.Entry{}
		var order []string
		for _, e := range entries {
			k := vulnKey(e)
			if _, ok := byVuln[k]; !ok {
				order = append(order, k)
			}
			byVuln[k] = append(byVuln[k], e)
		}
		sort.Strings(order)
		for _, k := range order {
			f, counted := evaluateVuln(in, g, k, byVuln[k], ks)
			if !counted && f.Minor && f.Fix == FixNone && f.Status != Unknown {
				// Kept (flagged) so --all and JSON consumers can audit what was hidden.
				res.MinorUnfixed++
			}
			if counted {
				res.FixedCount++
				continue
			}
			res.Findings = append(res.Findings, f)
		}
	}
	return res
}

// evaluateVuln returns a finding, or counted=true when the installed version
// already contains the fix.
//
// Ubuntu publishes the same CVE on a standard channel and, after standard
// support ends, on the Pro (ESM) channel. The verdicts are merged so the user
// gets one conclusion, never two contradictory ones.
func evaluateVuln(in Input, g Group, key string, entries []bundle.Entry, ks KernelState) (Finding, bool) {
	var std, pro []bundle.Entry
	for _, e := range entries {
		if e.RequiresSubscription {
			pro = append(pro, e)
		} else {
			std = append(std, e)
		}
	}
	f := Finding{
		ID: key, Package: g.Key, Binaries: g.Binaries, InstalledVersion: g.Version,
		Origin: g.Origin, Kernel: g.Kernel, Layer: "L1",
	}
	enrich(&f, entries)

	sv, err := evaluateChannel(in.OS.Kind, g.Version, std)
	var pv channelVerdict
	if err == nil {
		pv, err = evaluateChannel(in.OS.Kind, g.Version, pro)
	}
	if err != nil {
		f.Status, f.Fix = Unknown, FixNone
		f.Notes = append(f.Notes, "版本无法解析，不能判定："+err.Error())
		return f, false
	}

	switch {
	case pv.present && !pv.affected:
		// The installed version already carries the Pro/ESM fix.
		return f, true
	case !sv.present && !pv.present:
		return f, true
	case !sv.present:
		return proFinding(in, f, g, pv), false
	case !sv.affected:
		return f, true
	case sv.fix == "" && pv.present && pv.fix != "":
		return proFinding(in, f, g, pv), false
	}

	f.Status = statusFor(g.Origin)
	switch {
	case sv.fix != "":
		f.Fix, f.FixedVersion = FixUpgrade, sv.fix
	case sv.wontFix:
		f.Fix = FixNone
		f.DistroStatus = "wont_fix"
		f.Notes = append(f.Notes, "发行版已决定不单独修复（通常为低风险问题），请评估缓解措施。")
	default:
		f.Fix = FixNone
		f.DistroStatus = "unfixed"
		f.Notes = append(f.Notes, "发行版尚未发布修复（Debian 数据无法区分“尚未修复”与“判定为次要、暂不修复”）。")
	}
	if g.Kernel && f.Fix == FixUpgrade && ks.NewerInstalled && ks.NewestVersion != "" {
		if c, err := version.Compare(in.OS.Kind, ks.NewestVersion, f.FixedVersion); err == nil && c >= 0 {
			f.Fix = FixReboot
			f.Notes = append(f.Notes, fmt.Sprintf("已安装修复后的内核 %s，但当前运行的仍是旧内核；重启后生效。", ks.NewestVersion))
		}
	}
	return f, false
}

func proFinding(in Input, f Finding, g Group, pv channelVerdict) Finding {
	f.Status = statusFor(g.Origin)
	if pv.fix == "" {
		f.Fix = FixNone
		f.DistroStatus = "unfixed"
		return f
	}
	f.FixedVersion = pv.fix
	if in.Inventory.UbuntuPro {
		f.Fix = FixUpgrade
		f.Notes = append(f.Notes, "修复来自 Ubuntu Pro（ESM）；本机已启用 Pro，可直接升级。")
	} else {
		f.Fix = FixSubscription
		f.Notes = append(f.Notes, "修复仅在 Ubuntu Pro（ESM）中提供；标准软件源中没有可升级的版本。")
	}
	return f
}

// VulnKey and Enrich let layer L2 group and annotate entries exactly like L1.
func VulnKey(e bundle.Entry) string { return vulnKey(e) }

// Enrich fills CVE ids, references, CVSS, EPSS and KEV from entries.
func Enrich(f *Finding, entries []bundle.Entry) { enrich(f, entries) }

func statusFor(o system.Origin) Status {
	if o == system.Official {
		return ConfirmedAffected
	}
	return PotentiallyAffected
}

var severityRank = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2, "LOW": 1}

// urgencyRank orders Debian urgencies; unknown values rank as "medium" so an
// unrecognised rating never hides an issue.
var urgencyRank = map[string]int{"end-of-life": 0, "unimportant": 0, "low": 1, "medium": 2, "not yet assigned": 2, "high": 3}

func enrich(f *Finding, entries []bundle.Entry) {
	cves, advs, refs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	bestUrgency, sawUrgency, allMinor := -1, false, true
	defer func() {
		// Minor only if every record that rates the issue calls it negligible.
		f.Minor = sawUrgency && allMinor
	}()
	for _, e := range entries {
		if e.Urgency != nil && *e.Urgency != "" {
			u := strings.ToLower(strings.Trim(*e.Urgency, "* "))
			r, ok := urgencyRank[u]
			if !ok {
				r = 2
			}
			sawUrgency = true
			if r > 0 {
				allMinor = false
			}
			if r > bestUrgency {
				bestUrgency, f.Urgency = r, u
			}
		} else {
			allMinor = false
		}
		for _, c := range e.CVEIDs {
			cves[c] = true
		}
		if e.AdvisoryID != "" {
			advs[e.AdvisoryID] = true
		}
		if strings.HasPrefix(e.Ref, "https://") {
			refs[e.Ref] = true
		}
		if e.KEV {
			f.KEV = true
		}
		if e.CVSS != nil && (f.CVSS == nil || *e.CVSS > *f.CVSS) {
			v := *e.CVSS
			f.CVSS = &v
		}
		if e.EPSS != nil && (f.EPSS == nil || *e.EPSS > *f.EPSS) {
			v := *e.EPSS
			f.EPSS = &v
		}
		if e.Severity != nil && severityRank[strings.ToUpper(*e.Severity)] > severityRank[f.Severity] {
			f.Severity = strings.ToUpper(*e.Severity)
		}
	}
	f.CVEs, f.Advisories, f.Refs = keys(cves), keys(advs), keys(refs)
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
