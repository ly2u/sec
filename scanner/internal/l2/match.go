package l2

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/version"
)

// MethodLabel is the user-facing name of an install method.
var MethodLabel = map[string]string{
	"baota": "宝塔面板", "lnmp": "一键安装脚本（LNMP/OneinStack 等）", "source": "源码编译",
	"binary": "官方二进制", "nvm": "nvm", "fnm": "fnm", "volta": "volta", "n": "n",
	"process": "运行中的程序（不属于任何软件包）", "package": "第三方软件源", "go": "Go 程序",
}

// Outcome of matching installs against the upstream bundle.
type Outcome struct {
	Findings     []match.Finding
	AlreadyFixed int
	// NoData lists products found on the host for which the data source has
	// no upstream ranges yet; absence of findings there means "unknown".
	NoData []string
}

type group struct {
	in    Install
	paths []string
}

// Evaluate matches discovered installs against upstream ranges. exposed
// reports whether an install is reachable from the network.
func Evaluate(res Result, b *bundle.Bundle, rules []*Rule, exposed func(Install) bool) Outcome {
	var out Outcome
	byName := map[string]*Rule{}
	for _, r := range rules {
		byName[r.Slug] = r
		byName[strings.ToLower(r.Name)] = r
	}
	// Merge installs that are the same software (php and php-fpm of one build).
	groups := map[string]*group{}
	var order []string
	for _, in := range res.Installs {
		if in.Version == "" {
			continue
		}
		k := strings.Join([]string{in.Product, in.Version, in.Method, in.BundledIn, strings.Join(in.Packages, ",")}, "|")
		g := groups[k]
		if g == nil {
			g = &group{in: in}
			groups[k] = g
			order = append(order, k)
		}
		if in.Path != "" {
			g.paths = append(g.paths, in.Path)
		}
		g.in.Running = g.in.Running || in.Running
	}
	noData := map[string]bool{}
	for _, k := range order {
		g := groups[k]
		in, rule := g.in, byName[g.in.Product]
		if rule == nil {
			continue
		}
		entries := b.SourcePackages[in.Product]
		if len(entries) == 0 {
			noData[rule.Name] = true
			continue
		}
		byVuln := map[string][]bundle.Entry{}
		var keys []string
		for _, e := range entries {
			vk := match.VulnKey(e)
			if _, ok := byVuln[vk]; !ok {
				keys = append(keys, vk)
			}
			byVuln[vk] = append(byVuln[vk], e)
		}
		sort.Strings(keys)
		isExposed := exposed != nil && exposed(in)
		for _, vk := range keys {
			f, fixed := evaluate(in, g.paths, rule, byName, vk, byVuln[vk])
			if fixed {
				out.AlreadyFixed++
				continue
			}
			f.Exposed = isExposed
			out.Findings = append(out.Findings, f)
		}
	}
	for n := range noData {
		out.NoData = append(out.NoData, n)
	}
	sort.Strings(out.NoData)
	return out
}

func evaluate(in Install, paths []string, rule *Rule, byName map[string]*Rule, key string, entries []bundle.Entry) (match.Finding, bool) {
	f := match.Finding{
		ID: key, Package: rule.Name, InstalledVersion: in.Version, Layer: "L2",
		Method: in.Method, Path: strings.Join(paths, "、"),
	}
	if len(in.Packages) > 0 {
		f.Binaries = in.Packages
	} else {
		f.Binaries = paths
	}
	match.Enrich(&f, entries)
	affected := false
	var events []version.Event
	for _, e := range entries {
		for _, r := range e.Ranges {
			if r.Type != "UPSTREAM" {
				continue
			}
			events = append(events, r.Events...)
			a, err := version.Affected(version.Upstream, in.Version, r.Events)
			if err != nil {
				f.Status, f.Fix = match.Unknown, match.FixNone
				f.Notes = append(f.Notes, "版本无法比较："+err.Error())
				return f, false
			}
			affected = affected || a
		}
	}
	if !affected {
		return f, true
	}
	f.Status = match.ConfirmedAffected
	// The smallest fixed release above the installed one; for an end-of-life
	// line this is the fix in the next supported branch.
	fix, err := version.FirstFixAbove(version.Upstream, in.Version, events)
	if err != nil || fix == "" {
		f.Fix = match.FixNone
		f.DistroStatus = "unfixed"
		f.Notes = append(f.Notes, "上游尚未发布修复版本，或该版本系列已停止维护。")
	} else {
		f.Fix, f.FixedVersion = match.FixUpgrade, fix
	}
	switch {
	case in.BundledIn != "":
		host := byName[strings.ToLower(in.BundledIn)]
		how := "升级或重新编译 " + in.BundledIn
		if host != nil {
			how = host.UpgradeText(in.Method, "")
		}
		f.Guidance = fmt.Sprintf("这份 %s 是编译进 %s 的，系统里的 %s 升级不会影响它。需要%s，并确认新版本内置的 %s 不低于 %s。",
			rule.Name, in.BundledIn, rule.Name, how, rule.Name, orLatest(f.FixedVersion))
	case in.Method == "package":
		// The report renders a package-manager command for these.
	default:
		f.Guidance = rule.UpgradeText(in.Method, f.FixedVersion)
	}
	return f, false
}

func orLatest(v string) string {
	if v == "" {
		return "最新的受支持版本"
	}
	return v
}
