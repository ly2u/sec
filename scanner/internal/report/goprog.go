package report

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/version"
)

// Go programs get their own view: which compiled-in component is behind the
// vulnerabilities, which version of it is needed, and concrete steps (where
// to download, which service to restart) instead of a list of CVE numbers.

var pseudoVersion = regexp.MustCompile(`^0\.0\.0-([0-9]{4})([0-9]{2})([0-9]{2})[0-9]{6}-[0-9a-f]{12}$`)

// displayVersion turns a Go pseudo-version into something readable.
func displayVersion(v string) string {
	if m := pseudoVersion.FindStringSubmatch(v); m != nil {
		return fmt.Sprintf("未标版本号（%s-%s-%s 的代码）", m[1], m[2], m[3])
	}
	return v
}

type goComponent struct {
	label, installed string
	vulns, unfixed   int
	need             string // highest fixed version among its findings
	own              bool
}

// goComponents summarises a Go program's findings by component, the
// program's own module first, then the standard library, then dependencies.
func goComponents(fs []match.Finding) []goComponent {
	by := map[string]*goComponent{}
	var order []string
	seen := map[string]bool{}
	for _, f := range fs {
		key := f.Module
		c := by[key]
		if c == nil {
			c = &goComponent{installed: f.ModuleVersion, own: f.Component == ""}
			switch {
			case c.own:
				c.label = "程序本身（" + f.Module + "）"
			case f.Module == "stdlib":
				c.label = "Go 标准库"
			default:
				c.label = f.Module
			}
			by[key] = c
			order = append(order, key)
		}
		id := key + "\x00" + f.ID
		if seen[id] {
			continue
		}
		seen[id] = true
		if isFixable(f) && f.FixedVersion != "" {
			c.vulns++
			if c.need == "" {
				c.need = f.FixedVersion
			} else if n, err := version.Compare(version.Go, f.FixedVersion, c.need); err == nil && n > 0 {
				c.need = f.FixedVersion
			}
		} else {
			c.unfixed++
		}
	}
	out := make([]goComponent, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		rank := func(c goComponent) int {
			switch {
			case c.own:
				return 0
			case c.label == "Go 标准库":
				return 1
			}
			return 2
		}
		if rank(out[i]) != rank(out[j]) {
			return rank(out[i]) < rank(out[j])
		}
		return out[i].vulns+out[i].unfixed > out[j].vulns+out[j].unfixed
	})
	return out
}

func (c goComponent) needText() string {
	var s string
	switch {
	case c.need == "":
		s = "暂无修复版本"
	case c.label == "Go 标准库":
		s = "用 Go " + c.need + " 或更高版本编译"
	default:
		s = c.need + " 或更高"
	}
	if c.need != "" && c.unfixed > 0 {
		s += fmt.Sprintf("（另有 %d 个暂无修复）", c.unfixed)
	}
	return s
}

// goSteps are the numbered steps to fix a Go program on the host.
func (r *Report) goSteps(g *pkgGroup) []string {
	f := g.findings[0]
	var steps []string
	own := g.target != ""
	if f.Method == "package" {
		if pkgs, bad := safeNames(f.Binaries); len(pkgs) > 0 && len(bad) == 0 {
			steps = append(steps, r.upgradeCommand(pkgs)+"    # 从它原来的第三方软件源升级")
		}
	} else {
		get := "到程序的官网或原来的下载渠道获取最新版本"
		if f.Project != "" {
			get = "到项目发布页下载最新版本：" + f.Project
		}
		if own {
			get += fmt.Sprintf("（至少 %s）", g.target)
		}
		steps = append(steps, get+"；也可以用原来的安装方式更新，例如重新运行它的一键安装脚本")
		steps = append(steps, "用新文件替换 "+f.Path+"（先备份旧文件）")
	}
	switch {
	case f.Unit != "" && unitRe.MatchString(f.Unit):
		steps = append(steps, "sudo systemctl restart "+f.Unit+"    # 让新版本生效")
	case f.Unit == "" && g.exposed:
		steps = append(steps, "重启这个程序：它正在对外提供服务，但不是 systemd 服务，请用原来启动它的方式重启")
	}
	steps = append(steps, "secwatch scan --pkg "+pkgArg(g.pkg)+"    # 确认问题已消失")
	return steps
}

// goRemedy is the short form used by --all.
func (r *Report) goRemedy(g *pkgGroup) ([][2]string, []string) {
	f := g.findings[0]
	out := [][2]string{{"位置", f.Path + "（Go 程序）"}}
	for i, s := range r.goSteps(g) {
		out = append(out, [2]string{fmt.Sprintf("步骤 %d", i+1), s})
	}
	var bins []string
	if f.Method == "package" {
		if pkgs, bad := safeNames(f.Binaries); len(bad) == 0 {
			bins = pkgs
		}
	}
	return out, bins
}

// writeGoProgram is the --pkg view of one Go program.
func (r *Report) writeGoProgram(t term, g *pkgGroup, unfixed []match.Finding) {
	f := g.findings[0]
	fmt.Fprintln(t)
	t.paint(cBold, g.pkg)
	fmt.Fprintf(t, "  %s  ", displayVersion(g.installed))
	t.paint(prioColor[g.priority], g.priority+" "+priorityLabel[g.priority])
	fmt.Fprintln(t)
	if s := reasons(g); s != "" {
		fmt.Fprintf(t, "  风险  %s\n", s)
	}
	where := f.Path + "（Go 程序"
	if f.Unit != "" {
		where += "，服务 " + f.Unit
	}
	fmt.Fprintf(t, "  位置  %s）\n", where)

	all := append(append([]match.Finding(nil), g.findings...), unfixed...)
	comps := goComponents(all)
	total := 0
	for _, c := range comps {
		total += c.vulns + c.unfixed
	}
	cw, vw := width("组件"), width("当前版本")
	for _, c := range comps {
		cw = max(cw, min(width(c.label), 40))
		vw = max(vw, min(width(c.installed), 20))
	}
	fmt.Fprintln(t)
	t.paint(cBold, fmt.Sprintf("  问题出在这些组件（共 %d 个漏洞）", total))
	fmt.Fprintln(t)
	t.paint(cDim, fmt.Sprintf("    %s  %s  %s  %s", pad("组件", cw), pad("当前版本", vw), "漏洞数", "修复需要"))
	fmt.Fprintln(t)
	const maxRows = 8
	for i, c := range comps {
		if i == maxRows {
			t.paint(cDim, fmt.Sprintf("    其余 %d 个组件见 secwatch scan --pkg %s --all", len(comps)-maxRows, pkgArg(g.pkg)))
			fmt.Fprintln(t)
			break
		}
		fmt.Fprintf(t, "    %s  %s  %6d  %s\n", pad(clip(c.label, cw), cw), pad(clip(c.installed, vw), vw), c.vulns+c.unfixed, c.needText())
	}

	fmt.Fprintln(t)
	if r.inContainer != nil {
		lines, _ := r.remedy(g)
		for _, l := range lines {
			fmt.Fprintf(t, "  %s  %s\n", l[0], l[1])
		}
	} else {
		t.paint(cBold, "  怎么修")
		fmt.Fprintln(t)
		for i, s := range r.goSteps(g) {
			fmt.Fprintf(t, "    %d. ", i+1)
			if cmd, comment, ok := strings.Cut(s, "    # "); ok {
				t.paint(cCmd, cmd)
				t.paint(cDim, "    # "+comment)
			} else {
				fmt.Fprint(t, s)
			}
			fmt.Fprintln(t)
		}
		hint := "如果换成最新版本后仍有这些问题，说明作者还没用新版 Go 和依赖重新编译"
		if f.Project != "" {
			hint += "，可以把上面的组件表发到项目的 issue 里提醒作者"
		}
		t.paint(cDim, "    "+hint+"。")
		fmt.Fprintln(t)
	}

	onlyBundled := true
	for _, c := range comps {
		onlyBundled = onlyBundled && !c.own
	}
	fmt.Fprintln(t)
	if onlyBundled {
		t.paint(cDim, "  说明：这些漏洞在程序内置的组件中，是否真的能被利用取决于程序有没有用到相关功能，所以标为“可能受影响”，优先级不高于 P2（已被在野利用的除外）。")
		fmt.Fprintln(t)
	}
	if r.showAll {
		r.writeVulnList(t, all, fmt.Sprintf("全部漏洞 %d 个", total))
	} else {
		t.paint(cDim, "  逐个漏洞的编号、评分和链接：secwatch scan --pkg "+pkgArg(g.pkg)+" --all")
		fmt.Fprintln(t)
	}
}
