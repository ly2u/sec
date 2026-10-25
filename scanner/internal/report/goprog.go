package report

import (
	"fmt"
	"path"
	"regexp"
	"runtime"
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
			if r.noUpdate(g) {
				steps = append(steps, "现在不用操作：你装的已经是软件源里的最新版，需要等作者用新版 Go 重新编译发布",
					"作者发布新版后（再次检查时会提示“升级即可”）："+r.upgradeCommand(pkgs))
			} else {
				steps = append(steps, r.upgradeCommand(pkgs)+"    # 从它原来的第三方软件源升级")
			}
		}
	} else {
		get := "到官网或原下载渠道"
		if f.Project != "" {
			get = "打开 " + f.Project
		}
		get += "，复制最新版中 linux-" + archNames() + " 文件的下载链接"
		if own {
			get += fmt.Sprintf("（至少 %s）", g.target)
		}
		steps = append(steps, get)
		file, name, ok := r.goFile(g)
		unit := ""
		if f.Unit != "" && unitRe.MatchString(f.Unit) {
			unit = f.Unit
		}
		if !ok {
			// The path is unusual: give no command that would contain it.
			steps = append(steps, "备份并用新文件替换 "+f.Path+"，然后重启它")
		} else {
			tmp := "/tmp/" + name + ".new"
			steps = append(steps,
				"curl -fL -o "+tmp+" '<下载链接>'    # 换成复制的链接；压缩包要先解压，取出其中的 "+name,
				"sudo cp -a "+file+" "+r.backupName(file)+"    # 备份旧版本")
			if unit != "" {
				steps = append(steps, "sudo systemctl stop "+unit)
			}
			steps = append(steps, "sudo install -m 755 "+tmp+" "+file+"    # 换上新版本")
			switch {
			case unit != "":
				steps = append(steps, "sudo systemctl start "+unit+"    # 启动新版本")
			case f.Unit == "" && (g.exposed || hasRunning(g)):
				steps = append(steps, "用原来启动它的方式重新启动这个程序（它不是 systemd 服务）")
			}
		}
	}
	if f.Method == "package" && f.Unit != "" && unitRe.MatchString(f.Unit) {
		steps = append(steps, "sudo systemctl restart "+f.Unit+"    # 让新版本生效")
	}
	steps = append(steps, "secwatch scan --pkg "+pkgArg(g.pkg)+"    # 确认问题已消失")
	return steps
}

// safeFile restricts paths that may appear in suggested commands.
var safeFile = regexp.MustCompile(`^/[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$`)

// goFile returns the program's path and file name if both are safe to put in
// a command line.
func (r *Report) goFile(g *pkgGroup) (file, name string, ok bool) {
	file = g.findings[0].Path
	if !safeFile.MatchString(file) || strings.Contains(file, "/..") || strings.Contains(file, "/./") {
		return "", "", false
	}
	name = path.Base(file)
	if !processName.MatchString(name) {
		return "", "", false
	}
	return file, name, true
}

func (r *Report) backupName(file string) string {
	return file + ".bak-" + r.ScannedAt.Format("20060102")
}

// goRollback undoes the replacement if the new version misbehaves.
func (r *Report) goRollback(g *pkgGroup) string {
	f := g.findings[0]
	file, _, ok := r.goFile(g)
	if f.Method == "package" || !ok {
		return ""
	}
	cmd := "sudo cp -a " + r.backupName(file) + " " + file
	if f.Unit != "" && unitRe.MatchString(f.Unit) {
		cmd += " && sudo systemctl restart " + f.Unit
	}
	return cmd
}

func hasRunning(g *pkgGroup) bool { return g.findings[0].Unit != "" || g.exposed }

// archNames names this machine's architecture as release files spell it.
func archNames() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64/x86_64"
	case "arm64":
		return "arm64/aarch64"
	}
	return runtime.GOARCH
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
	// The same vulnerability can sit in two components (the standard library
	// and golang.org/x/net); the total counts it once.
	ids := map[string]bool{}
	for _, f := range all {
		ids[f.ID] = true
	}
	total := len(ids)
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
		t.paint(cBold, "  怎么修（参考命令，逐条确认后执行）")
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
		if rb := r.goRollback(g); rb != "" {
			t.paint(cDim, "    出问题时回滚：")
			t.paint(cCmd, rb)
			fmt.Fprintln(t)
		}
		if f.Method != "package" {
			t.paint(cDim, "    也可以用原来的安装方式（如一键安装脚本）更新，再执行最后一步确认。")
			fmt.Fprintln(t)
		}
		hint := "换成最新版后仍有问题，说明作者还没用新版 Go 和依赖重新编译"
		if f.Project != "" {
			hint += "，可把组件表发到项目 issue 提醒作者"
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
		t.paint(cDim, "  说明：漏洞都在内置组件中，能否被利用取决于程序是否用到相关功能，所以标为“可能受影响”。")
		fmt.Fprintln(t)
	}
	if r.showAll {
		r.writeVulnList(t, all, fmt.Sprintf("全部漏洞 %d 个", total))
	} else {
		t.paint(cDim, "  逐个漏洞：secwatch scan --pkg "+pkgArg(g.pkg)+" --all")
		fmt.Fprintln(t)
	}
}
