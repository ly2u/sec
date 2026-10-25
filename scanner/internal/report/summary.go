package report

import (
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/l2"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/version"
)

// The default view is a one-screen summary: a verdict, one table row per
// package that matters, a few "also note" lines and the commands to run.
// Everything else is one command away (--pkg NAME, --all).

const (
	watchNames = 3  // names listed per "also note" line
	pkgCVERows = 15 // vulnerabilities listed per package in the --pkg view
)

// ANSI styles, used only when the output is a colour terminal.
const (
	cRed    = "1;31"
	cYellow = "1;33"
	cGreen  = "1;32"
	cBold   = "1"
	cDim    = "2"
	cCmd    = "1;36"
)

var prioColor = map[string]string{"P0": cRed, "P1": cYellow, "P3": cDim}

// term writes sanitised text; colour codes bypass the sanitiser, so they can
// only come from the constants above, never from scanned data.
type term struct {
	safeWriter
	raw   io.Writer
	color bool
}

func newTerm(out io.Writer, color bool) term {
	return term{safeWriter: safeWriter{out}, raw: out, color: color}
}

func (t term) paint(style, s string) {
	if t.color && style != "" {
		io.WriteString(t.raw, "\x1b["+style+"m")
	}
	io.WriteString(t.safeWriter, s)
	if t.color && style != "" {
		io.WriteString(t.raw, "\x1b[0m")
	}
}

// width is the display width in a terminal: CJK and full-width forms take
// two columns. Ambiguous-width symbols are avoided inside aligned columns.
func width(s string) int {
	n := 0
	for _, r := range s {
		switch {
		case r >= 0x1100 && r <= 0x115f, r >= 0x2e80 && r <= 0xa4cf, r >= 0xac00 && r <= 0xd7a3,
			r >= 0xf900 && r <= 0xfaff, r >= 0xfe30 && r <= 0xfe4f, r >= 0xff00 && r <= 0xff60, r >= 0xffe0 && r <= 0xffe6:
			n += 2
		default:
			n++
		}
	}
	return n
}

func pad(s string, w int) string {
	if d := w - width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

func clip(s string, w int) string {
	if width(s) <= w {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if width(b.String()+string(r)) > w-1 {
			break
		}
		b.WriteRune(r)
	}
	return b.String() + "~"
}

func isFixable(f match.Finding) bool { return f.Fix == match.FixUpgrade || f.Fix == match.FixReboot }

func isUnfixed(f match.Finding) bool {
	return f.Status != match.Unknown && f.Fix == match.FixNone && !f.Minor
}

func vulnCount(g *pkgGroup) int {
	seen := map[string]bool{}
	for _, f := range g.findings {
		key := f.ID
		if len(f.CVEs) == 1 {
			key = f.CVEs[0]
		}
		seen[key] = true
	}
	return len(seen)
}

func maxEPSS(fs []match.Finding) float64 {
	var e float64
	for _, f := range fs {
		if f.EPSS != nil && *f.EPSS > e {
			e = *f.EPSS
		}
	}
	return e
}

func hasKernel(g *pkgGroup) bool {
	for _, f := range g.findings {
		if f.Kernel {
			return true
		}
	}
	return false
}

// severity in words, with the CVSS score for those who know it.
func severity(cvss float64) string {
	switch {
	case cvss >= CVSSCritical:
		return fmt.Sprintf("严重 %.1f", cvss)
	case cvss >= CVSSHigh:
		return fmt.Sprintf("高危 %.1f", cvss)
	case cvss >= 4:
		return fmt.Sprintf("中危 %.1f", cvss)
	case cvss >= 0:
		return fmt.Sprintf("低危 %.1f", cvss)
	}
	return ""
}

// reasons says, in a few words, why a package is where it is in the table.
func reasons(g *pkgGroup) string {
	var b []string
	if g.ransom {
		b = append(b, "已被勒索软件利用")
	} else if g.kev {
		b = append(b, "已被在野利用")
	}
	if e := maxEPSS(g.findings); e >= EPSSHigh {
		b = append(b, fmt.Sprintf("利用概率 %.0f%%", e*100))
	}
	if s := severity(g.maxCVSS); s != "" {
		b = append(b, s)
	}
	if g.exposed {
		b = append(b, "对外服务")
	}
	if hasKernel(g) {
		b = append(b, "需重启")
	}
	if g.goProg {
		own := false
		for _, f := range g.findings {
			own = own || f.Component == ""
		}
		if !own {
			b = append(b, "Go 程序内置组件")
		} else {
			b = append(b, "Go 程序")
		}
	}
	if g.l2 {
		if g.findings[0].Method == "package" {
			b = append(b, "第三方源")
		} else {
			b = append(b, "需单独升级")
		}
	}
	for _, f := range g.findings {
		if f.Status == match.PotentiallyAffected && !g.goProg {
			b = append(b, "来源未核实")
			break
		}
	}
	return strings.Join(b, " · ")
}

// writeBrief is the two-line header shared by the summary and --pkg views.
func (r *Report) writeBrief(t term) {
	t.paint(cBold, "LY2U SecWatch "+r.Scanner)
	line := " · " + r.OS.Name
	if r.inContainer != nil {
		line = " · " + r.containerBrief() + " · " + r.OS.Name
	}
	if r.Kernel.Running != "" {
		line += " · 内核 " + r.Kernel.Running
		if r.Kernel.NewerInstalled {
			line += "（新内核 " + r.Kernel.NewestVersion + " 已安装，重启后生效）"
		}
	}
	fmt.Fprintln(t, line)
	src := "在线获取"
	switch {
	case r.Data.Offline:
		src = "离线数据包"
	case r.Data.FromCache:
		src = "本地缓存"
	}
	t.paint(cDim, fmt.Sprintf("已检查 %d 个软件包 · 数据 %s UTC（%s，签名已校验）· 只读，未修改系统、未上传数据",
		r.Summary.Packages, r.Data.GeneratedAt.UTC().Format("2006-01-02 15:04"), src))
	fmt.Fprintln(t)
}

// writeSummary is the default terminal view (see checklist.go).
func (r *Report) writeSummary(t term) { r.writeChecklist(t) }

var argSafe = regexp.MustCompile(`^[A-Za-z0-9.+_-]+( [A-Za-z0-9.+_-]+)*$`)

// pkgArg quotes a package or product name for the --pkg hint, or returns ""
// if the name is not safe to show as part of a command.
func pkgArg(name string) string {
	if !argSafe.MatchString(name) || len(name) > 64 {
		return ""
	}
	if strings.Contains(name, " ") {
		return `"` + name + `"`
	}
	return name
}

// watchLines are the one-line notes that fit no other row of the summary.
func (r *Report) watchLines() []string {
	var lines []string
	if r.Kernel.NewerInstalled && r.Kernel.NewestVersion != "" {
		lines = append(lines, "新内核 "+r.Kernel.NewestVersion+" 已安装，重启后才会生效")
	}
	names := func(list []string) string {
		if len(list) > watchNames {
			return strings.Join(list[:watchNames], "、") + fmt.Sprintf(" 等 %d 个", len(list))
		}
		return strings.Join(list, "、")
	}

	if rt := r.Runtime; rt != nil {
		if len(rt.Stale) > 0 {
			var ps []string
			for _, sp := range rt.Stale {
				ps = append(ps, sp.Name)
			}
			lines = append(lines, fmt.Sprintf("补丁未生效：%s 仍在使用升级前的旧库，重启后才会生效", names(dedupe(ps))))
		}
		if rt.RebootRequired {
			lines = append(lines, "系统提示需要重启（/var/run/reboot-required），已安装的更新重启后才会生效")
		}
	}
	if pro := r.group(func(f match.Finding) bool { return f.Fix == match.FixSubscription && f.Priority != "P3" }); len(pro) > 0 {
		var ps []string
		for _, g := range pro {
			ps = append(ps, g.pkg)
		}
		lines = append(lines, fmt.Sprintf("修复只在 Ubuntu Pro（ESM）中提供：%s（--all 查看启用方法）", names(ps)))
	}
	if unknown := r.group(func(f match.Finding) bool { return f.Status == match.Unknown }); len(unknown) > 0 {
		lines = append(lines, fmt.Sprintf("无法判定：%d 个软件包（--all 查看原因）", len(unknown)))
	}

	var uncovered []string
	if len(r.ThirdParty) > 0 {
		var ps []string
		for _, p := range r.ThirdParty {
			ps = append(ps, p.Name)
		}
		uncovered = append(uncovered, names(ps)+"（第三方源，请关注其官方公告）")
	}
	if r.L2 != nil {
		// Without upstream data the scanner adds a note saying so; no second line here.
		if len(r.L2NoData) > 0 {
			uncovered = append(uncovered, names(r.L2NoData)+"（暂无上游数据）")
		}
	}
	if len(uncovered) > 0 {
		lines = append(lines, "未检查："+strings.Join(uncovered, "；"))
	}

	var odd []string
	for _, g := range r.group(func(f match.Finding) bool { return f.Layer != "L2" }) {
		if _, bad := safeNames(g.binaries); len(bad) > 0 {
			odd = append(odd, bad...)
		}
	}
	if len(odd) > 0 {
		lines = append(lines, "以下软件包名称含异常字符，可能被篡改，请人工核实（未写入任何命令）："+strings.Join(dedupe(odd), " "))
	}
	for _, n := range dedupe(r.Notes) {
		if n == bundle.WarnManifestUnsigned {
			continue // a known limitation of the data source, shown with --all
		}
		lines = append(lines, n)
	}

	return lines
}

// fixSteps are the numbered commands that end the summary. ref maps rows to
// their step ("upgrade", "pkg:NAME", "ctr:NAME"); popup asks for the apt
// prompt hint. No steps when nothing can be done now.
func (r *Report) fixSteps(fixable []*pkgGroup) (steps [][2]string, ref map[string]int, popup bool) {
	ref = map[string]int{}
	distro, kernel, exposed := false, false, false
	var separate, thirdParty []*pkgGroup
	for _, g := range fixable {
		switch {
		case !g.l2:
			distro = true
		case r.noUpdate(g):
			// Already the newest the repository has: nothing to run yet.
		case g.findings[0].Method == "package":
			thirdParty = append(thirdParty, g)
		default:
			separate = append(separate, g)
		}
		exposed = exposed || g.exposed || r.stalePackages[g.pkg]
		kernel = kernel || hasKernel(g)
	}
	cmd := func(c, comment string) { steps = append(steps, [2]string{c, comment}) }
	host := len(fixable) > 0
	var thirdBins, units []string
	for _, g := range thirdParty {
		if pkgs, bad := safeNames(g.findings[0].Binaries); len(bad) == 0 {
			thirdBins = append(thirdBins, pkgs...)
		}
		if u := g.findings[0].Unit; u != "" && unitRe.MatchString(u) {
			units = append(units, u)
		}
	}
	switch {
	case distro:
		// Third-party repositories are upgraded by the same command.
		cmd(r.fullUpgradeCommand(), "安装全部安全更新")
		ref["upgrade"] = len(steps)
	case len(thirdBins) > 0:
		cmd(r.upgradeCommand(dedupe(thirdBins)), "从原来的第三方软件源升级")
		ref["upgrade"] = len(steps)
		// Only programs outside the distribution: restarting them is enough.
		if len(units) > 0 {
			cmd("sudo systemctl restart "+strings.Join(dedupe(units), " "), "让新版本生效，不用重启服务器")
		}
	}
	listed := 0
	for _, g := range separate {
		if listed == 4 {
			break
		}
		a := pkgArg(g.pkg)
		if a == "" {
			continue
		}
		if g.goProg && g.target == "" && !urgent(g) {
			continue // only bundled code affected: nothing to do until a new release
		}
		listed++
		comment := fmt.Sprintf("%s 不是软件包安装的，系统升级不会更新它，这里有具体步骤", g.pkg)
		if g.goProg {
			comment = fmt.Sprintf("%s（%s）需要单独更新，这里有下载地址和具体步骤", g.pkg, g.findings[0].Path)
		}
		cmd("secwatch scan --pkg "+a, comment)
		ref["pkg:"+g.pkg] = len(steps)
	}
	for i, c := range r.containersToFix() {
		if i == 3 {
			break
		}
		cmd("secwatch scan --container "+c.Label(), "查看重建镜像的步骤")
		ref["ctr:"+c.Label()] = len(steps)
	}
	switch {
	case !host:
	case !distro:
		// Restarted right after their upgrade above.
	case kernel:
		cmd("sudo reboot", "让新内核和已升级的服务生效")
	case exposed:
		comment := "让升级后的库生效"
		if names := r.publicServices(); len(names) > 0 {
			comment += "；不便重启时，至少重启对外服务：" + strings.Join(names, "、")
		}
		cmd("sudo reboot", comment)
	default:
		cmd("sudo reboot", "让升级后的库生效；也可以只重启用到这些软件的服务")
	}
	if len(steps) == 0 {
		return nil, ref, false
	}
	cmd("secwatch scan", "再查一次，确认已修复")
	return steps, ref, distro && r.kind == version.Deb
}

// FilterPackage limits the text report to one package (--pkg). The name is
// matched against source package, binary package and product names.
func (r *Report) FilterPackage(name string) { r.only = strings.ToLower(strings.TrimSpace(name)) }

func (r *Report) matches(f match.Finding) bool {
	if strings.ToLower(f.Package) == r.only {
		return true
	}
	// A program can also be named by its file name (komari-agent or agent).
	if f.Path != "" && strings.ToLower(filepath.Base(f.Path)) == r.only {
		return true
	}
	for _, b := range f.Binaries {
		if strings.ToLower(b) == r.only {
			return true
		}
	}
	return false
}

// writePackage is the --pkg view: everything about one package.
func (r *Report) writePackage(t term) {
	r.writeBrief(t)
	fixable := r.group(func(f match.Finding) bool {
		return r.matches(f) && (isFixable(f) || f.Fix == match.FixSubscription)
	})
	unfixed := r.group(func(f match.Finding) bool { return r.matches(f) && isUnfixed(f) })
	unknown := r.group(func(f match.Finding) bool { return r.matches(f) && f.Status == match.Unknown })
	if len(fixable)+len(unfixed)+len(unknown) == 0 {
		fmt.Fprintf(t, "\n没有找到 %s 的漏洞：它已包含全部已知修复，或者名称不对（可以用源码包名、软件包名或软件名，如 openssh、openssh-server、Node.js）。\n", r.only)
		return
	}
	goUnfixed := map[string][]match.Finding{}
	for _, g := range unfixed {
		if g.goProg {
			goUnfixed[g.findings[0].Path] = append(goUnfixed[g.findings[0].Path], g.findings...)
		}
	}
	for _, g := range fixable {
		if g.goProg {
			r.writeGoProgram(t, g, goUnfixed[g.findings[0].Path])
			delete(goUnfixed, g.findings[0].Path)
			continue
		}
		fmt.Fprintln(t)
		t.paint(cBold, g.pkg)
		if g.target != "" {
			fmt.Fprintf(t, "  %s → %s  ", g.installed, g.target)
		} else {
			fmt.Fprintf(t, "  %s  ", g.installed)
		}
		t.paint(prioColor[g.priority], g.priority+" "+priorityLabel[g.priority])
		fmt.Fprintln(t)
		if s := reasons(g); s != "" {
			fmt.Fprintf(t, "  风险  %s\n", s)
		}
		lines, _ := r.remedy(g)
		for _, l := range lines {
			fmt.Fprintf(t, "  %s  %s\n", l[0], l[1])
		}
		r.writeVulnList(t, g.findings, fmt.Sprintf("可修复的漏洞 %d 个", vulnCount(g)))
	}
	for _, g := range unfixed {
		if g.goProg {
			if _, left := goUnfixed[g.findings[0].Path]; !left {
				continue // shown with the program above
			}
			fmt.Fprintln(t)
			t.paint(cBold, g.pkg)
			fmt.Fprintf(t, "  %s  暂无修复版本（上游还没有发布修复）\n", displayVersion(g.installed))
			r.writeVulnList(t, g.findings, fmt.Sprintf("暂无修复的漏洞 %d 个", vulnCount(g)))
			continue
		}
		fmt.Fprintln(t)
		t.paint(cBold, g.pkg)
		fmt.Fprintf(t, "  %s  暂无修复（发行版尚未发布更新，目前没有可执行的升级）\n", g.installed)
		r.writeVulnList(t, g.findings, fmt.Sprintf("暂无修复的漏洞 %d 个", vulnCount(g)))
	}
	for _, g := range unknown {
		fmt.Fprintf(t, "\n%s %s 无法判定：%s\n", g.pkg, g.installed, strings.Join(g.findings[0].Notes, "；"))
	}
}

// writeVulnList prints the vulnerabilities of one package, riskiest first.
func (r *Report) writeVulnList(t term, fs []match.Finding, title string) {
	sorted := append([]match.Finding(nil), fs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.KEV != b.KEV {
			return a.KEV
		}
		if ea, eb := maxEPSS([]match.Finding{a}), maxEPSS([]match.Finding{b}); ea != eb {
			return ea > eb
		}
		return score(a.CVSS) > score(b.CVSS)
	})
	fmt.Fprintf(t, "  %s（按风险排序）：\n", title)
	limit := len(sorted)
	if !r.showAll && limit > pkgCVERows {
		limit = pkgCVERows
	}
	for _, f := range sorted[:limit] {
		id := f.ID
		if len(f.CVEs) == 1 {
			id = f.CVEs[0]
		}
		var b []string
		if f.Ransomware {
			b = append(b, "已被勒索软件利用")
		} else if f.KEV {
			b = append(b, "已被在野利用")
		}
		if f.CVSS != nil {
			b = append(b, severity(*f.CVSS))
		}
		if f.EPSS != nil && *f.EPSS >= 0.01 {
			b = append(b, fmt.Sprintf("利用概率 %.0f%%", *f.EPSS*100))
		}
		if f.FixedVersion != "" && isFixable(f) {
			b = append(b, "修复于 "+f.FixedVersion)
		}
		if f.Component != "" {
			b = append(b, "来自 "+f.Component)
		}
		fmt.Fprintf(t, "    %s  %s  %s\n", f.Priority, pad(id, 16), strings.Join(b, " · "))
	}
	if limit < len(sorted) {
		hint := "secwatch scan --pkg " + pkgArg(r.only) + " --all"
		if pkgArg(r.only) == "" {
			hint = "--all"
		}
		t.paint(cDim, fmt.Sprintf("    另有 %d 个未列出（%s 查看全部）", len(sorted)-limit, hint))
		fmt.Fprintln(t)
	}
	t.paint(cDim, "  每个漏洞的说明："+siteCVE+"<漏洞编号>")
	fmt.Fprintln(t)
}

// remedy returns the label/text lines that tell how to fix one package, and
// the binary package names used in the commands.
func (r *Report) remedy(g *pkgGroup) ([][2]string, []string) {
	var out [][2]string
	add := func(k, v string) { out = append(out, [2]string{k, v}) }
	if r.inContainer != nil {
		add("修复", "更新镜像后重建容器，不要在容器里直接升级（步骤见 secwatch scan --container "+r.inContainer.Label()+"）")
		return out, nil
	}
	if g.goProg {
		return r.goRemedy(g)
	}
	if g.l2 {
		f := g.findings[0]
		label := l2.MethodLabel[f.Method]
		if f.Path != "" {
			add("位置", fmt.Sprintf("%s（%s）", f.Path, label))
		} else {
			add("来源", fmt.Sprintf("%s（%s）", strings.Join(f.Binaries, " "), label))
		}
		var bins []string
		if f.Method == "package" {
			if pkgs, bad := safeNames(f.Binaries); len(pkgs) > 0 && len(bad) == 0 {
				if r.noUpdate(g) {
					add("修复", "软件源里已经是最新版，暂时无法升级；作者发布新版后运行 "+r.upgradeCommand(pkgs))
				} else {
					add("修复", r.upgradeCommand(pkgs)+"（从原第三方软件源升级）")
				}
				bins = pkgs
			}
		} else if f.Guidance != "" {
			add("修复", f.Guidance)
		}
		if g.exposed {
			add("注意", "该程序正在对外提供服务，升级后需重启才会生效")
		}
		return out, bins
	}
	for _, f := range g.findings {
		if f.Fix == match.FixSubscription {
			add("修复", "只在 Ubuntu Pro（ESM）中提供：启用后执行 sudo pro attach <令牌>，再按常规方式升级")
			return out, nil
		}
	}
	bins, bad := safeNames(g.binaries)
	if hasKernel(g) {
		allInstalled := true
		for _, f := range g.findings {
			allInstalled = allInstalled && f.Fix == match.FixReboot
		}
		if allInstalled {
			add("修复", "已安装修复后的内核，重启系统后生效：sudo reboot（建议在维护窗口执行）")
		} else {
			add("修复", "升级内核后重启："+r.upgradeKernelCommand()+" && sudo reboot")
		}
		bins = nil
	} else if len(bins) > 0 {
		add("修复", r.upgradeCommand(bins))
		add("验证", fmt.Sprintf("%s（应不低于 %s）", r.verifyCommand(bins), g.target))
		if g.exposed || r.stalePackages[g.pkg] {
			add("注意", "正在运行的服务加载了它，升级后需重启相应服务才会生效")
		}
	}
	if len(bad) > 0 {
		add("注意", "以下包名含异常字符，未写入命令，请手动核实："+strings.Join(bad, " "))
	}
	return out, bins
}

// InstallCommand updates (or installs) the scanner; install.sh verifies the
// release signature before replacing the binary.
const InstallCommand = "curl -fsSL https://sec.ly2u.com/install.sh | sh"

// writeUpdate is the "new version available" hint. It never updates anything.
func (r *Report) writeUpdate(t term) {
	if r.Update == "" {
		return
	}
	fmt.Fprintln(t)
	t.paint(cYellow, fmt.Sprintf("有新版本 %s（当前 %s）", r.Update, r.Scanner))
	t.paint(cDim, "，更新：")
	t.paint(cCmd, InstallCommand)
	fmt.Fprintln(t)
}
