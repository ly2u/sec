package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/ly2u/sec/scanner/internal/l2"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/version"
)

var priorityLabel = map[string]string{
	"P0": "立即处理", "P1": "尽快处理", "P2": "计划处理", "P3": "了解即可",
}

// pkgGroup collects the findings of one package for display.
type pkgGroup struct {
	pkg       string
	installed string
	binaries  []string
	findings  []match.Finding
	priority  string
	target    string // highest fixed version among upgradable findings
	exposed   bool
	kev       bool
	maxCVSS   float64
	l2        bool
}

func (r *Report) group(filter func(match.Finding) bool) []*pkgGroup {
	by := map[string]*pkgGroup{}
	var order []string
	for _, f := range r.Findings {
		if !filter(f) {
			continue
		}
		k := f.Package + "\x00" + f.InstalledVersion + "\x00" + f.Layer + "\x00" + f.Path
		g := by[k]
		if g == nil {
			g = &pkgGroup{pkg: f.Package, installed: f.InstalledVersion, binaries: f.Binaries, priority: "P9", maxCVSS: -1, l2: f.Layer == "L2"}
			by[k] = g
			order = append(order, k)
		}
		g.findings = append(g.findings, f)
		if f.Priority < g.priority {
			g.priority = f.Priority
		}
		g.exposed = g.exposed || f.Exposed
		g.kev = g.kev || f.KEV
		if f.CVSS != nil && *f.CVSS > g.maxCVSS {
			g.maxCVSS = *f.CVSS
		}
		if f.FixedVersion != "" && (f.Fix == match.FixUpgrade || f.Fix == match.FixReboot || f.Fix == match.FixSubscription) {
			if g.target == "" || r.cmpFor(g.l2, f.FixedVersion, g.target) > 0 {
				g.target = f.FixedVersion
			}
		}
	}
	out := make([]*pkgGroup, 0, len(order))
	for _, k := range order {
		out = append(out, by[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].priority != out[j].priority {
			return out[i].priority < out[j].priority
		}
		if out[i].kev != out[j].kev {
			return out[i].kev
		}
		return out[i].maxCVSS > out[j].maxCVSS
	})
	return out
}

func (r *Report) cmpFor(upstream bool, a, b string) int {
	kind := r.kind
	if upstream {
		kind = version.Upstream
	}
	c, err := compareVersions(kind, a, b)
	if err != nil {
		return strings.Compare(a, b)
	}
	return c
}

func ids(fs []match.Finding, max int) string {
	var list []string
	for _, f := range fs {
		label := f.ID
		if len(f.CVEs) == 1 {
			label = f.CVEs[0]
		}
		list = append(list, label)
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i] > list[j] }) // newest IDs first
	if len(list) > max {
		return strings.Join(list[:max], "、") + fmt.Sprintf(" 等 %d 个", len(list))
	}
	return strings.Join(list, "、")
}

func badges(g *pkgGroup) string {
	var b []string
	if g.kev {
		b = append(b, "已被在野利用（CISA KEV）")
	}
	if g.maxCVSS >= 0 {
		b = append(b, fmt.Sprintf("最高 CVSS %.1f", g.maxCVSS))
	}
	var epss float64
	for _, f := range g.findings {
		if f.EPSS != nil && *f.EPSS > epss {
			epss = *f.EPSS
		}
	}
	if epss >= 0.01 {
		b = append(b, fmt.Sprintf("EPSS %.0f%%", epss*100))
	}
	if g.exposed {
		b = append(b, "所在进程对外监听")
	}
	return strings.Join(b, " · ")
}

func refsOf(g *pkgGroup, max int) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range g.findings {
		for _, ref := range f.Refs {
			if !seen[ref] && len(out) < max {
				seen[ref] = true
				out = append(out, ref)
			}
		}
	}
	return out
}

func section(w io.Writer, title string) {
	fmt.Fprintf(w, "\n== %s ==\n", title)
}

// safeWriter replaces control characters (other than newline) so that crafted
// package names, versions or process names cannot inject terminal escapes.
type safeWriter struct{ w io.Writer }

func (s safeWriter) Write(p []byte) (int, error) {
	clean := []rune(string(p))
	for i, c := range clean {
		if c != '\n' && unicode.IsControl(c) {
			clean[i] = '?'
		}
	}
	if _, err := io.WriteString(s.w, string(clean)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteText renders the Chinese human-readable report.
func (r *Report) WriteText(out io.Writer) {
	w := safeWriter{out}
	fmt.Fprintf(w, "LY2U SecWatch 漏洞自检 %s（只读检查，未修改系统）\n", r.Scanner)
	fmt.Fprintf(w, "系统  %s\n", r.OS.Name)
	src := "在线获取"
	switch {
	case r.Data.Offline:
		src = "离线数据包"
	case r.Data.FromCache:
		src = "本地缓存"
	}
	fmt.Fprintf(w, "数据  %s（生成于 %s UTC，%s，签名密钥 %s 校验通过）\n",
		r.Data.File, r.Data.GeneratedAt.UTC().Format("2006-01-02 15:04"), src, r.Data.KeyID)
	if r.Kernel.Running != "" {
		line := "运行 " + r.Kernel.Running
		if r.Kernel.NewerInstalled {
			line += "（已安装更新的内核 " + r.Kernel.NewestVersion + "，尚未重启生效）"
		}
		fmt.Fprintf(w, "内核  %s\n", line)
	}

	s := r.Summary
	section(w, "结论")
	actionableTotal := s.ByPriority["P0"] + s.ByPriority["P1"] + s.ByPriority["P2"] + s.ByPriority["P3"]
	if actionableTotal == 0 {
		fmt.Fprintln(w, "  ✓ 没有需要升级的软件包：已安装的版本均包含发行版已发布的全部安全修复。")
	} else {
		fmt.Fprintf(w, "  可修复：P0 立即处理 %d   P1 尽快处理 %d   P2 计划处理 %d   P3 了解即可 %d\n",
			s.ByPriority["P0"], s.ByPriority["P1"], s.ByPriority["P2"], s.ByPriority["P3"])
	}
	fmt.Fprintf(w, "  已检查 %d 个软件包 · 已由安装的版本修复 %d 项 · 第三方软件包（未覆盖）%d 个\n",
		s.Packages, s.AlreadyFixed, s.ThirdParty)
	if s.Unfixed > 0 {
		fmt.Fprintf(w, "  发行版暂无修复 %d 项（目前没有可执行的升级），其中值得关注 %d 项", s.Unfixed, s.UnfixedNotable)
		if s.MinorUnfixed > 0 {
			fmt.Fprintf(w, "；另有 %d 项被发行版评为可忽略，未计入", s.MinorUnfixed)
		}
		fmt.Fprintln(w)
	}
	if s.RestartServices > 0 || s.RebootNeeded {
		reboot := "否"
		if s.RebootNeeded {
			reboot = "是"
		}
		fmt.Fprintf(w, "  补丁未生效：需重启的服务 %d 个 · 需要重启系统：%s\n", s.RestartServices, reboot)
	}
	if n := s.ByStatus[string(match.PotentiallyAffected)]; n > 0 {
		fmt.Fprintf(w, "  其中 %d 项为“可能受影响”（软件包来源无法核实，见末尾提示）\n", n)
	}

	actionable := func(f match.Finding) bool {
		return (f.Fix == match.FixUpgrade || f.Fix == match.FixReboot) && (r.showAll || f.Priority != "P3")
	}
	groups := r.group(actionable)
	var upgradeAll []string
	if len(groups) > 0 {
		section(w, "需要处理（按优先级排序）")
		for _, g := range groups {
			potential := ""
			for _, f := range g.findings {
				if f.Status == match.PotentiallyAffected {
					potential = "  （可能受影响：软件包来源未核实）"
				}
			}
			fmt.Fprintf(w, "\n[%s %s] %s  %s → %s%s\n", g.priority, priorityLabel[g.priority], g.pkg, g.installed, g.target, potential)
			fmt.Fprintf(w, "  漏洞：%s\n", ids(g.findings, 6))
			if b := badges(g); b != "" {
				fmt.Fprintf(w, "  风险：%s\n", b)
			}
			if g.l2 {
				f := g.findings[0]
				label := l2.MethodLabel[f.Method]
				if f.Path != "" {
					fmt.Fprintf(w, "  位置：%s（%s）\n", f.Path, label)
				} else {
					fmt.Fprintf(w, "  来源：%s（%s）\n", strings.Join(f.Binaries, " "), label)
				}
				if f.Method == "package" {
					if pkgs, bad := safeNames(f.Binaries); len(pkgs) > 0 && len(bad) == 0 {
						fmt.Fprintf(w, "  修复：%s（从原第三方软件源升级）\n", r.upgradeCommand(pkgs))
						upgradeAll = append(upgradeAll, pkgs...)
					}
				} else if f.Guidance != "" {
					fmt.Fprintf(w, "  修复：%s\n", f.Guidance)
				}
				if g.exposed {
					fmt.Fprintf(w, "  注意：该程序正在对外提供服务，升级后需重启才会生效\n")
				}
				for _, ref := range refsOf(g, 2) {
					fmt.Fprintf(w, "  参考：%s\n", ref)
				}
				continue
			}
			bins, bad := safeNames(g.binaries)
			reboot := false
			for _, f := range g.findings {
				reboot = reboot || f.Fix == match.FixReboot || f.Kernel
			}
			if reboot && g.findings[0].Kernel {
				allInstalled := true
				for _, f := range g.findings {
					allInstalled = allInstalled && f.Fix == match.FixReboot
				}
				if allInstalled {
					fmt.Fprintf(w, "  修复：已安装修复后的内核，重启系统后生效：sudo reboot（建议在维护窗口执行）\n")
				} else {
					fmt.Fprintf(w, "  修复：升级内核后重启：%s && sudo reboot\n", r.upgradeKernelCommand())
				}
			} else if len(bins) > 0 {
				fmt.Fprintf(w, "  修复：%s\n", r.upgradeCommand(bins))
				fmt.Fprintf(w, "  验证：%s（应不低于 %s）\n", r.verifyCommand(bins), g.target)
				upgradeAll = append(upgradeAll, bins...)
				if g.exposed || r.stalePackages[g.pkg] {
					fmt.Fprintf(w, "  注意：正在运行的服务加载了它，升级后需重启相应服务才会生效\n")
				}
			}
			if len(bad) > 0 {
				fmt.Fprintf(w, "  注意：以下包名含异常字符，未写入命令，请手动核实：%s\n", strings.Join(bad, " "))
			}
			for _, ref := range refsOf(g, 2) {
				fmt.Fprintf(w, "  参考：%s\n", ref)
			}
		}
	}

	pro := r.group(func(f match.Finding) bool { return f.Fix == match.FixSubscription && (r.showAll || f.Priority != "P3") })
	if len(pro) > 0 {
		section(w, "修复仅在 Ubuntu Pro（ESM）中提供")
		fmt.Fprintln(w, "  标准软件源中没有可升级的版本。Ubuntu Pro 对个人用户提供一定数量的免费授权，启用后执行 sudo pro attach <令牌>，再按常规方式升级。")
		for _, g := range pro {
			fmt.Fprintf(w, "  [%s] %s %s → %s（Pro）  %s\n", g.priority, g.pkg, g.installed, g.target, ids(g.findings, 4))
		}
	}

	if rt := r.Runtime; rt != nil && (len(rt.Stale) > 0 || rt.RebootRequired) {
		section(w, "补丁未生效")
		if rt.RebootRequired {
			fmt.Fprintf(w, "  系统提示需要重启（/var/run/reboot-required）")
			if len(rt.RebootPackages) > 0 {
				fmt.Fprintf(w, "，涉及：%s", strings.Join(rt.RebootPackages, " "))
			}
			fmt.Fprintln(w)
		}
		for _, sp := range rt.Stale {
			fmt.Fprintf(w, "  %s（PID %s）仍在使用升级前的旧库", sp.Name, joinInts(sp.PIDs, 5))
			if len(sp.Packages) > 0 {
				fmt.Fprintf(w, "（来自 %s）", strings.Join(sp.Packages, "、"))
			}
			fmt.Fprintln(w)
			if unitRe.MatchString(sp.Unit) {
				fmt.Fprintf(w, "    重启生效：sudo systemctl restart %s\n", sp.Unit)
			} else {
				fmt.Fprintf(w, "    该进程不是 systemd 服务，请用其原本的方式重启。\n")
			}
		}
	}

	isUnfixed := func(f match.Finding) bool { return f.Status != match.Unknown && f.Fix == match.FixNone && !f.Minor }
	unfixed := r.group(func(f match.Finding) bool { return isUnfixed(f) && (r.showAll || Notable(f)) })
	hidden := 0
	for _, f := range r.Findings {
		if isUnfixed(f) && !(r.showAll || Notable(f)) {
			hidden++
		}
	}
	if len(unfixed) > 0 || hidden > 0 {
		section(w, "发行版暂无修复（目前没有可执行的升级，仅供了解）")
		if len(unfixed) > 0 {
			fmt.Fprintln(w, "  以下问题已被在野利用、被利用概率较高，或为对外服务中的严重漏洞，建议关注发行版公告并评估缓解措施：")
		}
		for _, g := range unfixed {
			fmt.Fprintf(w, "  · %s %s  %s", g.pkg, g.installed, ids(g.findings, 4))
			if b := badges(g); b != "" {
				fmt.Fprintf(w, "  （%s）", b)
			}
			fmt.Fprintln(w)
		}
		if hidden > 0 {
			fmt.Fprintf(w, "  另有 %d 项暂无修复的一般问题未展开（使用 --all 查看）。稳定版发行版常将次要问题留待后续版本修复，这属于正常情况。\n", hidden)
		}
	}

	if r.showAll {
		minor := r.group(func(f match.Finding) bool { return f.Minor && f.Fix == match.FixNone && f.Status != match.Unknown })
		if len(minor) > 0 {
			section(w, "发行版评为可忽略、不计划修复（默认隐藏）")
			for _, g := range minor {
				fmt.Fprintf(w, "  · %s %s  %s", g.pkg, g.installed, ids(g.findings, 6))
				if b := badges(g); b != "" {
					fmt.Fprintf(w, "  （%s）", b)
				}
				fmt.Fprintln(w)
			}
		}
	}

	if unknown := r.group(func(f match.Finding) bool { return f.Status == match.Unknown }); len(unknown) > 0 {
		section(w, "无法判定")
		for _, g := range unknown {
			fmt.Fprintf(w, "  %s %s：%s\n", g.pkg, g.installed, strings.Join(g.findings[0].Notes, "；"))
		}
	}

	if low := r.Summary.ByPriority["P3"]; low > 0 && !r.showAll {
		fmt.Fprintf(w, "\n另有 %d 项可修复的低优先级问题未展开，使用 --all 查看全部。\n", low)
	}

	if rt := r.Runtime; rt != nil {
		var public []string
		for _, l := range rt.Listeners {
			if l.Public {
				name := l.Process
				if name == "" {
					name = "未知进程"
				}
				public = append(public, fmt.Sprintf("%s:%d %s", l.Address, l.Port, name))
			}
		}
		if len(public) > 0 {
			section(w, "对外监听的服务（用于判断暴露面）")
			for _, p := range public {
				fmt.Fprintf(w, "  %s\n", p)
			}
		}
	}

	if r.L2 != nil && (len(r.L2.Installs) > 0 || len(r.L2.Containers) > 0) {
		section(w, "非包管理安装的软件")
		if !r.L2Evaluated {
			fmt.Fprintln(w, "  （未获取上游漏洞数据，以下软件只列出、未判定漏洞）")
		}
		for _, in := range r.L2.Installs {
			name := in.ProductName
			if in.Version != "" {
				name += " " + in.Version
			}
			where := in.Path
			if where == "" {
				where = strings.Join(in.Packages, " ")
			}
			label := l2.MethodLabel[in.Method]
			if in.OriginLabel != "" && in.Method == "package" {
				label += "：" + in.OriginLabel
			}
			line := fmt.Sprintf("  · %s  %s（%s）", name, where, label)
			if in.BundledIn != "" {
				line = fmt.Sprintf("  · %s  编译在 %s 中（%s）", name, in.BundledIn, in.Path)
			}
			if in.Running {
				line += " · 运行中"
			}
			fmt.Fprintln(w, line)
			if in.Note != "" {
				fmt.Fprintf(w, "      %s\n", in.Note)
			}
		}
		if len(r.L2NoData) > 0 {
			fmt.Fprintf(w, "  暂无上游漏洞数据：%s（结论为未知）\n", strings.Join(r.L2NoData, "、"))
		}
		if len(r.L2.Containers) > 0 {
			var parts []string
			for _, c := range r.L2.Containers {
				p := c.Name
				if c.Container != "" {
					p += "（容器 " + c.Container + "）"
				} else {
					p += fmt.Sprintf("（PID %d）", c.PID)
				}
				parts = append(parts, p)
			}
			fmt.Fprintf(w, "  容器内运行：%s。容器内部的软件版本本工具暂不检查，建议用 trivy image 扫描对应镜像，或确认镜像已重新构建。\n", strings.Join(parts, "、"))
		}
	}

	if len(r.ThirdParty) > 0 {
		section(w, "未覆盖：来自第三方源的软件包")
		fmt.Fprintln(w, "  这些软件包不是由发行版官方仓库提供的，发行版漏洞数据不适用于它们，本次结论为“未知”。")
		fmt.Fprintln(w, "  请关注这些软件的官方安全公告；SecWatch 已支持的软件（nginx、PHP、Node.js、Docker 等）会自动按上游版本判断，不在此列。")
		limit := 30
		if r.showAll {
			limit = len(r.ThirdParty)
		}
		for i, p := range r.ThirdParty {
			if i >= limit {
				fmt.Fprintf(w, "  …… 另有 %d 个，使用 --all 查看\n", len(r.ThirdParty)-limit)
				break
			}
			label := p.OriginLabel
			if label == "" {
				label = "第三方源"
			}
			fmt.Fprintf(w, "  %s %s（%s）\n", p.Name, p.Version, label)
		}
	}

	if len(upgradeAll) > 0 {
		section(w, "一键升级以上全部软件包")
		fmt.Fprintf(w, "  %s\n", r.upgradeCommand(dedupe(upgradeAll)))
		fmt.Fprintln(w, "  执行前请阅读上方说明；升级后按“补丁未生效”一节重启相关服务，然后重新运行 secwatch scan 复查。")
	}

	section(w, "说明")
	for _, n := range dedupe(r.Notes) {
		fmt.Fprintf(w, "  · %s\n", n)
	}
	fmt.Fprintln(w, "  · 结论基于发行版公开的安全数据与 CISA KEV、FIRST EPSS；未列出不代表没有漏洞（例如 0day、第三方软件、自行编译的程序）。")
	fmt.Fprintln(w, "  · 本工具不修改系统、不上传任何数据；以上命令仅供参考，请自行确认后执行。")
}

func (r *Report) upgradeKernelCommand() string {
	switch r.kind {
	case "deb":
		return "sudo apt-get update && sudo apt-get upgrade"
	case "rpm":
		return "sudo dnf upgrade kernel kernel-core"
	default:
		return "apk update && apk upgrade"
	}
}

func joinInts(v []int, max int) string {
	var s []string
	for i, x := range v {
		if i >= max {
			s = append(s, "…")
			break
		}
		s = append(s, fmt.Sprint(x))
	}
	return strings.Join(s, ",")
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
