package report

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ly2u/sec/scanner/internal/match"
)

// The default view is a check-up list: one status line, then one row per
// area (system packages, programs, containers, waiting for patches, notes),
// each saying what is wrong and what to do, then the commands to run.

const (
	labelWidth  = 12
	nameWidth   = 15
	tagWidth    = 11
	countWidth  = 12
	maxNames    = 8
	maxProgRows = 6
)

func (r *Report) row(t term, label, mark, markStyle, text string) {
	fmt.Fprint(t, "   "+pad(label, labelWidth))
	if mark != "" {
		t.paint(markStyle, mark)
		fmt.Fprint(t, " ")
	}
	fmt.Fprintln(t, text)
}

// subRow is an indented line under a row.
func (r *Report) subRow(t term, name, tag, tagStyle, count, action, actionStyle string) {
	fmt.Fprint(t, "   "+pad("", labelWidth)+"  "+pad(clip(name, nameWidth-1), nameWidth))
	t.paint(tagStyle, pad(tag, tagWidth))
	fmt.Fprint(t, pad(count, countWidth))
	t.paint(actionStyle, action)
	fmt.Fprintln(t)
}

// pkgNames lists package names with short tags, at most maxNames.
func pkgNames(gs []*pkgGroup) string {
	var names []string
	for i, g := range gs {
		if i == maxNames {
			names = append(names, fmt.Sprintf("等 %d 个", len(gs)))
			break
		}
		n := g.pkg
		switch {
		case g.ransom:
			n += "(勒索软件在用)"
		case hasKernel(g):
			n += "(需重启)"
		}
		names = append(names, n)
	}
	return strings.Join(names, " · ")
}

func urgent(g *pkgGroup) bool { return g.priority == "P0" || g.priority == "P1" }

// noUpdate tells whether a program from a third-party repository is already
// at the newest version that repository offers: upgrading changes nothing.
func (r *Report) noUpdate(g *pkgGroup) bool {
	f := g.findings[0]
	if !g.l2 || f.Method != "package" || len(f.Binaries) == 0 {
		return false
	}
	for _, b := range f.Binaries {
		if !r.noNewer[b] {
			return false
		}
	}
	return true
}

// waiting tells whether nothing can be done about a program until its
// author publishes a new release.
func (r *Report) waiting(g *pkgGroup) bool {
	if r.noUpdate(g) {
		return true
	}
	return g.l2 && g.findings[0].Method != "package" && g.goProg && g.target == "" && !urgent(g)
}

// verdict is the one-line conclusion for the host and its containers: the
// colour, the title ("● 状态良好") and the sentence after it.
func (r *Report) verdict(fixable []*pkgGroup) (style, title, msg string) {
	p0, p1, kev, ransom := 0, 0, 0, 0
	waitKEV, waitUrgent := 0, 0
	count := func(gs []*pkgGroup) {
		for _, g := range gs {
			// Nothing to upgrade to yet: said separately below, never as
			// "update soon".
			if r.waiting(g) {
				switch {
				case g.kev:
					waitKEV++
				case urgent(g):
					waitUrgent++
				}
				continue
			}
			switch g.priority {
			case "P0":
				p0++
			case "P1":
				p1++
			}
			if g.kev {
				kev++
			}
			if g.ransom {
				ransom++
			}
		}
	}
	count(fixable)
	hostKEV := kev
	for _, c := range r.Containers {
		if c.Report != nil {
			count(c.Report.group(isFixable))
		}
	}
	items := len(fixable) + len(r.containersToFix())
	waiting := 0
	for _, g := range fixable {
		if r.waiting(g) {
			waiting++
		}
	}
	items -= waiting
	switch {
	case p0 > 0 && kev > 0:
		where := ""
		if hostKEV == 0 {
			where = "容器中 "
		}
		if ransom > 0 {
			return cRed, "有紧急问题", fmt.Sprintf("%s%d 个软件包的漏洞已被黑客实际利用（其中 %d 个被勒索软件利用），请今天处理", where, kev, ransom)
		}
		return cRed, "有紧急问题", fmt.Sprintf("%s%d 个软件包的漏洞已被黑客实际利用，请今天处理", where, kev)
	case p0 > 0:
		return cRed, "有紧急问题", fmt.Sprintf("%d 个对外服务有严重漏洞，请今天处理", p0)
	case p1 > 0:
		return cYellow, "建议尽快更新", fmt.Sprintf("%d 项漏洞被利用的可能性较高，或在对外服务中", p1)
	case waitKEV > 0:
		return cRed, "需要留意", fmt.Sprintf("%d 个程序的漏洞已被黑客实际利用，但还没有新版本可升级：关注作者发布，必要时先停止它对外服务", waitKEV)
	case waitUrgent > 0:
		return cYellow, "需要留意", fmt.Sprintf("%d 个程序有较严重的漏洞，但还没有新版本可升级，请关注作者发布", waitUrgent)
	case items > 0:
		return cGreen, "状态良好", fmt.Sprintf("没有需要立即处理的漏洞，有 %d 项建议更新", items)
	case waiting > 0:
		return cGreen, "状态良好", fmt.Sprintf("没有需要你处理的问题，%d 个程序在等作者发布新版", waiting)
	case r.Summary.UnfixedNotable > 0:
		return cGreen, "状态良好", fmt.Sprintf("没有需要更新的软件，%d 项值得关注的问题在等发行版补丁", r.Summary.UnfixedNotable)
	}
	return cGreen, "状态良好", "没有发现需要处理的安全问题"
}

// statusLine prints the verdict and returns its colour for the gutter.
func (r *Report) statusLine(t term, fixable []*pkgGroup) string {
	style, title, msg := r.verdict(fixable)
	fmt.Fprint(t, " ")
	t.paint(style, "● "+title)
	fmt.Fprintln(t, "  "+msg)
	return style
}

// writeChecklist is the default terminal view.
func (r *Report) writeChecklist(t term) {
	// Header: what was checked.
	t.paint(cBold, "LY2U SecWatch "+r.Scanner)
	osLabel := OSLabel(r.OS.Distro, r.OS.Distro, r.OS.Release, "")
	if _, ok := distroNames[r.OS.Distro]; !ok {
		osLabel = r.OS.Name
	}
	var info []string
	if r.inContainer != nil {
		info = append(info, r.containerBrief())
	} else if r.Hostname != "" {
		info = append(info, clip(r.Hostname, 40))
	}
	info = append(info, osLabel)
	if r.Kernel.Running != "" {
		info = append(info, "内核 "+r.Kernel.Running)
	}
	info = append(info, "只读检查")
	t.paint(cDim, "  "+strings.Join(info, " · "))
	fmt.Fprintln(t)
	fmt.Fprintln(t)

	fixable := r.group(isFixable)
	// The check-up block gets a status-coloured bar on its left (colour
	// terminals only; logs stay plain). No right border: CJK terminals draw
	// some symbols two cells wide, which would break a box.
	block := t
	var buf bytes.Buffer
	if t.color {
		block = newTerm(&buf, true)
	}
	gutter := r.statusLine(block, fixable)
	fmt.Fprintln(block)

	steps, ref, popup := r.fixSteps(fixable)

	// System packages.
	var l1, l2 []*pkgGroup
	for _, g := range fixable {
		if g.l2 {
			l2 = append(l2, g)
		} else {
			l1 = append(l1, g)
		}
	}
	if len(l1) == 0 {
		text := fmt.Sprintf("%d 个都没有待修的漏洞", r.Summary.Packages)
		// Programs from third-party repositories are apt packages too and
		// are judged under 程序: say so, or "all fine" reads as a contradiction.
		for _, g := range l2 {
			if g.findings[0].Method == "package" {
				text = fmt.Sprintf("共 %d 个，官方源的都没有待修的漏洞（第三方源装的见“程序”）", r.Summary.Packages)
				break
			}
		}
		r.row(block, "系统软件包", "✓", cGreen, text)
	} else {
		var now, soon, rest []*pkgGroup
		for _, g := range l1 {
			switch g.priority {
			case "P0":
				now = append(now, g)
			case "P1":
				soon = append(soon, g)
			default:
				rest = append(rest, g)
			}
		}
		mark, style := "!", cYellow
		if len(now)+len(soon) > 0 {
			mark, style = "✗", cRed
		}
		r.row(block, "系统软件包", mark, style, fmt.Sprintf("%d 个需要更新", len(l1)))
		line := func(label, style string, gs []*pkgGroup) {
			fmt.Fprint(block, "   "+pad("", labelWidth)+"  ")
			block.paint(style, label)
			fmt.Fprintln(block, "  "+pkgNames(gs))
		}
		if len(now) > 0 {
			line("立即", cRed, now)
		}
		if len(soon) > 0 {
			line("尽快", cYellow, soon)
		}
		switch {
		case len(rest) > 0 && len(now)+len(soon) > 0:
			fmt.Fprint(block, "   "+pad("", labelWidth)+"  ")
			block.paint(cDim, "其他")
			fmt.Fprintf(block, "  %d 个，跟上面一起升级\n", len(rest))
		case len(rest) > 0:
			line("包括", cDim, rest)
		}
	}

	// Programs installed outside the distribution (third-party repositories,
	// hand installs, Go programs).
	installs := 0
	if r.L2 != nil {
		installs = len(r.L2.Installs)
	}
	// Urgent first, then what faces the internet, then what has a step.
	sort.SliceStable(l2, func(i, j int) bool {
		rank := func(g *pkgGroup) int {
			_, style := r.programAction(g, ref)
			switch {
			case urgent(g):
				return 0
			case g.exposed:
				return 1
			case style == cCmd:
				return 2
			}
			return 3
		}
		return rank(l2[i]) < rank(l2[j])
	})
	switch {
	case len(l2) > 0:
		wait := 0
		for _, g := range l2 {
			if r.waiting(g) {
				wait++
			}
		}
		mark, style, text := "!", cYellow, fmt.Sprintf("%d 个建议更新", len(l2)-wait)
		switch {
		case wait == len(l2):
			mark, style, text = "·", cDim, fmt.Sprintf("%d 个有已知漏洞，暂时没有新版本可升级", wait)
		case wait > 0:
			text += fmt.Sprintf("，%d 个在等作者发布新版", wait)
		}
		for _, g := range l2 {
			if urgent(g) {
				mark, style = "✗", cRed
				if wait == 0 {
					text = fmt.Sprintf("%d 个需要更新", len(l2))
				}
			}
		}
		r.row(block, "程序", mark, style, text)
		for i, g := range l2 {
			if i == maxProgRows {
				fmt.Fprint(block, "   "+pad("", labelWidth)+"  ")
				block.paint(cDim, fmt.Sprintf("其余 %d 个：%s scan --all", len(l2)-maxProgRows, Cmd))
				fmt.Fprintln(block)
				break
			}
			tag, tagStyle := "", ""
			if g.exposed {
				tag, tagStyle = "对外服务", cRed
			}
			action, actionStyle := r.programAction(g, ref)
			r.subRow(block, g.pkg, tag, tagStyle, fmt.Sprintf("%d 个漏洞", vulnCount(g)), action, actionStyle)
		}
	case installs > 0 && r.L2Evaluated:
		r.row(block, "程序", "✓", cGreen, fmt.Sprintf("%d 个单独安装的程序都没有发现问题", installs))
	}

	// Containers.
	switch {
	case len(r.Containers) > 0:
		toFix := r.containersToFix()
		var skipped []ContainerResult
		for _, c := range r.Containers {
			if c.Report == nil {
				skipped = append(skipped, c)
			}
		}
		clean := len(r.Containers) - len(toFix) - len(skipped)
		switch {
		case len(toFix) == 0 && len(skipped) == 0:
			r.row(block, "容器", "✓", cGreen, fmt.Sprintf("%d 个都没有发现问题", len(r.Containers)))
		case len(toFix) == 0:
			r.row(block, "容器", "·", cDim, fmt.Sprintf("%d 个未能检查", len(skipped)))
		default:
			mark, style := "!", cYellow
			for _, c := range toFix {
				if style, _ := c.verdict(); style == cRed || style == cYellow {
					mark = "✗"
				}
			}
			if mark == "✗" {
				style = cRed
			}
			r.row(block, "容器", mark, style, fmt.Sprintf("%d 个建议更新", len(toFix)))
		}
		for _, c := range toFix {
			n := len(c.Report.group(isFixable))
			action := "重建镜像"
			if i, ok := ref["ctr:"+c.Label()]; ok {
				action += fmt.Sprintf("，见第 %d 步", i)
			}
			r.subRow(block, c.Label(), c.OS, "", fmt.Sprintf("%d 个软件包", n), action, cCmd)
		}
		if len(toFix) > 0 || len(skipped) > 0 {
			for _, c := range skipped {
				r.subRow(block, c.Label(), c.OS, "", "", "未检查："+c.Reason, cDim)
			}
			if clean > 0 {
				fmt.Fprint(block, "   "+pad("", labelWidth)+"  ")
				block.paint(cDim, fmt.Sprintf("其余 %d 个没有发现问题", clean))
				fmt.Fprintln(block)
			}
		}
	case r.L2 != nil && len(r.L2.Containers) > 0 && !r.containersScanned:
		r.row(block, "容器", "·", cDim, "有容器在运行，但没有检查（需要以 root 运行）")
	}

	// Waiting for the distribution's patches.
	if notable := r.group(func(f match.Finding) bool { return isUnfixed(f) && Notable(f) }); len(notable) > 0 && r.inContainer == nil {
		var names []string
		same := true
		for _, g := range notable {
			if vulnCount(g) != vulnCount(notable[0]) {
				same = false
			}
		}
		for i, g := range notable {
			if i == 4 {
				names = append(names, fmt.Sprintf("等 %d 个软件包", len(notable)))
				break
			}
			n := g.pkg
			if hasKernelName(g) {
				n = "内核"
			}
			if !same {
				n += fmt.Sprintf(" %d 项", vulnCount(g))
			}
			names = append(names, n)
		}
		text := strings.Join(names, "、")
		if same {
			if len(notable) > 1 {
				text += "各"
			}
			text += fmt.Sprintf(" %d 项", vulnCount(notable[0]))
		}
		who := distroNames[r.OS.Distro]
		if who == "" {
			who = "发行版"
		}
		fmt.Fprint(block, "   "+pad("等待补丁", labelWidth))
		block.paint(cDim, "·")
		fmt.Fprint(block, " "+text+"值得关注")
		block.paint(cDim, "  "+who+" 还没发布修复，无需操作")
		fmt.Fprintln(block)
	}

	// Everything else worth knowing, one line each.
	for i, l := range r.watchLines() {
		label := ""
		if i == 0 {
			label = "留意"
		}
		fmt.Fprint(block, "   "+pad(label, labelWidth))
		block.paint(cDim, "·")
		fmt.Fprintln(block, " "+l)
	}

	if t.color {
		writeGutter(t, buf.String(), gutter)
	}

	// What to do.
	if r.inContainer != nil {
		if len(fixable) > 0 {
			r.writeContainerFix(t)
		}
	} else if len(steps) > 0 {
		fmt.Fprintln(t)
		t.paint(cBold, " 建议这样做")
		fmt.Fprintln(t)
		w := 0
		for _, st := range steps {
			if n := width(st[0]); n > w && n <= 64 {
				w = n
			}
		}
		for i, st := range steps {
			fmt.Fprintf(t, "   %d  ", i+1)
			t.paint(cCmd, st[0])
			if st[1] != "" {
				t.paint(cDim, strings.Repeat(" ", max(w-width(st[0]), 0)+2)+"# "+st[1])
			}
			fmt.Fprintln(t)
		}
		if popup {
			t.paint(cDim, "      升级中如有弹窗：替换配置文件选“保留当前版本”（keep the local version），选择重启服务时直接回车")
			fmt.Fprintln(t)
		}
	}

	// Where to look next, and what the data was.
	fmt.Fprintln(t)
	example := "名称"
	candidates := append(append([]*pkgGroup(nil), l1...), l2...)
	if len(candidates) == 0 {
		candidates = r.group(func(f match.Finding) bool { return isUnfixed(f) && Notable(f) })
	}
	if len(candidates) > 0 {
		if a := pkgArg(candidates[0].pkg); a != "" {
			example = a
		}
	}
	prefix := Cmd + " scan "
	if r.inContainer != nil {
		prefix += "--container " + r.inContainer.Label() + " "
	}
	t.paint(cDim, " 看详情  ")
	t.paint(cCmd, prefix+"--pkg "+example)
	t.paint(cDim, "     完整报告  ")
	t.paint(cCmd, prefix+"--all")
	fmt.Fprintln(t)
	if r.MenuHint && r.inContainer == nil {
		t.paint(cDim, " 定时提醒  ")
		t.paint(cCmd, "sudo "+Cmd)
		t.paint(cDim, "  打开菜单，可开启定时检查，有新问题时发到你的 Telegram")
		fmt.Fprintln(t)
	}
	src := "在线获取"
	switch {
	case r.Data.Offline:
		src = "离线数据包"
	case r.Data.FromCache:
		src = "本地缓存"
	}
	t.paint(cDim, fmt.Sprintf(" 数据 %s UTC（%s，签名已校验）· 已检查 %d 个软件包 · 未修改系统、未上传数据",
		r.Data.GeneratedAt.UTC().Format("2006-01-02 15:04"), src, r.Summary.Packages))
	fmt.Fprintln(t)
	r.writeUpdate(t)
}

// hasKernelName tells whether a group is the Linux kernel (for "内核").
func hasKernelName(g *pkgGroup) bool {
	if hasKernel(g) {
		return true
	}
	return g.pkg == "linux" || strings.HasPrefix(g.pkg, "linux-") || g.pkg == "kernel"
}

// programAction is the "what to do" cell of a program row.
func (r *Report) programAction(g *pkgGroup, ref map[string]int) (string, string) {
	f := g.findings[0]
	if r.noUpdate(g) {
		return "源里已是最新版，等作者发布新版", cDim
	}
	if f.Method == "package" {
		if i, ok := ref["upgrade"]; ok {
			return fmt.Sprintf("升级即可，见第 %d 步", i), cCmd
		}
		return "从原来的第三方源升级", cCmd
	}
	if i, ok := ref["pkg:"+g.pkg]; ok {
		return fmt.Sprintf("需要单独更新，见第 %d 步", i), cCmd
	}
	return "等作者发布新版，不急", cDim
}

// writeGutter copies an already sanitised block to the terminal with a
// coloured bar in front of every line.
func writeGutter(t term, block, style string) {
	for _, line := range strings.Split(strings.TrimSuffix(block, "\n"), "\n") {
		io.WriteString(t.raw, "\x1b["+style+"m▌\x1b[0m"+line+"\n")
	}
}
