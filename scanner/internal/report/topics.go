package report

import (
	"fmt"
	"sort"
	"strings"
)

// Topic is something the interactive menu offers to show in detail: a
// package or program with something to fix, or a checked container.
type Topic struct {
	Name      string // passed to FilterPackage or SelectContainer
	Container bool
	Detail    string // "程序 · 对外服务 · 14 个漏洞 · 尽快处理"
}

// maxTopics keeps the menu's list short; anything else can be typed.
const maxTopics = 15

// Topics lists, most urgent first, what is worth a closer look.
func (r *Report) Topics() []Topic {
	gs := r.group(isFixable)
	sort.SliceStable(gs, func(i, j int) bool { return gs[i].priority < gs[j].priority })
	var out []Topic
	for _, g := range gs {
		kind := "系统软件包"
		if g.l2 {
			kind = "程序"
		}
		parts := []string{kind}
		switch {
		case g.ransom:
			parts = append(parts, "已被勒索软件利用")
		case g.kev:
			parts = append(parts, "已被在野利用")
		}
		if g.exposed {
			parts = append(parts, "对外服务")
		}
		parts = append(parts, fmt.Sprintf("%d 个漏洞", vulnCount(g)), priorityLabel[g.priority])
		if r.waiting(g) {
			parts = append(parts, "暂无新版可升级")
		}
		out = append(out, Topic{Name: g.pkg, Detail: strings.Join(parts, " · ")})
	}
	for _, c := range r.Containers {
		if c.Report == nil {
			continue
		}
		detail := "容器 · " + c.OS
		if n := len(c.Report.group(isFixable)); n > 0 {
			detail += fmt.Sprintf(" · %d 个软件包需要更新", n)
		} else {
			detail += " · 没有发现问题"
		}
		out = append(out, Topic{Name: c.Label(), Container: true, Detail: detail})
	}
	if len(out) > maxTopics {
		out = out[:maxTopics]
	}
	return out
}

// Has tells whether name matches anything in the report (for a typed name).
func (r *Report) Has(name string) bool {
	saved := r.only
	defer func() { r.only = saved }()
	r.FilterPackage(name)
	for _, f := range r.Findings {
		if r.matches(f) {
			return true
		}
	}
	return false
}
