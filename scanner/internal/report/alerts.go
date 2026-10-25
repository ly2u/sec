package report

import (
	"sort"
	"strings"
)

// Alert is one thing to notify about: a package or program on the host or in
// a container whose priority reaches the notification level.
type Alert struct {
	Key      string `json:"key"`      // stable identity: where + name
	Where    string `json:"where"`    // "本机" or "容器 NAME"
	Name     string `json:"name"`     // package or program
	Priority string `json:"priority"` // P0..P3
	Text     string `json:"text"`     // one line for a message
}

// Verdict is the report's one-line conclusion: a level (urgent, soon, ok),
// a title and a sentence, as in the first line of the check-up list.
func (r *Report) Verdict() (level, title, msg string) {
	style, title, msg := r.verdict(r.group(isFixable))
	switch style {
	case cRed:
		level = "urgent"
	case cYellow:
		level = "soon"
	default:
		level = "ok"
	}
	return level, title, msg
}

// Alerts lists what reaches level (P0 highest) on the host and in its
// containers; anything exploited in the wild always does.
func (r *Report) Alerts(level string) []Alert {
	var out []Alert
	add := func(where string, gs []*pkgGroup) {
		for _, g := range gs {
			if g.priority > level && !g.kev {
				continue
			}
			var tags []string
			tags = append(tags, priorityLabel[g.priority])
			switch {
			case g.ransom:
				tags = append(tags, "已被勒索软件利用")
			case g.kev:
				tags = append(tags, "已被在野利用")
			}
			if g.exposed {
				tags = append(tags, "对外服务")
			}
			if hasKernel(g) {
				tags = append(tags, "需重启")
			}
			text := g.pkg + "（" + strings.Join(tags, " · ") + "）"
			if where != "本机" {
				text = where + "：" + text
			}
			out = append(out, Alert{Key: where + "/" + g.pkg, Where: where, Name: g.pkg, Priority: g.priority, Text: text})
		}
	}
	add("本机", r.group(isFixable))
	for _, c := range r.Containers {
		if c.Report != nil {
			add("容器 "+c.Label(), c.Report.group(isFixable))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}
