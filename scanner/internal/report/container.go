package report

import (
	"fmt"
	"strings"

	"github.com/ly2u/sec/scanner/internal/container"
)

// ContainerResult is the scan of one running container's root filesystem.
type ContainerResult struct {
	container.Target
	OS string `json:"os,omitempty"` // e.g. "Debian 12"
	// Status: scanned, or skipped with Reason (unsupported OS, no package
	// database, data unavailable, unreadable).
	Status string  `json:"status"`
	Reason string  `json:"reason,omitempty"`
	Report *Report `json:"report,omitempty"`
}

// Container status values.
const (
	ContainerScanned = "scanned"
	ContainerSkipped = "skipped"
)

// AddContainers attaches container results to the host report. Each scanned
// container's own report renders like a host report with --container.
func (r *Report) AddContainers(cs []ContainerResult, attempted bool) {
	r.Containers = cs
	r.containersScanned = attempted
	for i := range r.Containers {
		if sub := r.Containers[i].Report; sub != nil {
			t := r.Containers[i].Target
			sub.inContainer = &t
			sub.showAll = r.showAll
		}
	}
}

// SelectContainer makes the text report show one container (--container);
// false if there is no scanned container by that name or ID.
func (r *Report) SelectContainer(name string) (*Report, bool) {
	for _, c := range r.Containers {
		if (c.Name == name || c.ID == name) && c.Report != nil {
			c.Report.only = r.only
			c.Report.Color = r.Color
			return c.Report, true
		}
	}
	return nil, false
}

var distroNames = map[string]string{"debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine", "rocky": "Rocky Linux", "alma": "AlmaLinux"}

// OSLabel is a short display name such as "Ubuntu 24.04".
func OSLabel(id, distro, release, versionID string) string {
	if n, ok := distroNames[distro]; ok {
		return n + " " + release
	}
	return strings.TrimSpace(id + " " + versionID)
}

// containerVerdict is the one-cell result of a container in the host summary.
func (c ContainerResult) verdict() (style, text string) {
	if c.Report == nil {
		return cDim, "未检查：" + c.Reason
	}
	fixable := c.Report.group(isFixable)
	urgent := 0
	for _, g := range fixable {
		if g.priority == "P0" || g.priority == "P1" {
			urgent++
		}
	}
	switch {
	case len(fixable) == 0:
		return cGreen, "✓ 没有需要更新的软件包"
	case urgent > 0:
		style = cYellow
		for _, g := range fixable {
			if g.priority == "P0" {
				style = cRed
			}
		}
		return style, fmt.Sprintf("✗ %d 个需要尽快处理（共 %d 个软件包有更新）", urgent, len(fixable))
	default:
		return "", fmt.Sprintf("! %d 个软件包有更新，无紧急问题", len(fixable))
	}
}

// writeContainers is the container table of the host summary.
func (r *Report) writeContainers(t term) {
	if len(r.Containers) == 0 {
		return
	}
	nw, ow := width("容器"), width("系统")
	for _, c := range r.Containers {
		nw = max(nw, min(width(c.Label()), 20))
		ow = max(ow, width(c.OS))
	}
	fmt.Fprintln(t)
	t.paint(cBold, fmt.Sprintf("容器（%d 个运行中，检查了容器内的系统软件包）", len(r.Containers)))
	fmt.Fprintln(t)
	t.paint(cDim, fmt.Sprintf("  %s  %s  %s", pad("容器", nw), pad("系统", ow), "结果"))
	fmt.Fprintln(t)
	for _, c := range r.Containers {
		style, text := c.verdict()
		fmt.Fprintf(t, "  %s  %s  ", pad(clip(c.Label(), nw), nw), pad(c.OS, ow))
		t.paint(style, text)
		fmt.Fprintln(t)
	}
}

// containersToFix lists scanned containers with packages to update.
func (r *Report) containersToFix() []ContainerResult {
	var out []ContainerResult
	for _, c := range r.Containers {
		if c.Report != nil && len(c.Report.group(isFixable)) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// writeContainerFix replaces the host's upgrade steps in a container's own
// report: packages inside a container are fixed by a newer image.
func (r *Report) writeContainerFix(t term) {
	c := r.inContainer
	fmt.Fprintln(t)
	t.paint(cBold, "怎么修（容器里的漏洞要靠更新镜像修复）")
	fmt.Fprintln(t)
	fmt.Fprintln(t, "  不要在容器里直接升级软件包：容器重建后改动会丢失。")
	step := 1
	if c.Image != "" && !strings.Contains(c.Image, "@") {
		fmt.Fprintf(t, "  %d. ", step)
		t.paint(cCmd, "docker pull "+c.Image)
		t.paint(cDim, "  # 拉取这个镜像标签的最新版本")
		fmt.Fprintln(t)
		step++
	}
	fmt.Fprintf(t, "  %d. 用原来的方式重建容器，例如在 compose 文件所在目录执行 ", step)
	t.paint(cCmd, "docker compose up -d")
	fmt.Fprintln(t)
	step++
	fmt.Fprintf(t, "  %d. ", step)
	t.paint(cCmd, "secwatch scan --container "+c.Label())
	t.paint(cDim, "  # 再查一次")
	fmt.Fprintln(t)
	t.paint(cDim, "  如果最新镜像仍有这些漏洞，说明镜像还没更新：换用更新的版本标签，或者自建镜像时先升级基础镜像。")
	fmt.Fprintln(t)
}

// containerBrief is the header line of a container's own report.
func (r *Report) containerBrief() string {
	c := r.inContainer
	s := "容器 " + c.Label()
	if c.Image != "" {
		s += "（镜像 " + c.Image + "）"
	}
	return s
}

// exceedsContainers applies --fail-on to the containers too.
func (r *Report) exceedsContainers(level string) bool {
	for _, c := range r.Containers {
		if c.Report != nil && c.Report.Exceeds(level) {
			return true
		}
	}
	return false
}
