package report

import (
	"strings"
	"testing"
	"time"

	"github.com/ly2u/sec/scanner/internal/container"
	"github.com/ly2u/sec/scanner/internal/l2"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/procinfo"
	"github.com/ly2u/sec/scanner/internal/system"
	"github.com/ly2u/sec/scanner/internal/version"
)

func racknerd() *Report {
	var out []match.Finding
	goF := func(name, path, method, bin, unit, mod, modv, fix, comp string, n int, cvss float64) {
		for i := 0; i < n; i++ {
			f := match.Finding{ID: "CVE-2026-" + name + string(rune('a'+i%26)) + string(rune('a'+i/26)), Package: name, InstalledVersion: "1.0.0",
				Layer: "L2", Method: method, Path: path, Module: mod, ModuleVersion: modv, Component: comp, Unit: unit,
				Status: match.PotentiallyAffected, Fix: match.FixUpgrade, FixedVersion: fix, CVSS: f64(cvss)}
			if bin != "" {
				f.Binaries = []string{bin}
			}
			f.CVEs = []string{f.ID}
			out = append(out, f)
		}
	}
	goF("caddy", "/usr/bin/caddy", "package", "caddy", "caddy.service", "stdlib", "1.25.0", "1.25.9", "Go 1.25.0 标准库", 14, 9.8)
	goF("komari-agent", "/opt/komari/agent", "go", "", "komari-agent.service", "stdlib", "1.24.0", "1.26.10", "Go 1.24.0 标准库", 98, 10)
	out = append(out,
		match.Finding{ID: "CVE-2026-5450", CVEs: []string{"CVE-2026-5450"}, Package: "glibc", Binaries: []string{"libc6"}, InstalledVersion: "2.36-9+deb12u14", Status: match.ConfirmedAffected, Fix: match.FixNone, CVSS: f64(9.8), Layer: "L1"},
		match.Finding{ID: "CVE-2025-22037", CVEs: []string{"CVE-2025-22037"}, Package: "linux", Binaries: []string{"linux-image-amd64"}, InstalledVersion: "6.1.190-1", Status: match.ConfirmedAffected, Fix: match.FixNone, CVSS: f64(7.5), EPSS: f64(0.7), Layer: "L1"})
	rt := &procinfo.Report{Listeners: []procinfo.Listener{{Address: "::", Port: 443, Public: true, Process: "caddy"}}, Exposed: map[string]bool{"caddy": true, "glibc": true}}
	o := system.OS{PrettyName: "Debian GNU/Linux 12 (bookworm)", Distro: "debian", Release: "12", Kind: version.Deb}
	res := match.Result{PackagesScanned: 730, Kernel: match.KernelState{Running: "6.1.0-54-amd64"}}
	r := Build("v0.1.5", o, &system.Inventory{}, res, rt, DataInfo{GeneratedAt: time.Date(2026, 10, 25, 1, 18, 0, 0, time.UTC), KeyID: "X", FromCache: true}, nil, false,
		&l2.Result{Installs: []l2.Install{{ProductName: "caddy", Version: "2.10.2"}, {ProductName: "komari-agent", Version: "1.5.0"}}}, &l2.Outcome{Findings: out})
	r.Hostname = "racknerd-5a83f4d"
	var ctr []match.Finding
	for i := 0; i < 8; i++ {
		ctr = append(ctr, match.Finding{ID: "CVE-2026-90" + string(rune('0'+i)), CVEs: []string{"CVE-2026-90" + string(rune('0'+i))}, Package: "pkg" + string(rune('a'+i)), Binaries: []string{"pkg" + string(rune('a'+i))}, InstalledVersion: "1", FixedVersion: "2", Status: match.ConfirmedAffected, Fix: match.FixUpgrade, CVSS: f64(6.5), Layer: "L1"})
	}
	co := system.OS{PrettyName: "Debian GNU/Linux 13 (trixie)", Distro: "debian", Release: "13", Kind: version.Deb}
	sub := Build("v0.1.5", co, &system.Inventory{}, match.Result{Findings: ctr, PackagesScanned: 120}, nil, DataInfo{KeyID: "X"}, nil, false, nil, nil)
	r.AddContainers([]ContainerResult{{Target: container.Target{ID: "abc", Name: "qqbot-vps-api"}, OS: "Debian 13", Status: ContainerScanned, Report: sub}}, true)
	return r
}

// The first real users' VPS after upgrading: only programs and a container
// left, which must read as "fine, three things to update" with exact steps.
func TestChecklistOnMostlyCleanHost(t *testing.T) {
	out := render(racknerd())
	t.Log("\n" + out)
	for _, want := range []string{
		"LY2U SecWatch v0.1.5  racknerd-5a83f4d · Debian 12 · 内核 6.1.0-54-amd64 · 只读检查",
		" ● 状态良好  没有需要立即处理的漏洞，有 2 项建议更新",
		"   系统软件包  ✓ 730 个都是最新",
		"   程序        ! 1 个建议更新，1 个在等作者发布新版",
		"caddy          对外服务   14 个漏洞   升级即可，见第 1 步",
		"komari-agent              98 个漏洞   等作者发布新版，不急",
		"qqbot-vps-api  Debian 13  8 个软件包  重建镜像，见第 3 步",
		"   等待补丁    · glibc、内核各 1 项值得关注  Debian 还没发布修复，无需操作",
		"   2  sudo systemctl restart caddy.service",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "reboot") || strings.Contains(out, "弹窗") {
		t.Error("nothing from the distribution to upgrade: no reboot, no apt prompt hint")
	}
	if n := strings.Count(out, "\n"); n > 22 {
		t.Errorf("%d lines", n)
	}
}

func TestChecklistGutterOnColourTerminals(t *testing.T) {
	r := racknerd()
	r.Color = true
	out := render(r)
	bar := "\x1b[1;32m▌\x1b[0m"
	if !strings.Contains(out, bar+" \x1b[1;32m● 状态良好\x1b[0m") || !strings.Contains(out, bar+"   系统软件包") {
		t.Errorf("green bar in front of the check-up block:\n%q", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "建议这样做") || strings.Contains(line, "LY2U SecWatch") {
			if strings.Contains(line, "▌") {
				t.Errorf("only the check-up block has the bar: %q", line)
			}
		}
	}
	urgent := outdatedHost(false)
	urgent.Color = true
	if !strings.Contains(render(urgent), "\x1b[1;31m▌\x1b[0m") {
		t.Error("red bar when something is urgent")
	}
	r.Color = false
	if strings.Contains(render(r), "▌") {
		t.Error("plain output (logs, pipes) has no bar")
	}
}

func TestAlertsAndVerdict(t *testing.T) {
	r := outdatedHost(false)
	level, title, _ := r.Verdict()
	if level != "urgent" || title != "有紧急问题" {
		t.Errorf("verdict %s %s", level, title)
	}
	p1 := r.Alerts("P1")
	if len(p1) != 3 || p1[0].Text != "inetutils（立即处理 · 已被在野利用）" || p1[0].Key != "本机/inetutils" {
		t.Fatalf("P1 alerts: %+v", p1)
	}
	if n := len(r.Alerts("P2")); n != 23 {
		t.Errorf("P2 alerts: %d", n)
	}
	c := racknerd()
	if lvl, _, _ := c.Verdict(); lvl != "ok" || len(c.Alerts("P1")) != 0 {
		t.Error("a host with only P2 items has nothing to notify at P1")
	}
}

func TestChecklistPointsToMenuWhenNotScheduled(t *testing.T) {
	r := racknerd()
	if strings.Contains(render(r), "sudo secwatch  打开菜单") {
		t.Error("no hint once a scheduled check is set up")
	}
	r.MenuHint = true
	out := render(r)
	if !strings.Contains(out, " 定时提醒  sudo secwatch  打开菜单，可开启定时检查，有新问题时发到你的 Telegram") {
		t.Errorf("%s", out)
	}
	if n := strings.Count(out, "\n"); n > 23 {
		t.Errorf("%d lines", n)
	}
}

// caddy from Caddy's repository is already the newest version there: its
// Go standard library findings wait for a new release, like komari-agent.
func TestChecklistProgramAlreadyNewestInRepo(t *testing.T) {
	r := racknerd()
	r.noNewer["caddy"] = true
	out := render(r)
	for _, want := range []string{
		" ● 状态良好  没有需要立即处理的漏洞，有 1 项建议更新",
		"   程序        · 2 个有已知漏洞，暂时没有新版本可升级",
		"caddy          对外服务   14 个漏洞   源里已是最新版，等作者发布新版",
		"   1  secwatch scan --container qqbot-vps-api",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "only-upgrade caddy") || strings.Contains(out, "restart caddy") {
		t.Errorf("nothing to run for caddy\n%s", out)
	}
	// Without the container, nothing at all is left to do.
	r.Containers = nil
	if out := render(r); !strings.Contains(out, " ● 状态良好  没有需要你处理的问题，2 个程序在等作者发布新版") {
		t.Errorf("%s", out)
	}
}
