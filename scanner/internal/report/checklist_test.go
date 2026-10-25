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
		"lysec v0.1.5  racknerd-5a83f4d · Debian 12 · 内核 6.1.0-54-amd64 · 只读检查",
		" ● 状态良好  没有需要立即处理的漏洞，有 2 项建议更新",
		"   系统软件包  ✓ 共 730 个，官方源的都没有待修的漏洞（第三方源装的见“程序”）",
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
		if strings.Contains(line, "建议这样做") || strings.Contains(line, "lysec") {
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

// A serious problem with nothing to upgrade to is not "update soon".
func TestVerdictWhenUrgentProgramCannotBeUpgraded(t *testing.T) {
	r := racknerd()
	r.Containers = nil
	r.noNewer["caddy"] = true
	for i := range r.Findings {
		if r.Findings[i].Package == "caddy" {
			r.Findings[i].Priority = "P1"
		}
	}
	_, title, msg := r.Verdict()
	if title != "需要留意" || !strings.Contains(msg, "还没有可升级的版本") {
		t.Errorf("%s %s", title, msg)
	}
	for i := range r.Findings {
		if r.Findings[i].Package == "caddy" {
			r.Findings[i].KEV = true
		}
	}
	if level, title, msg := r.Verdict(); level != "urgent" || !strings.Contains(msg, "必要时先停止它对外服务") {
		t.Errorf("%s %s %s", level, title, msg)
	}
}

// Debian's caddy 2.6.2-5: the fix (2.6.2-5+deb12u1) is published but not in
// the machine's repositories yet, so apt offers nothing newer.
func TestFixNotInRepositoriesYet(t *testing.T) {
	var fs []match.Finding
	for _, id := range []string{"CVE-2026-27590", "CVE-2026-27587"} {
		fs = append(fs, match.Finding{ID: id, CVEs: []string{id}, Package: "caddy", Binaries: []string{"caddy"}, InstalledVersion: "2.6.2-5",
			FixedVersion: "2.6.2-5+deb12u1", Status: match.ConfirmedAffected, Fix: match.FixUpgrade, CVSS: f64(8.9), Layer: "L1", Priority: "P1"})
	}
	inv := &system.Inventory{Indexed: true, Packages: []system.Package{{Name: "caddy", Version: "2.6.2-5", Origin: system.Official}}}
	o := system.OS{PrettyName: "Debian GNU/Linux 12 (bookworm)", Distro: "debian", Release: "12", Kind: version.Deb}
	rt := &procinfo.Report{Exposed: map[string]bool{"caddy": true}} // serves the web: P1
	build := func() *Report {
		return Build("v0.1.11", o, inv, match.Result{Findings: fs, PackagesScanned: 395}, rt, DataInfo{KeyID: "X"}, nil, false, nil, nil)
	}
	r := build()
	out := render(r)
	for _, want := range []string{
		"● 需要留意  1 项较严重的漏洞还没有可升级的版本",
		"系统软件包  ✓ 395 个都没有待修的漏洞",
		"等源更新  caddy  修复已发布，还没进你的软件源，通常随 Debian 下次小版本更新到达，现在无需操作",
		"看详情  secwatch scan --pkg caddy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "apt-get") || strings.Contains(out, "建议尽快更新") {
		t.Errorf("nothing to run yet\n%s", out)
	}
	r.FilterPackage("caddy")
	if out := render(r); !strings.Contains(out, "修复版本 2.6.2-5+deb12u1 已发布，但还没进你的软件源") {
		t.Errorf("--pkg explains\n%s", out)
	}
	// Once apt offers a newer caddy, it is an ordinary update again.
	inv.Packages[0].Newer = "2.6.2-5+deb12u1"
	if out := render(build()); !strings.Contains(out, "● 建议尽快更新") || !strings.Contains(out, "apt-get") {
		t.Errorf("available fix is an update\n%s", out)
	}
	// Stale lists prove nothing.
	inv.Packages[0].Newer, inv.Indexed = "", false
	if out := render(build()); !strings.Contains(out, "● 建议尽快更新") {
		t.Errorf("without fresh lists, the usual advice\n%s", out)
	}
}

func TestVerdictForPackagesWaitingForRepositories(t *testing.T) {
	f := match.Finding{ID: "CVE-1", CVEs: []string{"CVE-1"}, Package: "caddy", Binaries: []string{"caddy"}, InstalledVersion: "2.6.2-5",
		FixedVersion: "2.6.2-5+deb12u1", Status: match.ConfirmedAffected, Fix: match.FixUpgrade, CVSS: f64(5.4), Layer: "L1"}
	inv := &system.Inventory{Indexed: true, Packages: []system.Package{{Name: "caddy", Version: "2.6.2-5", Origin: system.Official}}}
	o := system.OS{Distro: "debian", Release: "12", Kind: version.Deb}
	r := Build("v", o, inv, match.Result{Findings: []match.Finding{f}}, nil, DataInfo{}, nil, false, nil, nil)
	if _, title, msg := r.Verdict(); title != "状态良好" || msg != "没有需要你处理的问题，1 个软件包的修复还没进你的软件源" {
		t.Errorf("%s %s", title, msg)
	}
}
