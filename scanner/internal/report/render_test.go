package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/l2"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/procinfo"
	"github.com/ly2u/sec/scanner/internal/system"
	"github.com/ly2u/sec/scanner/internal/version"
)

func f64(v float64) *float64 { return &v }

// An outdated Debian 12 host, shaped like a real scan: a few urgent packages
// and many routine ones.
func outdatedHost(showAll bool) *Report {
	findings := []match.Finding{
		{ID: "CVE-2026-24061", CVEs: []string{"CVE-2026-24061"}, Package: "inetutils", Binaries: []string{"inetutils-telnet"},
			InstalledVersion: "2:2.4-2", FixedVersion: "2:2.4-2+deb12u3", Status: match.ConfirmedAffected, Fix: match.FixUpgrade,
			CVSS: f64(9.8), KEV: true, Layer: "L1", Refs: []string{"https://security-tracker.debian.org/tracker/CVE-2026-24061"}},
		{ID: "CVE-2024-6387", CVEs: []string{"CVE-2024-6387"}, Package: "openssh", Binaries: []string{"openssh-server"},
			InstalledVersion: "1:9.2p1-2", FixedVersion: "1:9.2p1-2+deb12u3", Status: match.ConfirmedAffected, Fix: match.FixUpgrade,
			CVSS: f64(8.1), Layer: "L1"},
		{ID: "CVE-2023-38408", CVEs: []string{"CVE-2023-38408"}, Package: "openssh", Binaries: []string{"openssh-server"},
			InstalledVersion: "1:9.2p1-2", FixedVersion: "1:9.2p1-2+deb12u10", Status: match.ConfirmedAffected, Fix: match.FixUpgrade,
			CVSS: f64(9.8), Layer: "L1"},
		{ID: "CVE-2025-1000", CVEs: []string{"CVE-2025-1000"}, Package: "linux", Binaries: []string{"linux-image-6.1.0-9-amd64"},
			InstalledVersion: "6.1.27-1", FixedVersion: "6.1.158-1", Status: match.ConfirmedAffected, Fix: match.FixUpgrade,
			CVSS: f64(7.8), EPSS: f64(0.4), Kernel: true, Layer: "L1"},
	}
	for i := 0; i < 20; i++ {
		findings = append(findings, match.Finding{
			ID: fmt.Sprintf("CVE-2026-%05d", 10000+i), CVEs: []string{fmt.Sprintf("CVE-2026-%05d", 10000+i)},
			Package: fmt.Sprintf("lib%02d", i), Binaries: []string{fmt.Sprintf("lib%02d", i)},
			InstalledVersion: "1.0-1", FixedVersion: "1.0-1+deb12u1", Status: match.ConfirmedAffected, Fix: match.FixUpgrade,
			CVSS: f64(7.5), Layer: "L1",
		})
	}
	findings = append(findings, match.Finding{ID: "CVE-2026-99999", CVEs: []string{"CVE-2026-99999"}, Package: "less", Binaries: []string{"less"},
		InstalledVersion: "590-2", FixedVersion: "590-2.1", Status: match.ConfirmedAffected, Fix: match.FixUpgrade, CVSS: f64(4.0), Layer: "L1"})
	rt := &procinfo.Report{
		Listeners: []procinfo.Listener{{Address: "0.0.0.0", Port: 22, Public: true, Process: "sshd"}, {Address: "::", Port: 443, Public: true, Process: "caddy"}},
		Exposed:   map[string]bool{"openssh": true},
	}
	res := match.Result{Findings: findings, PackagesScanned: 729}
	o := system.OS{PrettyName: "Debian GNU/Linux 12 (bookworm)", Distro: "debian", Release: "12", Kind: version.Deb}
	data := DataInfo{File: "debian-12.abc.json.zst", GeneratedAt: time.Date(2026, 10, 24, 4, 11, 0, 0, time.UTC), KeyID: "D7B7CA69ADC798BC"}
	return Build("v0.1.1", o, &system.Inventory{}, res, rt, data, nil, showAll, nil, nil)
}

func render(r *Report) string {
	var b bytes.Buffer
	r.WriteText(&b)
	return b.String()
}

func TestSummaryIsAChecklist(t *testing.T) {
	out := render(outdatedHost(false))
	t.Log("\n" + out)
	for _, want := range []string{
		"● 有紧急问题  1 个软件包的漏洞已被黑客实际利用，请今天处理",
		"   系统软件包  ✗ 24 个需要更新",
		"立即  inetutils · openssh",
		"尽快  linux(需重启)",
		"其他  21 个，跟上面一起升级",
		" 建议这样做",
		"   1  sudo apt-get update && sudo apt-get upgrade --with-new-pkgs  # 安装全部安全更新",
		"   2  sudo reboot",
		"   3  secwatch scan",
		"升级中如有弹窗",
		"看详情  secwatch scan --pkg inetutils     完整报告  secwatch scan --all",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, noisy := range []string{"验证：", "dpkg-query", "--only-upgrade", "参考：", "https://", "1:9.2p1-2", "CVE-"} {
		if strings.Contains(out, noisy) {
			t.Errorf("default view must not contain %q", noisy)
		}
	}
	if lines := strings.Count(out, "\n"); lines > 24 {
		t.Errorf("default report too long: %d lines", lines)
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("no colour unless requested")
	}
}

func TestSummaryColoursOnlyFromConstants(t *testing.T) {
	r := outdatedHost(false)
	r.Color = true
	r.Findings[0].Package = "inet\x1b[2Jutils"
	out := render(r)
	if !strings.Contains(out, "\x1b[1;31m● 有紧急问题\x1b[0m") {
		t.Errorf("verdict should be red on a colour terminal:\n%q", out)
	}
	if strings.Contains(out, "\x1b[2J") {
		t.Error("escape sequences from scanned data must still be neutralised")
	}
}

func TestPackageView(t *testing.T) {
	r := outdatedHost(false)
	r.FilterPackage("openssh-server") // binary name works as well as the source name
	out := render(r)
	t.Log("\n" + out)
	for _, want := range []string{
		"openssh  1:9.2p1-2 → 1:9.2p1-2+deb12u10  P0 立即处理",
		"  风险  严重 9.8 · 对外服务",
		"  修复  sudo apt-get update && sudo apt-get install --only-upgrade openssh-server",
		"  验证  dpkg-query",
		"可修复的漏洞 2 个（按风险排序）",
		"    P0  CVE-2023-38408    严重 9.8 · 修复于 1:9.2p1-2+deb12u10",
		"https://sec.ly2u.com/cve/<漏洞编号>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "inetutils") {
		t.Error("other packages must not be shown")
	}
	r.FilterPackage("nope")
	if out := render(r); !strings.Contains(out, "没有找到 nope 的漏洞") {
		t.Errorf("unknown name:\n%s", out)
	}
}

func TestWidthCountsCJKAsTwoColumns(t *testing.T) {
	if width("软件包") != 6 || width("P0 立即") != 7 || pad("优先级", 7) != "优先级 " {
		t.Fatal("display width")
	}
	if got := clip("averyveryverylongname", 8); got != "averyve~" {
		t.Fatalf("clip: %q", got)
	}
}

func TestDetailedReportKeepsCommandsAndReferences(t *testing.T) {
	out := render(outdatedHost(true))
	for _, want := range []string{"验证：dpkg-query", "--only-upgrade inetutils-telnet", "参考：https://security-tracker.debian.org/tracker/CVE-2026-24061", "== 只升级以上列出的软件包 ==", "less"} {
		if !strings.Contains(out, want) {
			t.Errorf("--all must contain %q", want)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "再次运行 secwatch scan 确认已全部修复") {
		t.Error("--all also ends with the next steps")
	}
}

func TestCleanHostHasNoNextSteps(t *testing.T) {
	o := system.OS{PrettyName: "Debian GNU/Linux 13 (trixie)", Distro: "debian", Release: "13", Kind: version.Deb}
	r := Build("v0.1.1", o, &system.Inventory{}, match.Result{PackagesScanned: 352}, nil, DataInfo{KeyID: "D7B7CA69ADC798BC"}, nil, false, nil, nil)
	out := render(r)
	if !strings.Contains(out, "● 状态良好  没有发现需要处理的安全问题") || !strings.Contains(out, "系统软件包  ✓ 352 个都是最新") || strings.Contains(out, "建议这样做") {
		t.Errorf("clean host:\n%s", out)
	}
}

func TestServiceNamesInCommandsAreWhitelisted(t *testing.T) {
	r := outdatedHost(false)
	// The kernel finding forces a reboot; drop it to reach the per-service advice.
	var keep []match.Finding
	for _, f := range r.Findings {
		if !f.Kernel {
			keep = append(keep, f)
		}
	}
	r.Findings = keep
	r.Runtime.Listeners = append(r.Runtime.Listeners, procinfo.Listener{Public: true, Process: "evil;rm -rf /"})
	out := render(r)
	steps := out[strings.LastIndex(out, "建议这样做"):]
	if !strings.Contains(steps, "至少重启对外服务：sshd、caddy\n") || strings.Contains(steps, "evil") {
		t.Errorf("service names in suggested actions must pass the whitelist:\n%s", steps)
	}
}

// Shaped like the first real scan of an outdated Debian 12 VPS (v0.1.1):
// 7 P0, 6 P1, 42 P2 and 15 P3 packages, thousands of unfixed issues, a
// NodeSource Node.js, Caddy from its own repository and MariaDB in Docker.
func realisticHost() *Report {
	var fs []match.Finding
	add := func(pkg, bin, inst, fix string, n int, cvss, epss float64, kev, kernel bool) {
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("CVE-2025-%05d", len(fs)+10000)
			f := match.Finding{ID: id, CVEs: []string{id}, Package: pkg, Binaries: []string{bin}, InstalledVersion: inst,
				FixedVersion: fix, Status: match.ConfirmedAffected, Fix: match.FixUpgrade, Layer: "L1", Kernel: kernel}
			if i == 0 {
				f.CVSS, f.KEV = f64(cvss), kev
				if epss > 0 {
					f.EPSS = f64(epss)
				}
			} else {
				f.CVSS = f64(5.5)
			}
			fs = append(fs, f)
		}
	}
	add("linux", "linux-image-6.1.0-9-amd64", "6.1.27-1", "6.1.190-1", 7887, 10.0, 0.94, true, true)
	add("inetutils", "inetutils-telnet", "2:2.4-2", "2:2.4-2+deb12u3", 5, 9.8, 0.99, true, false)
	add("freetype", "libfreetype6", "2.12.1+dfsg-5", "2.12.1+dfsg-5+deb12u4", 1, 8.1, 0.28, true, false)
	add("nghttp2", "libnghttp2-14", "1.52.0-1", "1.52.0-1+deb12u3", 3, 7.5, 1.0, true, false)
	add("openssh", "openssh-server", "1:9.2p1-2", "1:9.2p1-2+deb12u10", 17, 9.8, 1.0, false, false)
	add("krb5", "libkrb5-3", "1.20.1-2", "1.20.1-2+deb12u5", 9, 9.1, 0, false, false)
	add("openssl", "libssl3", "3.0.9-1", "3.0.22-1~deb12u1", 48, 9.1, 0.67, false, false)
	add("xz-utils", "liblzma5", "5.4.1-0.2", "5.4.1-1+deb12u1", 2, 8.7, 0, false, false)
	add("pcre2", "libpcre2-8-0", "10.42-1", "10.42-1+deb12u2", 7, 8.2, 0, false, false)
	add("pam", "libpam0g", "1.5.2-6", "1.5.2-6+deb12u2", 2, 7.8, 0, false, false)
	add("systemd", "systemd", "252.6-1", "252.39-1~deb12u2", 8, 7.5, 1.0, false, false)
	add("sqlite3", "libsqlite3-0", "3.40.1-2", "3.40.1-2+deb12u2", 2, 7.2, 0.73, false, false)
	for i := 0; i < 42; i++ {
		add(fmt.Sprintf("lib%02d", i), fmt.Sprintf("lib%02d", i), "1.0-1", "1.0-1+deb12u1", 3, 8.8, 0, false, false)
	}
	for i := 0; i < 15; i++ {
		add(fmt.Sprintf("low%02d", i), fmt.Sprintf("low%02d", i), "1.0-1", "1.0-1+deb12u1", 1, 5.0, 0, false, false)
	}
	unfixed := func(pkg, inst string, cvss, epss float64) {
		id := fmt.Sprintf("CVE-2026-%05d", len(fs)+10000)
		f := match.Finding{ID: id, CVEs: []string{id}, Package: pkg, Binaries: []string{pkg}, InstalledVersion: inst,
			Status: match.ConfirmedAffected, Fix: match.FixNone, Layer: "L1", CVSS: f64(cvss)}
		if epss > 0 {
			f.EPSS = f64(epss)
		}
		fs = append(fs, f)
	}
	unfixed("glibc", "2.36-9+deb12u14", 9.8, 0)
	unfixed("linux", "6.1.27-1", 7.5, 0.70)
	for i := 0; i < 2491; i++ {
		unfixed("linux", "6.1.27-1", 5.5, 0)
	}
	node := match.Finding{ID: "CVE-2026-111497", CVEs: []string{"CVE-2026-111497"}, Package: "Node.js", Binaries: []string{"nodejs"},
		InstalledVersion: "22.22.0", FixedVersion: "22.23.4", Status: match.ConfirmedAffected, Fix: match.FixUpgrade,
		CVSS: f64(9.2), EPSS: f64(0.25), Layer: "L2", Method: "package"}

	rt := &procinfo.Report{
		Listeners: []procinfo.Listener{
			{Address: "::", Port: 80, Public: true, Process: "caddy"}, {Address: "::", Port: 443, Public: true, Process: "caddy"},
			{Address: "::", Port: 3001, Public: true, Process: "bun"}, {Address: "0.0.0.0", Port: 21445, Public: true, Process: "sshd"},
		},
		Exposed: map[string]bool{"openssh": true, "krb5": true, "openssl": true, "xz-utils": true, "pcre2": true, "pam": true, "systemd": true, "glibc": true},
	}
	res := match.Result{Findings: fs, PackagesScanned: 729, MinorUnfixed: 390,
		ThirdParty: []system.Package{{Name: "caddy", Version: "2.10.2", OriginLabel: "source=none"}},
		Kernel:     match.KernelState{Running: "6.1.0-9-amd64"}}
	o := system.OS{PrettyName: "Debian GNU/Linux 12 (bookworm)", Distro: "debian", Release: "12", Kind: version.Deb}
	data := DataInfo{File: "debian-12.abc.json.zst", GeneratedAt: time.Date(2026, 10, 24, 4, 11, 0, 0, time.UTC), KeyID: "D7B7CA69ADC798BC", FromCache: true}
	found := &l2.Result{
		Installs:   []l2.Install{{Product: "node", ProductName: "Node.js", Version: "22.22.0", Method: "package", Packages: []string{"nodejs"}}},
		Containers: []l2.ContainerProcess{{Product: "mariadb", Name: "mariadbd", PID: 657}},
	}
	return Build("v0.1.2", o, &system.Inventory{}, res, rt, data, []string{bundle.WarnManifestUnsigned}, false, found, &l2.Outcome{Findings: []match.Finding{node}})
}

func TestRealisticHostFitsOneScreen(t *testing.T) {
	out := render(realisticHost())
	t.Log("\n" + out)
	if lines := strings.Count(out, "\n"); lines > 34 {
		t.Errorf("default report should fit one screen, got %d lines", lines)
	}
	for _, want := range []string{
		"● 有紧急问题  4 个软件包的漏洞已被黑客实际利用，请今天处理",
		"   系统软件包  ✗ 69 个需要更新",
		"立即  linux(需重启) · inetutils · freetype · nghttp2 · openssh · krb5 · openssl",
		"尽快  xz-utils · pcre2 · pam · systemd · sqlite3",
		"其他  57 个，跟上面一起升级",
		"   程序        ✗ 1 个需要更新",
		"Node.js                   1 个漏洞    升级即可，见第 1 步",
		"   容器        · 有容器在运行，但没有检查（需要以 root 运行）",
		"   等待补丁    · glibc、内核各 1 项值得关注  Debian 还没发布修复，无需操作",
		"   留意        · 未检查：caddy（第三方源，请关注其官方公告）",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	r := realisticHost()
	for i := range r.Findings {
		if r.Findings[i].Package == "inetutils" {
			r.Findings[i].Ransomware = true
		}
	}
	if out := render(r); !strings.Contains(out, "（其中 1 个被勒索软件利用）") || !strings.Contains(out, "inetutils(勒索软件在用)") {
		t.Error("ransomware use is the strongest signal and replaces the plain KEV mark")
	}
	if strings.Contains(out, "manifest") {
		t.Error("the unsigned-manifest caveat belongs to --all")
	}
}

func TestFailOnThreshold(t *testing.T) {
	r := outdatedHost(false) // P0 with KEV, P1, P2, P3
	for level, want := range map[string]bool{"P0": true, "P1": true, "P3": true, "none": false} {
		if r.Exceeds(level) != want {
			t.Errorf("--fail-on %s: want %v", level, want)
		}
	}
	// Only P2/P3 left: the default threshold passes, P2 fails.
	var keep []match.Finding
	for _, f := range r.Findings {
		if f.Priority >= "P2" {
			keep = append(keep, f)
		}
	}
	r.Findings = keep
	r.Summary.ByPriority = map[string]int{"P2": 20, "P3": 1}
	r.Summary.KEV = 0
	if r.Urgent() || !r.Exceeds("P2") || r.Exceeds("P1") {
		t.Error("threshold comparison")
	}
}

func TestUpdateHint(t *testing.T) {
	r := outdatedHost(false)
	if strings.Contains(render(r), "有新版本") {
		t.Error("no hint without a newer release")
	}
	r.Update = "v0.1.4"
	out := render(r)
	if !strings.HasSuffix(strings.TrimSpace(out), "有新版本 v0.1.4（当前 v0.1.1），更新：sudo secwatch update（或在 sudo secwatch 菜单里选“更新”）") {
		t.Errorf("the hint is the last line:\n%s", out)
	}
	// With the short name installed, every hint uses it.
	Cmd = "lysec"
	defer func() { Cmd = "secwatch" }()
	out = render(r)
	if !strings.Contains(out, "sudo lysec update") || strings.Contains(out, "secwatch scan") {
		t.Errorf("short name everywhere:\n%s", out)
	}
}

func TestGoComponentsAndSteps(t *testing.T) {
	mk := func(id, mod, modv, fix, comp string) match.Finding {
		f := match.Finding{ID: id, CVEs: []string{id}, Package: "agent", InstalledVersion: "0.0.0-20260917063746-c7bafb79b1a7",
			Layer: "L2", Method: "go", Path: "/opt/komari/agent", Module: mod, ModuleVersion: modv, Component: comp,
			Project: "https://github.com/komari-monitor/komari-agent/releases", Unit: "komari-agent.service",
			Status: match.PotentiallyAffected, Fix: match.FixUpgrade, FixedVersion: fix, CVSS: f64(7.5)}
		if fix == "" {
			f.Fix = match.FixNone
		}
		return f
	}
	fs := []match.Finding{
		mk("CVE-1", "stdlib", "1.24.0", "1.24.13", "Go 1.24.0 标准库"),
		mk("CVE-2", "stdlib", "1.24.0", "1.25.13", "Go 1.24.0 标准库"),
		mk("CVE-3", "golang.org/x/net", "0.38.0", "0.55.0", "依赖 golang.org/x/net 0.38.0"),
		mk("GO-4", "golang.org/x/crypto", "0.39.0", "", "依赖 golang.org/x/crypto 0.39.0"),
	}
	o := system.OS{PrettyName: "Debian GNU/Linux 12 (bookworm)", Distro: "debian", Release: "12", Kind: version.Deb}
	r := Build("v0.1.4", o, &system.Inventory{}, match.Result{}, nil, DataInfo{KeyID: "X"}, nil, false, &l2.Result{}, &l2.Outcome{Findings: fs})
	r.FilterPackage("agent")
	out := render(r)
	t.Log("\n" + out)
	for _, want := range []string{
		"agent  未标版本号（2026-09-17 的代码）  P2 有空时处理",
		"位置  /opt/komari/agent（Go 程序，服务 komari-agent.service）",
		"问题出在这些组件（共 4 个漏洞：3 个已有修复版本，1 个暂无修复）",
		"Go 标准库            1.24.0         2  用 Go 1.25.13 或更高版本编译",
		"golang.org/x/net     0.38.0         1  0.55.0 或更高",
		"golang.org/x/crypto  0.39.0         1  暂无修复版本",
		"1. 打开 https://github.com/komari-monitor/komari-agent/releases，复制最新版中 linux-",
		"2. curl -fL -o /tmp/agent.new '<下载链接>'",
		"3. sudo cp -a /opt/komari/agent /opt/komari/agent.bak-",
		"4. sudo systemctl stop komari-agent.service",
		"5. sudo install -m 755 /tmp/agent.new /opt/komari/agent",
		"6. sudo systemctl start komari-agent.service",
		"7. secwatch scan --pkg agent",
		"出问题时回滚：sudo cp -a /opt/komari/agent.bak-",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Count(out, "\n") > 32 {
		t.Error("the program view should stay short")
	}

	// A path that is unsafe in a shell command gets prose, never a command.
	for i := range r.Findings {
		r.Findings[i].Path = "/opt/my app/agent;id"
	}
	odd := render(r)
	if strings.Contains(odd, "sudo install") || strings.Contains(odd, "sudo cp") || !strings.Contains(odd, "备份并用新文件替换") {
		t.Errorf("unsafe path in commands:\n%s", odd)
	}
}

// Only programs outside the distribution need fixing: no server reboot, no
// full system upgrade, no apt prompts; restart the services instead.
func TestThirdPartyOnlyFixRestartsServices(t *testing.T) {
	caddy := match.Finding{ID: "CVE-2099-1", CVEs: []string{"CVE-2099-1"}, Package: "caddy", Binaries: []string{"caddy"},
		InstalledVersion: "2.10.2", Layer: "L2", Method: "package", Path: "/usr/bin/caddy", Module: "stdlib", ModuleVersion: "1.25.0",
		Component: "Go 1.25.0 标准库", Unit: "caddy.service", Status: match.PotentiallyAffected, Fix: match.FixUpgrade,
		FixedVersion: "1.25.5", CVSS: f64(9.8)}
	o := system.OS{PrettyName: "Debian GNU/Linux 12 (bookworm)", Distro: "debian", Release: "12", Kind: version.Deb}
	rt := &procinfo.Report{Listeners: []procinfo.Listener{{Address: "::", Port: 443, Public: true, Process: "caddy"}}, Exposed: map[string]bool{"caddy": true}}
	r := Build("v0.1.5", o, &system.Inventory{}, match.Result{PackagesScanned: 10}, rt, DataInfo{KeyID: "X"}, nil, false, &l2.Result{}, &l2.Outcome{Findings: []match.Finding{caddy}})
	out := render(r)
	t.Log("\n" + out)
	for _, want := range []string{
		"1  sudo apt-get update && sudo apt-get install --only-upgrade caddy",
		"2  sudo systemctl restart caddy.service",
		"不用重启服务器",
		"caddy          对外服务   1 个漏洞    升级即可，见第 1 步",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, unwanted := range []string{"sudo reboot", "upgrade --with-new-pkgs", "keep the local version"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("must not contain %q", unwanted)
		}
	}
}

func TestPkgMatchesProgramFileName(t *testing.T) {
	f := match.Finding{ID: "CVE-2099-9", CVEs: []string{"CVE-2099-9"}, Package: "komari-agent", InstalledVersion: "1.5.0",
		Layer: "L2", Method: "go", Path: "/opt/komari/agent", Module: "stdlib", ModuleVersion: "1.24.0", Component: "Go 1.24.0 标准库",
		Status: match.PotentiallyAffected, Fix: match.FixUpgrade, FixedVersion: "1.24.13", CVSS: f64(7.5)}
	o := system.OS{PrettyName: "Debian GNU/Linux 12 (bookworm)", Distro: "debian", Release: "12", Kind: version.Deb}
	r := Build("v0.1.5", o, &system.Inventory{}, match.Result{}, nil, DataInfo{KeyID: "X"}, nil, false, &l2.Result{}, &l2.Outcome{Findings: []match.Finding{f}})
	for _, name := range []string{"komari-agent", "agent", "Komari-Agent"} {
		r.FilterPackage(name)
		if out := render(r); !strings.Contains(out, "komari-agent  1.5.0") {
			t.Errorf("--pkg %s:\n%s", name, out)
		}
	}
}
