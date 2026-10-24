package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

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

func TestCompactReportLeadsWithVerdictAndEndsWithNextSteps(t *testing.T) {
	out := render(outdatedHost(false))
	// Counted by package, not by vulnerability: openssh has two CVEs but is one package.
	if !strings.Contains(out, "✗ 24 个软件包有可修复的安全漏洞：立即处理 2 个（1 个已被在野利用）、尽快处理 1 个、计划处理 20 个、低优先级 1 个") {
		t.Fatalf("verdict missing or wrong:\n%s", out)
	}
	if !strings.Contains(out, "openssh  1:9.2p1-2 → 1:9.2p1-2+deb12u10") ||
		!strings.Contains(out, "CVE-2023-38408 等 2 个漏洞，最高 CVSS 9.8，所在服务对外监听") {
		t.Errorf("P0 entry should be compact with the key facts:\n%s", out)
	}
	if !strings.Contains(out, "详情：https://sec.ly2u.com/cve/CVE-2026-24061") {
		t.Error("P0 entries link to the site, exploited CVE first")
	}
	if !strings.Contains(out, "内核：升级后需要重启系统才会生效") {
		t.Error("kernel entries must say a reboot is needed")
	}
	// P2 is one line per package, capped.
	if !strings.Contains(out, "…… 另有 5 个，使用 secwatch scan --all 查看") {
		t.Errorf("P2 list must be capped at %d:\n%s", compactP2, out)
	}
	for _, noisy := range []string{"验证：", "dpkg-query", "--only-upgrade", "参考："} {
		if strings.Contains(out, noisy) {
			t.Errorf("default view must not contain per-package %q lines", noisy)
		}
	}
	// The last section is the next steps, with one system-wide command.
	last := out[strings.LastIndex(out, "== "):]
	if !strings.HasPrefix(last, "== 下一步 ==") {
		t.Fatalf("report must end with the next steps, ends with:\n%s", last)
	}
	for _, want := range []string{
		"sudo apt-get update && sudo apt-get upgrade --with-new-pkgs",
		"重启服务器，让新内核和所有服务生效：sudo reboot",
		"再次运行 secwatch scan",
		"secwatch scan --all",
	} {
		if !strings.Contains(last, want) {
			t.Errorf("next steps missing %q:\n%s", want, last)
		}
	}
	if lines := strings.Count(out, "\n"); lines > 80 {
		t.Errorf("default report too long: %d lines", lines)
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
	if !strings.Contains(out, "✓ 没有需要升级的软件包") || strings.Contains(out, "== 下一步 ==") {
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
	steps := out[strings.LastIndex(out, "== 下一步 =="):]
	if !strings.Contains(steps, "至少重启对外服务：sshd、caddy，") || strings.Contains(steps, "evil") {
		t.Errorf("service names in suggested actions must pass the whitelist:\n%s", steps)
	}
}
