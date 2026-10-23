package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/testutil"
	"github.com/ly2u/sec/scanner/internal/testutil/fixture"
	"github.com/ly2u/sec/scanner/internal/version"
)

func put(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixed(cve, v string, cvss float64, kev bool) bundle.Entry {
	sev := "HIGH"
	if cvss >= 9 {
		sev = "CRITICAL"
	}
	return bundle.Entry{
		ID: cve, CVEIDs: []string{cve}, Status: "fixed", CVSS: &cvss, Severity: &sev, KEV: kev,
		Ranges: []bundle.Range{{Type: "ECOSYSTEM", Events: []version.Event{{Introduced: "0"}, {Fixed: v}}}},
		Ref:    "https://security-tracker.debian.org/tracker/" + cve,
	}
}

// A fake Debian 12 host: one patched backport (openssh), one vulnerable
// official package (curl), one nginx.org package (must not be judged), and a
// crafted package name that must never reach a command line.
func debianHost(t *testing.T) (root, bundlePath, pub string) {
	root = t.TempDir()
	put(t, root, "etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n")
	put(t, root, "var/lib/dpkg/status", `Package: openssh-server
Status: install ok installed
Source: openssh
Version: 1:9.2p1-2+deb12u3

Package: curl
Status: install ok installed
Version: 7.88.1-10+deb12u5

Package: libcurl4
Status: install ok installed
Source: curl
Version: 7.88.1-10+deb12u5

Package: nginx
Status: install ok installed
Version: 1.26.1-1~bookworm
`)
	lists := "var/lib/apt/lists/"
	put(t, root, lists+"deb.debian.org_debian_dists_bookworm_InRelease", "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Debian\nLabel: Debian\n")
	put(t, root, lists+"deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages",
		"Package: openssh-server\nVersion: 1:9.2p1-2+deb12u3\n\nPackage: curl\nVersion: 7.88.1-10+deb12u12\n\nPackage: libcurl4\nVersion: 7.88.1-10+deb12u12\n\nPackage: nginx\nVersion: 1.22.1-9+deb12u2\n")
	put(t, root, lists+"nginx.org_packages_debian_dists_bookworm_InRelease", "Origin: nginx\n")
	put(t, root, lists+"nginx.org_packages_debian_dists_bookworm_nginx_binary-amd64_Packages", "Package: nginx\nVersion: 1.26.2-1~bookworm\n")

	out := t.TempDir()
	path, err := fixture.WriteBundle("debian", "12", "source", map[string][]bundle.Entry{
		"openssh": {fixed("CVE-2024-6387", "1:9.2p1-2+deb12u3", 8.1, false)},
		"curl":    {fixed("CVE-2025-1111", "7.88.1-10+deb12u12", 9.8, true)},
		"nginx":   {fixed("CVE-2025-2222", "1.22.1-9+deb12u3", 7.5, false)},
	}, out)
	if err != nil {
		t.Fatal(err)
	}
	return root, path, filepath.Join(out, "key.pub")
}

func TestScanEndToEndText(t *testing.T) {
	root, path, pub := debianHost(t)
	var stdout, stderr bytes.Buffer
	code := scan([]string{"--root", root, "--offline", "--bundle", path, "--pubkey", pub, "--no-cache"}, &stdout, &stderr)
	out := stdout.String()
	if code != exitImportant {
		t.Fatalf("KEV finding must give exit code 3, got %d\nstderr: %s\n%s", code, stderr.String(), out)
	}
	for _, want := range []string{
		"[P0 立即处理] curl  7.88.1-10+deb12u5 → 7.88.1-10+deb12u12",
		"已被在野利用（CISA KEV）",
		"sudo apt-get update && sudo apt-get install --only-upgrade curl libcurl4",
		"未覆盖：来自第三方源的软件包",
		"nginx 1.26.1-1~bookworm",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n----\n%s", want, out)
		}
	}
	if strings.Contains(out, "CVE-2024-6387") || strings.Contains(out, "CVE-2025-2222") {
		t.Errorf("patched backport and third-party nginx must not be reported\n%s", out)
	}
	t.Log("\n" + out)
}

func TestScanEndToEndJSON(t *testing.T) {
	root, path, pub := debianHost(t)
	var stdout, stderr bytes.Buffer
	scan([]string{"--root", root, "--offline", "--bundle", path, "--pubkey", pub, "--no-cache", "--format", "json"}, &stdout, &stderr)
	var rep struct {
		Schema   int `json:"schema"`
		Findings []struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Priority string `json:"priority"`
		} `json:"findings"`
		Summary struct {
			AlreadyFixed int `json:"already_fixed"`
			ThirdParty   int `json:"third_party_packages"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
	if rep.Schema != 1 || len(rep.Findings) != 1 || rep.Findings[0].ID != "CVE-2025-1111" ||
		rep.Findings[0].Status != "CONFIRMED_AFFECTED" || rep.Findings[0].Priority != "P0" {
		t.Fatalf("unexpected findings: %+v", rep)
	}
	if rep.Summary.AlreadyFixed != 1 || rep.Summary.ThirdParty != 1 {
		t.Fatalf("summary: %+v", rep.Summary)
	}
}

func TestScanRejectsTamperedBundle(t *testing.T) {
	root, path, pub := debianHost(t)
	data, _ := os.ReadFile(path)
	data[len(data)-5] ^= 0xff
	os.WriteFile(path, data, 0o644)
	var stdout, stderr bytes.Buffer
	code := scan([]string{"--root", root, "--offline", "--bundle", path, "--pubkey", pub, "--no-cache"}, &stdout, &stderr)
	if code != exitError || !strings.Contains(stderr.String(), "signature") {
		t.Fatalf("tampered bundle must abort the scan: code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("no report may be produced from unverified data")
	}
}

func TestScanRejectsOfficialKeyMismatch(t *testing.T) {
	// Without --pubkey only the embedded production key is trusted; a test
	// bundle signed with another key must be refused.
	root, path, _ := debianHost(t)
	var stdout, stderr bytes.Buffer
	if code := scan([]string{"--root", root, "--offline", "--bundle", path, "--no-cache"}, &stdout, &stderr); code != exitError {
		t.Fatalf("bundle signed by an untrusted key must be refused, got %d", code)
	}
}

func TestMaliciousPackageNameNeverReachesCommand(t *testing.T) {
	root, _, _ := debianHost(t)
	evil := "evil;rm -rf /"
	put(t, root, "var/lib/dpkg/status", "Package: "+evil+"\nStatus: install ok installed\nSource: curl\nVersion: 7.88.1-10+deb12u5\n\nPackage: term\x1b[2Jx\nStatus: install ok installed\nVersion: 1.0\n")
	// List the crafted name in the official index so it reaches the command builder.
	put(t, root, "var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages",
		"Package: "+evil+"\nVersion: 7.88.1-10+deb12u12\n")
	out := t.TempDir()
	path, _ := fixture.WriteBundle("debian", "12", "source", map[string][]bundle.Entry{
		"curl": {fixed("CVE-2025-1111", "7.88.1-10+deb12u12", 9.8, true)},
	}, out)
	var stdout, stderr bytes.Buffer
	scan([]string{"--root", root, "--offline", "--bundle", path, "--pubkey", filepath.Join(out, "key.pub"), "--no-cache"}, &stdout, &stderr)
	text := stdout.String()
	for _, line := range strings.Split(text, "\n") {
		if (strings.Contains(line, "apt-get") || strings.Contains(line, "dpkg-query")) && strings.Contains(line, "rm -rf") {
			t.Fatalf("unsafe name reached a command: %s", line)
		}
	}
	if !strings.Contains(text, "异常字符") {
		t.Fatalf("the rejected name must be pointed out to the user\n%s", text)
	}
	if strings.Contains(text, "\x1b") {
		t.Fatal("terminal escape sequences must be neutralised in the text report")
	}
	if !strings.Contains(text, "离线数据包") {
		t.Fatal("offline mode must be labelled as such")
	}
}

// Modelled on the first real Debian 13 scan: nothing to upgrade, but many
// unfixed issues. The report must say "nothing to upgrade", must not label
// anything "fix urgently", and must exit 0.
func TestUpToDateHostWithOnlyUnfixedIssues(t *testing.T) {
	root, _, _ := debianHost(t)
	put(t, root, "var/lib/dpkg/status", "Package: openssh-server\nStatus: install ok installed\nSource: openssh\nVersion: 1:9.2p1-2+deb12u3\n")
	unfixed := func(cve string, cvss, epss float64, urgency string) bundle.Entry {
		e := fixed(cve, "", cvss, false)
		e.Ranges = []bundle.Range{{Type: "ECOSYSTEM", Events: []version.Event{{Introduced: "0"}}}}
		e.Status, e.EPSS, e.Urgency = "unfixed", &epss, &urgency
		return e
	}
	out := t.TempDir()
	path, _ := fixture.WriteBundle("debian", "12", "source", map[string][]bundle.Entry{"openssh": {
		unfixed("CVE-2020-15778", 7.8, 0.25, "unimportant"),
		unfixed("CVE-2026-0020", 7.5, 0.30, "medium"),
		unfixed("CVE-2026-0021", 5.0, 0.001, "low"),
		fixed("CVE-2024-6387", "1:9.2p1-2+deb12u3", 8.1, false),
	}}, out)
	var stdout, stderr bytes.Buffer
	code := scan([]string{"--root", root, "--offline", "--bundle", path, "--pubkey", filepath.Join(out, "key.pub"), "--no-cache"}, &stdout, &stderr)
	text := stdout.String()
	if code != exitOK {
		t.Fatalf("nothing actionable and nothing in KEV: exit code must be 0, got %d\n%s", code, text)
	}
	for _, want := range []string{"没有需要升级的软件包", "发行版暂无修复 2 项", "值得关注 1 项", "1 项被发行版评为可忽略", "CVE-2026-0020"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"CVE-2020-15778", "尽快处理", "立即处理"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("must not contain %q\n%s", unwanted, text)
		}
	}
	t.Log("\n" + text)
}

func TestAllShowsHiddenMinorIssues(t *testing.T) {
	root, _, _ := debianHost(t)
	put(t, root, "var/lib/dpkg/status", "Package: openssh-server\nStatus: install ok installed\nSource: openssh\nVersion: 1:9.2p1-2+deb12u3\n")
	e := fixed("CVE-2020-15778", "", 7.8, false)
	e.Ranges = []bundle.Range{{Type: "ECOSYSTEM", Events: []version.Event{{Introduced: "0"}}}}
	u := "unimportant"
	e.Status, e.Urgency = "unfixed", &u
	out := t.TempDir()
	path, _ := fixture.WriteBundle("debian", "12", "source", map[string][]bundle.Entry{"openssh": {e}}, out)
	args := []string{"--root", root, "--offline", "--bundle", path, "--pubkey", filepath.Join(out, "key.pub"), "--no-cache"}
	var a, b, errb bytes.Buffer
	scan(args, &a, &errb)
	scan(append(args, "--all"), &b, &errb)
	if strings.Contains(a.String(), "CVE-2020-15778") {
		t.Fatal("hidden by default")
	}
	if !strings.Contains(b.String(), "评为可忽略") || !strings.Contains(b.String(), "CVE-2020-15778") {
		t.Fatalf("--all must reveal it for auditing\n%s", b.String())
	}
}

// L2 end to end on a mounted root (nothing is executed there): an nvm Node
// hit by Node2Shell and Docker CE from Docker's own repository.
func TestL2EndToEnd(t *testing.T) {
	root, _, _ := debianHost(t)
	put(t, root, "root/.nvm/versions/node/v24.22.0/bin/node", "ELF")
	put(t, root, "var/lib/dpkg/status", "Package: docker-ce\nStatus: install ok installed\nVersion: 5:29.8.2-1~debian.12~bookworm\n")
	lists := "var/lib/apt/lists/"
	put(t, root, lists+"download.docker.com_linux_debian_dists_bookworm_InRelease", "Origin: Docker\nLabel: Docker CE\n")
	put(t, root, lists+"download.docker.com_linux_debian_dists_bookworm_stable_binary-amd64_Packages", "Package: docker-ce\nVersion: 5:29.8.2-1~debian.12~bookworm\n")

	s, _ := testutil.NewSigner()
	out := t.TempDir()
	distro, _ := fixture.WriteBundleSigned(s, "debian", "12", "source", map[string][]bundle.Entry{}, out)
	upEntry := func(cve string, fixes ...[2]string) bundle.Entry {
		cvss := 9.2
		e := bundle.Entry{ID: cve, CVEIDs: []string{cve}, CVSS: &cvss, Ref: "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"}
		for _, f := range fixes {
			e.Ranges = append(e.Ranges, bundle.Range{Type: "UPSTREAM", Events: []version.Event{{Introduced: f[0]}, {Fixed: f[1]}}})
		}
		return e
	}
	upstream, _ := fixture.WriteBundleSigned(s, "upstream", "1", "product", map[string][]bundle.Entry{
		"node":   {upEntry("CVE-2026-111497", [2]string{"22.0.0", "22.23.4"}, [2]string{"24.0.0", "24.22.1"})},
		"docker": {upEntry("CVE-2026-0102", [2]string{"29.0.0", "29.9.0"})},
	}, out)
	pub := filepath.Join(out, "key.pub")
	os.WriteFile(pub, s.PublicKeyFile(), 0o644)

	var stdout, stderr bytes.Buffer
	code := scan([]string{"--root", root, "--offline", "--bundle", distro, "--upstream-bundle", upstream,
		"--pubkey", pub, "--no-cache"}, &stdout, &stderr)
	text := stdout.String()
	if code == exitError {
		t.Fatalf("scan failed: %s", stderr.String())
	}
	for _, want := range []string{
		"Node.js  24.22.0 → 24.22.1",
		"位置：/root/.nvm/versions/node/v24.22.0/bin/node（nvm）",
		"nvm install 24.22.1",
		"Docker Engine  29.8.2 → 29.9.0",
		"sudo apt-get update && sudo apt-get install --only-upgrade docker-ce（从原第三方软件源升级）",
		"== 非包管理安装的软件 ==",
		"第三方软件包（未覆盖）0 个",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "未覆盖：来自第三方源的软件包") {
		t.Errorf("docker-ce was evaluated by L2 and must not be listed as uncovered\n%s", text)
	}
	t.Log("\n" + text)
}
