package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/container"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/report"
	"github.com/ly2u/sec/scanner/internal/system"
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
		"✗ 高风险：1 个软件包有安全更新，1 个需要尽快处理，其中 1 个的漏洞已被在野利用",
		"  P0 立即  curl         1  已被在野利用 · 严重 9.8",
		"sudo apt-get update && sudo apt-get upgrade --with-new-pkgs",
		"未检查：nginx（第三方源，请关注其官方公告）",
		"secwatch scan --pkg curl",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n----\n%s", want, out)
		}
	}
	if strings.Contains(out, "CVE-2024-6387") || strings.Contains(out, "CVE-2025-2222") {
		t.Errorf("patched backport and third-party nginx must not be reported\n%s", out)
	}
	t.Log("\n" + out)

	// --all keeps one exact command per package.
	stdout.Reset()
	scan([]string{"--root", root, "--offline", "--bundle", path, "--pubkey", pub, "--no-cache", "--all"}, &stdout, &stderr)
	if all := stdout.String(); !strings.Contains(all, "sudo apt-get update && sudo apt-get install --only-upgrade curl libcurl4") ||
		!strings.Contains(all, "已被在野利用（CISA KEV）") {
		t.Errorf("--all must list per-package commands\n%s", all)
	}
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
		"  P2 计划  Docker Engine       1  严重 9.2 · 第三方源",
		"  P2 计划  Node.js             1  严重 9.2 · 需单独升级",
		"1. sudo apt-get update && sudo apt-get upgrade --with-new-pkgs",
		"2. secwatch scan --pkg Node.js",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "异常字符") {
		t.Errorf("an install path is not a package name\n%s", text)
	}
	detail := func(args ...string) string {
		var o, e bytes.Buffer
		scan(append([]string{"--root", root, "--offline", "--bundle", distro, "--upstream-bundle", upstream,
			"--pubkey", pub, "--no-cache"}, args...), &o, &e)
		return o.String()
	}
	for args, wants := range map[string][]string{
		"--pkg Node.js":   {"Node.js  24.22.0 → 24.22.1", "位置  /root/.nvm/versions/node/v24.22.0/bin/node（nvm）", "nvm install 24.22.1"},
		"--pkg docker-ce": {"Docker Engine  29.8.2 → 29.9.0", "sudo apt-get update && sudo apt-get install --only-upgrade docker-ce（从原第三方软件源升级）"},
		"--all":           {"== 非包管理安装的软件 ==", "单独升级不是通过软件包安装的软件"},
	} {
		out := detail(strings.SplitN(args, " ", 2)...)
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Errorf("%s missing %q\n%s", args, want, out)
			}
		}
	}
	if strings.Contains(text, "未覆盖：来自第三方源的软件包") {
		t.Errorf("docker-ce was evaluated by L2 and must not be listed as uncovered\n%s", text)
	}
	t.Log("\n" + text)
}

// Containers are scanned through their root filesystems. Here the roots are
// plain directories standing in for /proc/PID/root.
func TestContainerScan(t *testing.T) {
	web, path, pub := debianHost(t) // an image with apt lists and a vulnerable curl
	slim, _, _ := debianHost(t)     // the same image with its apt lists deleted
	os.RemoveAll(filepath.Join(slim, "var/lib/apt/lists"))
	distroless := t.TempDir()
	old := t.TempDir()
	put(t, old, "etc/os-release", "ID=alpine\nVERSION_ID=3.18.4\nPRETTY_NAME=\"Alpine Linux v3.18\"\n")

	keys, err := trustedKeys(pub)
	if err != nil {
		t.Fatal(err)
	}
	res, err := loadOffline(path, "", "debian", "12", keys)
	if err != nil {
		t.Fatal(err)
	}
	fetches := 0
	fetch := cachedFetch(func(d, r string) (*bundle.Result, error) {
		fetches++
		return res, nil
	})
	cs := scanContainers([]container.Target{
		{ID: "aaaaaaaaaaaa", Name: "web", Image: "nginx:1.27", Root: web},
		{ID: "bbbbbbbbbbbb", Name: "slim", Root: slim},
		{ID: "cccccccccccc", Name: "app", Root: distroless},
		{ID: "dddddddddddd", Root: old},
	}, fetch, false)
	if fetches != 1 {
		t.Errorf("one bundle per distro release, fetched %d times", fetches)
	}

	o := system.OS{PrettyName: "Debian GNU/Linux 13 (trixie)", Distro: "debian", Release: "13", Kind: version.Deb}
	host := report.Build("v0.1.3", o, &system.Inventory{}, match.Result{PackagesScanned: 300}, nil, report.DataInfo{KeyID: "X"}, nil, false, nil, nil)
	host.AddContainers(cs, true)
	var b bytes.Buffer
	host.WriteText(&b)
	out := b.String()
	t.Log("\n" + out)
	for _, want := range []string{
		"✓ 本机没有需要升级的软件包",
		"容器（4 个运行中，检查了容器内的系统软件包）",
		"  web           Debian 12    ✗ 1 个需要尽快处理（共 1 个软件包有更新）",
		"  app                        未检查：精简镜像（没有系统信息和软件包数据库）",
		"  dddddddddddd  Alpine 3.18  未检查：暂不支持该系统版本",
		"secwatch scan --container web",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "trivy") || strings.Contains(out, "sudo reboot") {
		t.Error("containers were scanned and the host has nothing to upgrade")
	}
	if !host.Exceeds("P1") {
		t.Error("an exploited vulnerability in a container must set exit code 3")
	}

	sub, ok := host.SelectContainer("web")
	if !ok {
		t.Fatal("select by name")
	}
	b.Reset()
	sub.WriteText(&b)
	one := b.String()
	t.Log("\n" + one)
	for _, want := range []string{
		"容器 web（镜像 nginx:1.27）",
		"  P0 立即  curl         1  已被在野利用 · 严重 9.8",
		"docker pull nginx:1.27",
		"secwatch scan --container web --pkg curl",
	} {
		if !strings.Contains(one, want) {
			t.Errorf("container view missing %q", want)
		}
	}
	if strings.Contains(one, "apt-get") {
		t.Error("packages inside a container are fixed by a newer image, not apt-get")
	}

	host.FilterPackage("libcurl4")
	host.AddContainers(cs, true)
	pkgView, _ := host.SelectContainer("web")
	b.Reset()
	pkgView.WriteText(&b)
	if s := b.String(); strings.Contains(s, "apt-get") || !strings.Contains(s, "更新镜像后重建容器") || !strings.Contains(s, "CVE-2025-1111") {
		t.Errorf("--container web --pkg libcurl4:\n%s", s)
	}
	host.FilterPackage("")

	slimRep, _ := host.SelectContainer("bbbbbbbbbbbb")
	b.Reset()
	slimRep.WriteText(&b)
	if s := b.String(); !strings.Contains(s, "镜像里没有软件源索引") || strings.Contains(s, "apt-get update 后重新扫描") {
		t.Errorf("image without apt lists:\n%s", s)
	}

	var j bytes.Buffer
	host.WriteJSON(&j)
	var parsed struct {
		Containers []struct {
			Name   string
			Status string
			Report *struct{ Findings []json.RawMessage }
		}
	}
	json.Unmarshal(j.Bytes(), &parsed)
	if len(parsed.Containers) != 4 || parsed.Containers[0].Status != "scanned" || len(parsed.Containers[0].Report.Findings) != 1 {
		t.Errorf("json containers: %+v", parsed.Containers)
	}
}

// Go programs on a mounted root: one installed by hand, one from a
// third-party repository (which must stop being listed as "not checked").
func TestGoProgramsEndToEnd(t *testing.T) {
	root, _, _ := debianHost(t)
	exe, _ := os.Executable() // a real Go binary
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"usr/local/bin/frpc", "usr/bin/caddy"} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		if err := os.WriteFile(filepath.Join(root, p), data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	status, _ := os.ReadFile(filepath.Join(root, "var/lib/dpkg/status"))
	put(t, root, "var/lib/dpkg/status", string(status)+"\nPackage: caddy\nStatus: install ok installed\nVersion: 2.10.2\n")
	put(t, root, "var/lib/dpkg/info/caddy.list", "/usr\n/usr/bin\n/usr/bin/caddy\n")
	put(t, root, "var/lib/apt/lists/dl.cloudsmith.io_public_caddy_stable_deb_debian_dists_any-version_main_binary-amd64_Packages", "Package: caddy\nVersion: 2.10.2\n")

	s, _ := testutil.NewSigner()
	out := t.TempDir()
	distro, _ := fixture.WriteBundleSigned(s, "debian", "12", "source", map[string][]bundle.Entry{}, out)
	cvss := 7.5
	goBundle, _ := fixture.WriteBundleSigned(s, "golang", "1", "module", map[string][]bundle.Entry{
		"stdlib": {{ID: "CVE-2099-1234", CVEIDs: []string{"CVE-2099-1234"}, CVSS: &cvss, Ref: "https://pkg.go.dev/vuln/GO-2099-0001",
			Ranges: []bundle.Range{{Type: "SEMVER", Events: []version.Event{{Introduced: "0"}, {Fixed: "99.0.0"}}}}}},
	}, out)
	pub := filepath.Join(out, "key.pub")
	os.WriteFile(pub, s.PublicKeyFile(), 0o644)
	args := []string{"--root", root, "--offline", "--bundle", distro, "--go-bundle", goBundle, "--pubkey", pub, "--no-cache"}

	var stdout, stderr bytes.Buffer
	if code := scan(args, &stdout, &stderr); code == exitError {
		t.Fatalf("scan failed: %s", stderr.String())
	}
	text := stdout.String()
	t.Log("\n" + text)
	for _, want := range []string{
		"  P2 计划  caddy        1  高危 7.5 · Go 程序内置组件 · 第三方源",
		"  P2 计划  frpc         1  高危 7.5 · Go 程序内置组件 · 需单独升级",
		"secwatch scan --pkg frpc",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(text, "caddy（第三方源") {
		t.Error("caddy was checked as a Go program and must not be listed as not checked")
	}

	stdout.Reset()
	scan(append(args, "--pkg", "frpc"), &stdout, &stderr)
	one := stdout.String()
	t.Log("\n" + one)
	for _, want := range []string{
		"位置  /usr/local/bin/frpc（Go 程序）",
		"问题出在这些组件（共 1 个漏洞）",
		"用 Go 99.0.0 或更高版本编译",
		"1. 打开项目发布页 https://github.com/ly2u/sec/releases，找到最新版本里文件名带 linux 和",
		"curl -fL -o /tmp/frpc.new '<下载链接>'",
		"sudo install -m 755 /tmp/frpc.new /usr/local/bin/frpc",
		"可能受影响",
	} {
		if !strings.Contains(one, want) {
			t.Errorf("--pkg frpc missing %q", want)
		}
	}
	if strings.Contains(one, "CVE-2099-1234") {
		t.Error("CVE numbers are behind --all; the default shows components and steps")
	}
	stdout.Reset()
	scan(append(args, "--pkg", "frpc", "--all"), &stdout, &stderr)
	if !strings.Contains(stdout.String(), "CVE-2099-1234") || !strings.Contains(stdout.String(), "来自 Go ") {
		t.Errorf("--pkg frpc --all lists every vulnerability\n%s", stdout.String())
	}

	stdout.Reset()
	noGo := []string{"--root", root, "--offline", "--bundle", distro, "--pubkey", pub, "--no-cache"}
	scan(noGo, &stdout, &stderr)
	if !strings.Contains(stdout.String(), "离线模式未提供 --go-bundle") {
		t.Errorf("without Go data the programs are only listed, and the report says why\n%s", stdout.String())
	}
}

func TestNewerRelease(t *testing.T) {
	for _, c := range []struct{ current, latest, want string }{
		{"v0.1.3", "v0.1.4", "v0.1.4"},
		{"v0.1.10", "v0.1.9", ""},
		{"v0.1.4", "v0.1.4", ""},
		{"dev", "v0.1.4", ""},
		{"v0.1.3", "", ""},
	} {
		if got := newerRelease(c.current, c.latest); got != c.want {
			t.Errorf("newerRelease(%s, %s) = %q", c.current, c.latest, got)
		}
	}
}
