package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ly2u/sec/scanner/internal/bundle"
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
