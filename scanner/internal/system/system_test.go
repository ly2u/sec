package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ly2u/sec/scanner/internal/version"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectOS(t *testing.T) {
	cases := map[string][3]string{
		"ID=debian\nVERSION_ID=\"12\"\n":                 {"debian", "12", "deb"},
		"ID=ubuntu\nVERSION_ID=\"24.04\"\n":              {"ubuntu", "24.04", "deb"},
		"ID=\"rocky\"\nVERSION_ID=\"9.4\"\n":             {"rocky", "9", "rpm"},
		"ID=\"almalinux\"\nVERSION_ID=\"8.10\"\n":        {"alma", "8", "rpm"},
		"ID=alpine\nVERSION_ID=3.22.1\n":                 {"alpine", "3.22", "apk"},
		"ID=debian\nPRETTY_NAME=\"Debian trixie/sid\"\n": {"debian", "testing", "deb"},
	}
	for content, want := range cases {
		root := t.TempDir()
		write(t, root, "etc/os-release", content)
		o, err := DetectOS(Host{Root: root})
		if err != nil {
			t.Fatal(err)
		}
		if o.Distro != want[0] || o.Release != want[1] || string(o.Kind) != want[2] {
			t.Errorf("%q => %s %s %s, want %v", content, o.Distro, o.Release, o.Kind, want)
		}
	}
}

const dpkgStatus = `Package: openssh-server
Status: install ok installed
Architecture: amd64
Source: openssh
Version: 1:9.2p1-2+deb12u2
Description: secure shell server
 multi-line description that must be ignored

Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.15-1~deb12u1

Package: linux-image-6.1.0-25-amd64
Status: install ok installed
Architecture: amd64
Source: linux-signed-amd64 (6.1.106+3)
Version: 6.1.106-3

Package: removed-thing
Status: deinstall ok config-files
Version: 1.0-1

Package: nginx
Status: install ok installed
Architecture: amd64
Version: 1.26.1-1~bookworm

Package: mytool
Status: install ok installed
Version: 0.1
`

func TestParseDpkgStatus(t *testing.T) {
	pkgs, err := ParseDpkgStatus(strings.NewReader(dpkgStatus))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Package{}
	for _, p := range pkgs {
		got[p.Name] = p
	}
	if len(pkgs) != 5 {
		t.Fatalf("expected 5 installed packages (config-files excluded), got %d", len(pkgs))
	}
	if p := got["libssl3"]; p.Source != "openssl" || p.SourceVersion != "3.0.15-1~deb12u1" {
		t.Errorf("libssl3 source mapping wrong: %+v", p)
	}
	if p := got["linux-image-6.1.0-25-amd64"]; p.Source != "linux-signed-amd64" || p.SourceVersion != "6.1.106+3" {
		t.Errorf("source version in parentheses must be used: %+v", p)
	}
	if p := got["nginx"]; p.Source != "nginx" || p.SourceVersion != p.Version {
		t.Errorf("missing Source field means source == binary: %+v", p)
	}
}

func debianRoot(t *testing.T) string {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	write(t, root, "var/lib/dpkg/status", dpkgStatus)
	lists := "var/lib/apt/lists/"
	// A Chinese mirror: origin must come from the Release file, not the host name.
	write(t, root, lists+"mirrors.example.cn_debian_dists_bookworm_InRelease", "Origin: Debian\nLabel: Debian\nSuite: stable\n\nignored body\n")
	write(t, root, lists+"mirrors.example.cn_debian_dists_bookworm_main_binary-amd64_Packages",
		"Package: openssh-server\nVersion: 1:9.2p1-2+deb12u7\n\nPackage: libssl3\nVersion: 3.0.15-1~deb12u1\n\nPackage: nginx\nVersion: 1.22.1-9+deb12u2\n")
	write(t, root, lists+"nginx.org_packages_debian_dists_bookworm_InRelease", "Origin: nginx\nLabel: nginx\n")
	write(t, root, lists+"nginx.org_packages_debian_dists_bookworm_nginx_binary-amd64_Packages",
		"Package: nginx\nVersion: 1.26.2-1~bookworm\n")
	return root
}

func TestAptOriginClassification(t *testing.T) {
	root := debianRoot(t)
	h := Host{Root: root}
	o, _ := DetectOS(h)
	inv, err := ReadPackages(h, o)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Origin{}
	for _, p := range inv.Packages {
		got[p.Name] = p.Origin
	}
	want := map[string]Origin{
		"libssl3":        Official,   // exact match in the official list
		"openssh-server": Official,   // outdated official: name only in official lists
		"nginx":          ThirdParty, // newer than Debian's nginx: from nginx.org
		"mytool":         ThirdParty, // in no list at all
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s origin = %s, want %s", name, got[name], w)
		}
	}
	if len(inv.Notes) != 0 {
		t.Errorf("unexpected notes: %v", inv.Notes)
	}
}

func TestMissingAptListsAreUnverified(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	write(t, root, "var/lib/dpkg/status", dpkgStatus)
	h := Host{Root: root}
	o, _ := DetectOS(h)
	inv, err := ReadPackages(h, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range inv.Packages {
		if p.Origin != Unverified {
			t.Fatalf("%s should be unverified without apt lists, got %s", p.Name, p.Origin)
		}
	}
	if len(inv.Notes) == 0 {
		t.Fatal("missing apt lists must be explained to the user")
	}
}

func TestParseRPMQuery(t *testing.T) {
	out := "openssl-libs\t1\t3.2.2\t6.el9_5.1\tx86_64\topenssl-3.2.2-6.el9_5.1.src.rpm\tRocky Enterprise Software Foundation\n" +
		"nginx\t(none)\t1.26.2\t1.el9.ngx\tx86_64\tnginx-1.26.2-1.el9.ngx.src.rpm\tNginx, Inc.\n" +
		"gpg-pubkey\t(none)\t8483c65d\t5ccc5b19\t(none)\t(none)\t(none)\n"
	pkgs := ParseRPMQuery([]byte(out), "rocky")
	if len(pkgs) != 2 {
		t.Fatalf("gpg-pubkey must be skipped, got %d", len(pkgs))
	}
	if p := pkgs[0]; p.Source != "openssl" || p.Version != "1:3.2.2-6.el9_5.1" || p.Origin != Official {
		t.Errorf("openssl-libs parsed wrong: %+v", p)
	}
	if p := pkgs[1]; p.Version != "0:1.26.2-1.el9.ngx" || p.Origin != ThirdParty {
		t.Errorf("nginx.org rpm must be third-party with epoch 0: %+v", p)
	}
	if c, _ := version.Compare(version.RPM, pkgs[0].Version, "1:3.2.2-6.el9_5.1"); c != 0 {
		t.Error("installed EVR must compare equal to the OSV fixed EVR")
	}
}

func TestParseAPKInstalled(t *testing.T) {
	db := "C:Q1abc=\nP:libcrypto3\nV:3.3.2-r0\nA:x86_64\no:openssl\n\nP:busybox\nV:1.36.1-r29\n\n"
	pkgs := ParseAPKInstalled(strings.NewReader(db))
	if len(pkgs) != 2 || pkgs[0].Source != "openssl" || pkgs[1].Source != "busybox" {
		t.Fatalf("unexpected apk parse: %+v", pkgs)
	}
}

func TestSourceRPMName(t *testing.T) {
	for in, want := range map[string]string{
		"openssl-3.2.2-6.el9_5.1.src.rpm":        "openssl",
		"python3.11-3.11.9-7.el9_5.src.rpm":      "python3.11",
		"kernel-5.14.0-427.13.1.el9_4.src.rpm":   "kernel",
		"perl-IO-Socket-SSL-2.073-2.el9.src.rpm": "perl-IO-Socket-SSL",
	} {
		if got := sourceRPMName(in); got != want {
			t.Errorf("%s => %q, want %q", in, got, want)
		}
	}
}
