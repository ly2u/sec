package l2

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ly2u/sec/scanner/internal/system"
)

func TestRulesLoadAndValidate(t *testing.T) {
	rules, err := LoadRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) < 12 {
		t.Fatalf("expected the 12 initial products, got %d", len(rules))
	}
	for _, r := range rules {
		for _, m := range []string{"baota", "source", "binary", "process"} {
			if !strings.Contains(r.UpgradeText(m, "1.2.3"), "1.2.3") && m != "process" {
				t.Errorf("%s: upgrade text for %s lacks the fixed version", r.Slug, m)
			}
		}
	}
}

// The scanner embeds a copy of rules/products; both must be identical so the
// server and the scanner agree on product identities.
func TestEmbeddedRulesMatchRepository(t *testing.T) {
	repo := filepath.Join("..", "..", "..", "rules", "products")
	files, err := filepath.Glob(filepath.Join(repo, "*.json"))
	if err != nil || len(files) == 0 {
		t.Skip("repository rules not available")
	}
	entries, _ := embedded.ReadDir("rules")
	if len(entries) != len(files) {
		t.Fatalf("embedded %d rules, repository has %d", len(entries), len(files))
	}
	for _, f := range files {
		want, _ := os.ReadFile(f)
		got, err := embedded.ReadFile("rules/" + filepath.Base(f))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s differs; run: cp rules/products/*.json scanner/internal/l2/rules/", filepath.Base(f))
		}
	}
}

func TestRuleValidationRejectsDangerousRules(t *testing.T) {
	bad := []Rule{
		{Slug: "x", Name: "x", Detect: Detect{VersionRegex: "(1)", VersionArgs: []string{"-c", "rm -rf /"}}},
		{Slug: "x", Name: "x", Detect: Detect{VersionRegex: "(1)", VersionArgs: []string{"; reboot"}}},
		{Slug: "x", Name: "x", Detect: Detect{VersionRegex: "(1)", Binaries: []Binary{{Glob: "relative/nginx", Method: "source"}}}},
		{Slug: "x", Name: "x", Detect: Detect{VersionRegex: "(1)", Binaries: []Binary{{Glob: "/opt/../etc/x", Method: "source"}}}},
		{Slug: "x", Name: "x", Detect: Detect{VersionRegex: "no-group"}},
	}
	for i, r := range bad {
		if err := r.compile(); err == nil {
			t.Errorf("rule %d must be rejected", i)
		}
	}
}

func TestSafeToExec(t *testing.T) {
	if err := SafeToExec("/bin/sh"); err != nil {
		t.Fatalf("a root-owned system binary must be allowed: %v", err)
	}
	// Anything under /tmp is never safe: the directory is world-writable.
	f := filepath.Join(t.TempDir(), "nginx")
	os.WriteFile(f, []byte("#!/bin/sh\necho hi\n"), 0o755)
	if err := SafeToExec(f); err == nil {
		t.Fatal("a file in a temp directory must not be executed as root")
	}
	if err := SafeToExec("relative"); err == nil {
		t.Fatal("relative paths must be refused")
	}
}

func put(t *testing.T, root, rel, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverOnMountedRoot(t *testing.T) {
	rules, err := LoadRules()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	put(t, root, "www/server/nginx/sbin/nginx", "#!/bin/sh\n", 0o755)
	put(t, root, "root/.nvm/versions/node/v24.22.0/bin/node", "ELF", 0o755)
	put(t, root, "home/alice/.nvm/versions/node/v22.11.0/bin/node", "ELF", 0o755)
	put(t, root, "usr/local/bin/node", "ELF", 0o755) // owned by a package below
	inv := &system.Inventory{Packages: []system.Package{
		{Name: "docker-ce", Version: "5:29.8.2-1~debian.13~trixie", Source: "docker-ce", Origin: system.ThirdParty, OriginLabel: "Docker CE"},
		{Name: "docker-ce-cli", Version: "5:29.8.2-1~debian.13~trixie", Source: "docker-ce", Origin: system.ThirdParty},
		{Name: "nginx", Version: "1.26.1-1~bookworm", Source: "nginx", Origin: system.ThirdParty, OriginLabel: "nginx"},
		{Name: "php8.3-fpm", Version: "8.3.12-1+0~20240927.43+debian12~1.gbp1", Source: "php8.3", Origin: system.ThirdParty},
		{Name: "openssl", Version: "3.0.15-1~deb12u1", Source: "openssl", Origin: system.Official},
	}}
	owner := func(p string) string {
		if p == "/usr/local/bin/node" {
			return "nodejs"
		}
		return ""
	}
	res := Discover(Env{Host: system.Host{Root: root}, Inventory: inv, Owner: owner}, rules)

	got := map[string]Install{}
	for _, in := range res.Installs {
		got[in.Product+"|"+in.Path+"|"+strings.Join(in.Packages, ",")] = in
	}
	check := func(key, version, source string) {
		t.Helper()
		in, ok := got[key]
		if !ok {
			t.Fatalf("missing %s; have %v", key, keysOf(got))
		}
		if in.Version != version || in.VersionSource != source {
			t.Errorf("%s: version %q via %q, want %q via %q (note: %s)", key, in.Version, in.VersionSource, version, source, in.Note)
		}
	}
	check("docker||docker-ce,docker-ce-cli", "29.8.2", "package")
	check("nginx||nginx", "1.26.1", "package")
	check("php||php8.3-fpm", "8.3.12", "package")
	check("node|/root/.nvm/versions/node/v24.22.0/bin/node|", "24.22.0", "path")
	check("node|/home/alice/.nvm/versions/node/v22.11.0/bin/node|", "22.11.0", "path")
	// Not executed on a mounted root: no version, but the install is reported.
	if in := got["nginx|/www/server/nginx/sbin/nginx|"]; in.Method != "baota" || in.Version != "" || in.Note == "" {
		t.Errorf("BaoTa nginx must be listed with a reason for the missing version: %+v", in)
	}
	if _, ok := got["node|/usr/local/bin/node|"]; ok {
		t.Error("a package-owned binary belongs to L1, not L2")
	}
	if _, ok := got["openssl||openssl"]; ok {
		t.Error("official packages are never L2")
	}
}

func keysOf(m map[string]Install) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
