package l2

import (
	"strings"
	"testing"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/version"
)

func up(cve string, cvss float64, ranges ...[]version.Event) bundle.Entry {
	e := bundle.Entry{ID: cve, CVEIDs: []string{cve}, CVSS: &cvss, Ref: "https://www.cve.org/CVERecord?id=" + cve}
	for _, r := range ranges {
		e.Ranges = append(e.Ranges, bundle.Range{Type: "UPSTREAM", Events: r})
	}
	return e
}

func ev(intro, kind, value string) []version.Event {
	e := []version.Event{{Introduced: intro}}
	switch kind {
	case "fixed":
		e = append(e, version.Event{Fixed: value})
	case "limit":
		e = append(e, version.Event{Limit: value})
	}
	return e
}

// Upstream data shaped exactly like the live corpus on 2026-10-23.
var upstream = &bundle.Bundle{PackageKey: "product", SourcePackages: map[string][]bundle.Entry{
	// PHP2Shell (CVE-2026-109618): PHP Group branch ranges.
	"php": {up("CVE-2026-109618", 9.2,
		ev("8.2.0", "fixed", "8.2.35"), ev("8.3.0", "fixed", "8.3.36"), ev("8.4.0", "fixed", "8.4.27"))},
	// Node2Shell (CVE-2026-111497): from the Node.js security working group.
	"node": {up("CVE-2026-111497", 9.2,
		ev("22.0.0", "fixed", "22.23.4"), ev("24.0.0", "fixed", "24.22.1"), ev("26.0.0", "fixed", "26.12.1"))},
	// F5 nginx: two maintained branches plus an end-of-life range without a fix.
	"nginx": {up("CVE-2026-95101", 8.2,
		ev("1.31.0", "fixed", "1.31.7"), ev("1.30.0", "fixed", "1.30.6"), ev("1.25.0", "limit", "1.30.0"))},
	"openssl": {up("CVE-2026-0101", 7.5, ev("1.1.1", "fixed", "1.1.1x"), ev("3.0.0", "fixed", "3.0.18"))},
	"docker":  {up("CVE-2026-0102", 8.0, ev("29.0.0", "fixed", "29.9.0"))},
}}

func evalOne(t *testing.T, installs ...Install) Outcome {
	t.Helper()
	rules, err := LoadRules()
	if err != nil {
		t.Fatal(err)
	}
	return Evaluate(Result{Installs: installs}, upstream, rules, nil)
}

func TestNode2ShellOnNvm(t *testing.T) {
	o := evalOne(t, Install{Product: "node", ProductName: "Node.js", Version: "24.22.0", Method: "nvm",
		Path: "/root/.nvm/versions/node/v24.22.0/bin/node", VersionSource: "path"})
	if len(o.Findings) != 1 {
		t.Fatalf("Node 24.22.0 is affected by Node2Shell: %+v", o)
	}
	f := o.Findings[0]
	if f.FixedVersion != "24.22.1" || f.Status != match.ConfirmedAffected || f.Layer != "L2" {
		t.Fatalf("unexpected finding %+v", f)
	}
	if !strings.Contains(f.Guidance, "nvm install 24.22.1") {
		t.Fatalf("nvm users need nvm instructions, got %q", f.Guidance)
	}
	if o := evalOne(t, Install{Product: "node", Version: "24.22.1", Method: "nvm"}); len(o.Findings) != 0 || o.AlreadyFixed != 1 {
		t.Fatalf("24.22.1 is the fix: %+v", o)
	}
}

func TestPHP2ShellOnBaoTaMergesBinaries(t *testing.T) {
	o := evalOne(t,
		Install{Product: "php", ProductName: "PHP", Version: "8.3.10", Method: "baota", Path: "/www/server/php/83/bin/php"},
		Install{Product: "php", ProductName: "PHP", Version: "8.3.10", Method: "baota", Path: "/www/server/php/83/sbin/php-fpm"},
	)
	if len(o.Findings) != 1 {
		t.Fatalf("php and php-fpm of one build are one finding: %+v", o.Findings)
	}
	f := o.Findings[0]
	if f.FixedVersion != "8.3.36" || !strings.Contains(f.Guidance, "宝塔") || !strings.Contains(f.Path, "php-fpm") {
		t.Fatalf("unexpected %+v", f)
	}
}

func TestNginxEndOfLifeBranchPointsToNextFix(t *testing.T) {
	o := evalOne(t, Install{Product: "nginx", ProductName: "nginx", Version: "1.28.0", Method: "source", Path: "/usr/local/nginx/sbin/nginx"})
	if len(o.Findings) != 1 || o.Findings[0].FixedVersion != "1.30.6" {
		t.Fatalf("1.28 is end-of-life: upgrade target is the next branch's fix 1.30.6: %+v", o.Findings)
	}
	for _, v := range []string{"1.24.0", "1.30.6", "1.31.7"} {
		if o := evalOne(t, Install{Product: "nginx", Version: v, Method: "source"}); len(o.Findings) != 0 {
			t.Errorf("nginx %s is not affected: %+v", v, o.Findings)
		}
	}
}

func TestBundledOpenSSLGuidance(t *testing.T) {
	o := evalOne(t, Install{Product: "openssl", ProductName: "OpenSSL", Version: "1.1.1w", Method: "baota",
		Path: "/www/server/nginx/sbin/nginx", BundledIn: "nginx", VersionSource: "exec"})
	if len(o.Findings) != 1 {
		t.Fatalf("bundled OpenSSL 1.1.1w is affected: %+v", o)
	}
	g := o.Findings[0].Guidance
	if !strings.Contains(g, "编译进 nginx") || !strings.Contains(g, "宝塔") {
		t.Fatalf("users must learn that upgrading system OpenSSL does not help: %q", g)
	}
}

func TestThirdPartyPackageAndMissingData(t *testing.T) {
	o := evalOne(t,
		Install{Product: "docker", ProductName: "Docker Engine", Version: "29.8.2", Method: "package", Packages: []string{"docker-ce", "docker-ce-cli"}},
		Install{Product: "redis", ProductName: "Redis", Version: "7.0.0", Method: "source", Path: "/usr/local/bin/redis-server"},
	)
	if len(o.Findings) != 1 || o.Findings[0].Guidance != "" || len(o.Findings[0].Binaries) != 2 {
		t.Fatalf("package installs carry package names for a template command: %+v", o.Findings)
	}
	if len(o.NoData) != 1 || o.NoData[0] != "Redis" {
		t.Fatalf("products without data must be reported as unknown: %+v", o.NoData)
	}
}

func TestVersionlessInstallIsNotJudged(t *testing.T) {
	if o := evalOne(t, Install{Product: "nginx", Method: "baota", Path: "/www/server/nginx/sbin/nginx"}); len(o.Findings) != 0 {
		t.Fatalf("no version, no verdict: %+v", o)
	}
}
