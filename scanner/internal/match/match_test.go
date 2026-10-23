package match

import (
	"testing"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/system"
	"github.com/ly2u/sec/scanner/internal/version"
)

func entry(cve, fixed string, pro bool) bundle.Entry {
	events := []version.Event{{Introduced: "0"}}
	status := "unfixed"
	if fixed != "" {
		events = append(events, version.Event{Fixed: fixed})
		status = "fixed"
	}
	return bundle.Entry{
		ID: cve, CVEIDs: []string{cve}, Status: status, RequiresSubscription: pro,
		Ranges: []bundle.Range{{Type: "ECOSYSTEM", Events: events}},
		Ref:    "https://security-tracker.debian.org/tracker/" + cve,
	}
}

func pkg(name, ver, src, srcVer string, o system.Origin) system.Package {
	if src == "" {
		src, srcVer = name, ver
	}
	return system.Package{Name: name, Version: ver, Source: src, SourceVersion: srcVer, Origin: o}
}

var debian12 = system.OS{ID: "debian", Distro: "debian", Release: "12", Kind: version.Deb, Supported: true}

func run(os system.OS, pkgs []system.Package, b map[string][]bundle.Entry, running string, pro bool) Result {
	return Evaluate(Input{
		OS:            os,
		Inventory:     &system.Inventory{Packages: pkgs, UbuntuPro: pro},
		Bundle:        &bundle.Bundle{PackageKey: "source", SourcePackages: b},
		RunningKernel: running,
	})
}

func only(t *testing.T, r Result) Finding {
	t.Helper()
	if len(r.Findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d: %+v", len(r.Findings), r.Findings)
	}
	return r.Findings[0]
}

// regreSSHion: DSA-5724-1 fixed CVE-2024-6387 in 1:9.2p1-2+deb12u3; upstream
// fixed it in 9.8p1. The patched Debian package must not be reported.
func TestBackportIsFixed(t *testing.T) {
	b := map[string][]bundle.Entry{"openssh": {entry("CVE-2024-6387", "1:9.2p1-2+deb12u3", false)}}
	r := run(debian12, []system.Package{
		pkg("openssh-server", "1:9.2p1-2+deb12u3", "openssh", "1:9.2p1-2+deb12u3", system.Official),
	}, b, "", false)
	if len(r.Findings) != 0 || r.FixedCount != 1 {
		t.Fatalf("patched backport must count as fixed: %+v", r)
	}
	r = run(debian12, []system.Package{
		pkg("openssh-server", "1:9.2p1-2+deb12u2", "openssh", "1:9.2p1-2+deb12u2", system.Official),
		pkg("openssh-client", "1:9.2p1-2+deb12u2", "openssh", "1:9.2p1-2+deb12u2", system.Official),
	}, b, "", false)
	f := only(t, r)
	if f.Status != ConfirmedAffected || f.Fix != FixUpgrade || f.FixedVersion != "1:9.2p1-2+deb12u3" {
		t.Fatalf("unpatched openssh: %+v", f)
	}
	if len(f.Binaries) != 2 {
		t.Fatalf("both binaries from the source must be listed: %v", f.Binaries)
	}
}

func TestThirdPartyIsNotJudgedByDistroData(t *testing.T) {
	b := map[string][]bundle.Entry{"nginx": {entry("CVE-2025-0001", "1.22.1-9+deb12u3", false)}}
	r := run(debian12, []system.Package{pkg("nginx", "1.26.1-1~bookworm", "", "", system.ThirdParty)}, b, "", false)
	if len(r.Findings) != 0 || len(r.ThirdParty) != 1 {
		t.Fatalf("nginx.org package must be listed as uncovered, not matched: %+v", r)
	}
}

func TestUnverifiedOriginIsOnlyPotential(t *testing.T) {
	b := map[string][]bundle.Entry{"curl": {entry("CVE-2025-0002", "7.88.1-10+deb12u9", false)}}
	r := run(debian12, []system.Package{pkg("curl", "7.88.1-10+deb12u5", "", "", system.Unverified)}, b, "", false)
	if f := only(t, r); f.Status != PotentiallyAffected {
		t.Fatalf("without apt lists the verdict must be POTENTIALLY_AFFECTED: %+v", f)
	}
}

func TestUnfixedIsAffectedWithoutUpgrade(t *testing.T) {
	b := map[string][]bundle.Entry{"glibc": {entry("CVE-2025-0003", "", false)}}
	r := run(debian12, []system.Package{pkg("libc6", "2.36-9+deb12u10", "glibc", "2.36-9+deb12u10", system.Official)}, b, "", false)
	f := only(t, r)
	if f.Fix != FixNone || f.DistroStatus != "unfixed" || f.FixedVersion != "" {
		t.Fatalf("no fix exists, so no upgrade may be suggested: %+v", f)
	}
}

func TestKernelOnlyRunningCountsAndRebootIsDetected(t *testing.T) {
	b := map[string][]bundle.Entry{"linux": {entry("CVE-2025-0004", "6.1.110-1", false)}}
	pkgs := []system.Package{
		// old, not running
		pkg("linux-image-6.1.0-21-amd64", "6.1.90-1", "linux-signed-amd64", "6.1.90+1", system.Official),
		// running, vulnerable
		pkg("linux-image-6.1.0-25-amd64", "6.1.106-3", "linux-signed-amd64", "6.1.106+3", system.Official),
		// newer, installed, fixed
		pkg("linux-image-6.1.0-26-amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", system.Official),
		// userspace headers built from "linux": must not carry kernel CVEs
		pkg("linux-libc-dev", "6.1.90-1", "linux", "6.1.90-1", system.Official),
	}
	r := run(debian12, pkgs, b, "6.1.0-25-amd64", false)
	f := only(t, r)
	if !f.Kernel || f.InstalledVersion != "6.1.106-3" || f.Fix != FixReboot {
		t.Fatalf("running kernel must be judged and a reboot suggested: %+v", f)
	}
	if !r.Kernel.Known || !r.Kernel.NewerInstalled {
		t.Fatalf("kernel state: %+v", r.Kernel)
	}
	// Running the newest kernel: nothing to report.
	r = run(debian12, pkgs, b, "6.1.0-26-amd64", false)
	if len(r.Findings) != 0 {
		t.Fatalf("patched running kernel must not be reported: %+v", r.Findings)
	}
}

var ubuntu2004 = system.OS{ID: "ubuntu", Distro: "ubuntu", Release: "20.04", Kind: version.Deb, Supported: true}

func TestUbuntuProMerge(t *testing.T) {
	b := map[string][]bundle.Entry{"ghostscript": {
		entry("CVE-2025-0005", "", false),                          // standard: no fix
		entry("CVE-2025-0005", "9.50~dfsg-5ubuntu4.15+esm3", true), // Pro: fixed
	}}
	installed := []system.Package{pkg("ghostscript", "9.50~dfsg-5ubuntu4.14", "", "", system.Official)}

	f := only(t, run(ubuntu2004, installed, b, "", false))
	if f.Fix != FixSubscription || f.FixedVersion != "9.50~dfsg-5ubuntu4.15+esm3" {
		t.Fatalf("without Pro, the fix must be flagged as subscription-only: %+v", f)
	}
	f = only(t, run(ubuntu2004, installed, b, "", true))
	if f.Fix != FixUpgrade {
		t.Fatalf("with Pro attached, the ESM fix is a normal upgrade: %+v", f)
	}
	esm := []system.Package{pkg("ghostscript", "9.50~dfsg-5ubuntu4.15+esm3", "", "", system.Official)}
	if r := run(ubuntu2004, esm, b, "", false); len(r.Findings) != 0 {
		t.Fatalf("installed ESM version is fixed even though the standard channel says unfixed: %+v", r.Findings)
	}
}

func TestSeveralAdvisoriesForOneCVEUseHighestFix(t *testing.T) {
	a := entry("CVE-2025-0006", "1.0-2", false)
	b2 := entry("CVE-2025-0006", "1.0-4", false) // regression fix
	b2.ID = "DSA-9999-2"
	b := map[string][]bundle.Entry{"foo": {a, b2}}
	f := only(t, run(debian12, []system.Package{pkg("foo", "1.0-1", "", "", system.Official)}, b, "", false))
	if f.FixedVersion != "1.0-4" {
		t.Fatalf("upgrade target must cover every advisory: %+v", f)
	}
	f = only(t, run(debian12, []system.Package{pkg("foo", "1.0-3", "", "", system.Official)}, b, "", false))
	if f.FixedVersion != "1.0-4" {
		t.Fatalf("still affected by the regression advisory: %+v", f)
	}
}

func TestRPMKernelRunningRelease(t *testing.T) {
	rocky := system.OS{ID: "rocky", Distro: "rocky", Release: "9", Kind: version.RPM, Supported: true}
	b := map[string][]bundle.Entry{"kernel": {entry("CVE-2025-0007", "0:5.14.0-503.11.1.el9_5", false)}}
	k := func(name, vr string) system.Package {
		p := pkg(name, "0:"+vr, "kernel", "0:"+vr, system.Official)
		p.Arch = "x86_64"
		return p
	}
	pkgs := []system.Package{
		k("kernel-core", "5.14.0-427.13.1.el9_4"),
		k("kernel-core", "5.14.0-503.11.1.el9_5"),
		k("kernel-headers", "5.14.0-503.11.1.el9_5"),
	}
	f := only(t, run(rocky, pkgs, b, "5.14.0-427.13.1.el9_4.x86_64", false))
	if f.Fix != FixReboot || f.InstalledVersion != "0:5.14.0-427.13.1.el9_4" {
		t.Fatalf("running RHEL-family kernel must be judged: %+v", f)
	}
}

func TestUnparsableVersionIsUnknown(t *testing.T) {
	b := map[string][]bundle.Entry{"foo": {entry("CVE-2025-0008", "1.0-2", false)}}
	f := only(t, run(debian12, []system.Package{pkg("foo", "?!garbage", "", "", system.Official)}, b, "", false))
	if f.Status != Unknown {
		t.Fatalf("garbage version must yield UNKNOWN, never FIXED: %+v", f)
	}
}
