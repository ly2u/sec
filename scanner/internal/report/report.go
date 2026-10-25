// Package report prioritises findings (docs/ARCHITECTURE.md D4) and renders
// them. Remediation commands are produced here from fixed templates; package
// and unit names must pass a whitelist before they may appear in a command.
// Nothing from the data bundle is ever emitted as command text.
package report

import (
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ly2u/sec/scanner/internal/container"
	"github.com/ly2u/sec/scanner/internal/l2"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/procinfo"
	"github.com/ly2u/sec/scanner/internal/system"
	"github.com/ly2u/sec/scanner/internal/version"
)

// SchemaVersion of the JSON report.
const SchemaVersion = 1

// Thresholds (CVSS 3.x based, see D4).
const (
	CVSSCritical = 9.0
	CVSSHigh     = 7.0
	EPSSHigh     = 0.1
)

// Report is the complete scan outcome.
type Report struct {
	Schema     int               `json:"schema"`
	Scanner    string            `json:"scanner_version"`
	ScannedAt  time.Time         `json:"scanned_at"`
	OS         OSInfo            `json:"os"`
	Data       DataInfo          `json:"data"`
	Summary    Summary           `json:"summary"`
	Findings   []match.Finding   `json:"findings"`
	Kernel     match.KernelState `json:"kernel"`
	Runtime    *procinfo.Report  `json:"runtime"`
	ThirdParty []system.Package  `json:"third_party_packages"`
	// L2: software installed outside the distribution's package manager.
	L2          *l2.Result `json:"l2"`
	L2Evaluated bool       `json:"l2_evaluated"`
	L2NoData    []string   `json:"l2_products_without_data,omitempty"`
	// Containers: running containers scanned through /proc/PID/root.
	Containers        []ContainerResult `json:"containers"`
	containersScanned bool
	inContainer       *container.Target
	Notes             []string             `json:"notes"`
	Commands          map[string][]Command `json:"-"`
	kind              version.Kind
	distro            string
	showAll           bool
	only              string // --pkg: show one package in full
	stalePackages     map[string]bool
	// Hostname of the scanned machine, shown in the report header.
	Hostname string `json:"hostname,omitempty"`
	// Update: a newer scanner release ("v0.1.4"), set by the caller.
	Update string `json:"scanner_update,omitempty"`
	// Color enables ANSI styles in the text report (set for colour terminals).
	Color bool `json:"-"`
}

type OSInfo struct {
	Name    string `json:"name"`
	Distro  string `json:"distro"`
	Release string `json:"release"`
}

type DataInfo struct {
	File        string    `json:"file"`
	GeneratedAt time.Time `json:"generated_at"`
	KeyID       string    `json:"key_id"`
	FromCache   bool      `json:"from_cache"`
	Offline     bool      `json:"offline"`
}

type Summary struct {
	Packages     int `json:"packages"`
	Sources      int `json:"sources_evaluated"`
	AlreadyFixed int `json:"already_fixed"`
	// ByPriority counts only actionable findings (an upgrade, reboot or Pro
	// fix exists). Issues without any fix are counted under Unfixed instead:
	// "fix urgently" must never be shown when there is nothing to do.
	ByPriority      map[string]int `json:"by_priority"`
	ByStatus        map[string]int `json:"by_status"`
	Unfixed         int            `json:"no_fix_available"`
	UnfixedNotable  int            `json:"no_fix_notable"`
	MinorUnfixed    int            `json:"minor_unfixed_hidden"`
	KEV             int            `json:"kev"`
	ThirdParty      int            `json:"third_party_packages"`
	RestartServices int            `json:"services_needing_restart"`
	RebootNeeded    bool           `json:"reboot_needed"`
}

// Command is one suggested, never executed, shell command.
type Command struct {
	Purpose string `json:"purpose"`
	Text    string `json:"text"`
}

var unitRe = regexp.MustCompile(`^[A-Za-z0-9@._-]{1,128}\.service$`)

// Priority applies D4 to one finding.
func Priority(f match.Finding, exposed bool) string {
	cvss := 0.0
	if f.CVSS != nil {
		cvss = *f.CVSS
	}
	epss := 0.0
	if f.EPSS != nil {
		epss = *f.EPSS
	}
	high := cvss >= CVSSHigh || f.Severity == "HIGH" || f.Severity == "CRITICAL"
	switch {
	case f.KEV:
		return "P0"
	case cvss >= CVSSCritical && exposed:
		return "P0"
	case epss >= EPSSHigh:
		return "P1"
	case cvss >= CVSSHigh && exposed:
		return "P1"
	case high:
		return "P2"
	default:
		return "P3"
	}
}

// Build assembles the report.
func Build(scanner string, o system.OS, inv *system.Inventory, res match.Result, rt *procinfo.Report, data DataInfo, notes []string, showAll bool, found *l2.Result, outcome *l2.Outcome) *Report {
	r := &Report{
		Schema: SchemaVersion, Scanner: scanner, ScannedAt: time.Now().UTC(),
		OS:   OSInfo{Name: o.PrettyName, Distro: o.Distro, Release: o.Release},
		Data: data, Kernel: res.Kernel, Runtime: rt, ThirdParty: res.ThirdParty,
		kind: o.Kind, distro: o.Distro, showAll: showAll, stalePackages: map[string]bool{},
	}
	if found != nil {
		r.L2 = found
		r.Notes = append(r.Notes, found.Notes...)
	}
	if outcome != nil {
		r.L2Evaluated = true
		r.L2NoData = outcome.NoData
		res.Findings = append(append([]match.Finding{}, res.Findings...), outcome.Findings...)
		res.FixedCount += outcome.AlreadyFixed
		// Third-party packages that L2 actually evaluated are no longer "unknown".
		covered := map[string]bool{}
		noData := map[string]bool{}
		for _, n := range outcome.NoData {
			noData[n] = true
		}
		for _, in := range found.Installs {
			if in.Version != "" && !noData[in.ProductName] {
				for _, p := range in.Packages {
					covered[p] = true
				}
			}
		}
		var remaining []system.Package
		for _, p := range r.ThirdParty {
			if !covered[p.Name] {
				remaining = append(remaining, p)
			}
		}
		r.ThirdParty = remaining
	}
	if r.ThirdParty == nil {
		r.ThirdParty = []system.Package{}
	}
	r.Notes = append(append(append([]string{}, notes...), inv.Notes...), res.Notes...)
	if rt != nil {
		r.Notes = append(r.Notes, rt.Notes...)
		for _, sp := range rt.Stale {
			for _, p := range sp.Packages {
				r.stalePackages[p] = true
			}
		}
	}
	for _, f := range res.Findings {
		exposed := false
		if rt != nil {
			exposed = rt.Exposed[f.Package]
			for _, b := range f.Binaries {
				exposed = exposed || rt.Exposed[b]
			}
		}
		f.Exposed = exposed
		f.Priority = Priority(f, exposed)
		// Code bundled into a Go program (dependencies, standard library) may
		// not be reachable: never above P2 unless exploited in the wild.
		if f.Component != "" && !f.KEV && f.Priority < "P2" {
			f.Priority = "P2"
		}
		if f.Status == match.Unknown || (f.Minor && !f.KEV) {
			f.Priority = "P3"
		}
		r.Findings = append(r.Findings, f)
	}
	if r.Findings == nil {
		r.Findings = []match.Finding{}
	}
	r.Containers = []ContainerResult{}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.KEV != b.KEV {
			return a.KEV
		}
		ca, cb := score(a.CVSS), score(b.CVSS)
		if ca != cb {
			return ca > cb
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.ID < b.ID
	})
	s := Summary{
		Packages: res.PackagesScanned, Sources: res.SourcesEvaluated, AlreadyFixed: res.FixedCount,
		ByPriority: map[string]int{}, ByStatus: map[string]int{}, ThirdParty: len(r.ThirdParty),
		MinorUnfixed: res.MinorUnfixed,
	}
	for _, f := range r.Findings {
		s.ByStatus[string(f.Status)]++
		if f.KEV {
			s.KEV++
		}
		switch {
		case f.Status == match.Unknown:
		case Actionable(f):
			s.ByPriority[f.Priority]++
		case f.Minor:
			// Rated negligible by the distro; counted in MinorUnfixed.
		default:
			s.Unfixed++
			if Notable(f) {
				s.UnfixedNotable++
			}
		}
		if f.Fix == match.FixReboot {
			s.RebootNeeded = true
		}
	}
	if rt != nil {
		s.RestartServices = len(rt.Stale)
		if rt.RebootRequired {
			s.RebootNeeded = true
		}
	}
	r.Summary = s
	return r
}

func compareVersions(kind version.Kind, a, b string) (int, error) {
	return version.Compare(kind, a, b)
}

// Actionable reports whether the user can do something about f now.
func Actionable(f match.Finding) bool {
	return f.Fix == match.FixUpgrade || f.Fix == match.FixReboot || f.Fix == match.FixSubscription
}

// Notable marks unfixed issues worth showing by default: exploited in the
// wild, likely to be exploited, or critical and reachable from the network.
func Notable(f match.Finding) bool {
	epss := 0.0
	if f.EPSS != nil {
		epss = *f.EPSS
	}
	return f.KEV || epss >= EPSSHigh || (f.Exposed && f.CVSS != nil && *f.CVSS >= CVSSCritical)
}

// Urgent decides the default exit code: an actionable P0/P1, or anything in KEV.
func (r *Report) Urgent() bool { return r.Exceeds("P1") }

// Exceeds reports an actionable finding at level or above (P0 is highest), or
// any exploited vulnerability; "none" never fails (--fail-on).
func (r *Report) Exceeds(level string) bool {
	if level == "none" {
		return false
	}
	for p, n := range r.Summary.ByPriority {
		if n > 0 && p <= level {
			return true
		}
	}
	return r.Summary.KEV > 0 || r.exceedsContainers(level)
}

func score(v *float64) float64 {
	if v == nil {
		return -1
	}
	return *v
}

// safeNames filters names through the whitelist; rejected names are dropped
// from commands (and reported) rather than escaped.
func safeNames(names []string) ([]string, []string) {
	var ok, bad []string
	for _, n := range names {
		if system.ValidPackageName.MatchString(n) {
			ok = append(ok, n)
		} else {
			bad = append(bad, n)
		}
	}
	return ok, bad
}

func (r *Report) upgradeCommand(bins []string) string {
	switch r.kind {
	case version.Deb:
		return "sudo apt-get update && sudo apt-get install --only-upgrade " + strings.Join(bins, " ")
	case version.RPM:
		return "sudo dnf upgrade " + strings.Join(bins, " ")
	case version.APK:
		return "apk update && apk upgrade " + strings.Join(bins, " ")
	}
	return ""
}

func (r *Report) verifyCommand(bins []string) string {
	switch r.kind {
	case version.Deb:
		return "dpkg-query -W -f='${Package} ${Version}\\n' " + strings.Join(bins, " ")
	case version.RPM:
		return "rpm -q " + strings.Join(bins, " ")
	case version.APK:
		return "apk info -v " + strings.Join(bins, " ")
	}
	return ""
}

// WriteJSON renders the machine-readable report.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
