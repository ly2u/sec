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
	Schema        int                  `json:"schema"`
	Scanner       string               `json:"scanner_version"`
	ScannedAt     time.Time            `json:"scanned_at"`
	OS            OSInfo               `json:"os"`
	Data          DataInfo             `json:"data"`
	Summary       Summary              `json:"summary"`
	Findings      []match.Finding      `json:"findings"`
	Kernel        match.KernelState    `json:"kernel"`
	Runtime       *procinfo.Report     `json:"runtime"`
	ThirdParty    []system.Package     `json:"third_party_packages"`
	Notes         []string             `json:"notes"`
	Commands      map[string][]Command `json:"-"`
	kind          version.Kind
	distro        string
	showAll       bool
	stalePackages map[string]bool
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
	Packages        int            `json:"packages"`
	Sources         int            `json:"sources_evaluated"`
	AlreadyFixed    int            `json:"already_fixed"`
	ByPriority      map[string]int `json:"by_priority"`
	ByStatus        map[string]int `json:"by_status"`
	Unfixed         int            `json:"no_fix_available"`
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
func Build(scanner string, o system.OS, inv *system.Inventory, res match.Result, rt *procinfo.Report, data DataInfo, notes []string, showAll bool) *Report {
	r := &Report{
		Schema: SchemaVersion, Scanner: scanner, ScannedAt: time.Now().UTC(),
		OS:   OSInfo{Name: o.PrettyName, Distro: o.Distro, Release: o.Release},
		Data: data, Kernel: res.Kernel, Runtime: rt, ThirdParty: res.ThirdParty,
		kind: o.Kind, distro: o.Distro, showAll: showAll, stalePackages: map[string]bool{},
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
		if f.Status == match.Unknown {
			f.Priority = "P3"
		}
		r.Findings = append(r.Findings, f)
	}
	if r.Findings == nil {
		r.Findings = []match.Finding{}
	}
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
		ByPriority: map[string]int{}, ByStatus: map[string]int{}, ThirdParty: len(res.ThirdParty),
	}
	for _, f := range r.Findings {
		s.ByPriority[f.Priority]++
		s.ByStatus[string(f.Status)]++
		if f.Fix == match.FixNone {
			s.Unfixed++
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
