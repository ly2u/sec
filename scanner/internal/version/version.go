// Package version compares distro package versions with the native algorithm of
// each package manager. It never falls back to string or numeric comparison:
// an unparsable version is an error, which callers must report as UNKNOWN.
package version

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	apk "github.com/knqyf263/go-apk-version"
	deb "github.com/knqyf263/go-deb-version"
	rpm "github.com/knqyf263/go-rpm-version"

	"github.com/ly2u/sec/scanner/internal/thirdparty/semver"
)

// Kind is the package manager whose comparison rules apply.
type Kind string

const (
	Deb Kind = "deb"
	RPM Kind = "rpm"
	APK Kind = "apk"
	// Upstream compares plain upstream release versions (1.24.0, 9.8p1,
	// 1.1.1w, 24.22.1) segment by segment, using rpmvercmp's rules.
	Upstream Kind = "upstream"
	// Go compares Go module and Go release versions as semver without the
	// leading "v" (1.21.3, 0.17.0, 1.21.0-0, pseudo-versions), as the Go
	// vulnerability database writes them.
	Go Kind = "go"
)

var upstreamVersion = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~_]{0,63}$`)

// Compare returns -1, 0 or 1. The OSV sentinel "0" (as in introduced: "0")
// sorts before every real version.
func Compare(kind Kind, a, b string) (int, error) {
	c, err := compare(kind, a, b)
	switch {
	case err != nil:
		return 0, err
	case c < 0:
		return -1, nil
	case c > 0:
		return 1, nil
	}
	return 0, nil
}

func compare(kind Kind, a, b string) (int, error) {
	if a == "0" || b == "0" {
		switch {
		case a == b:
			return 0, nil
		case a == "0":
			return -1, nil
		default:
			return 1, nil
		}
	}
	switch kind {
	case Deb:
		va, err := deb.NewVersion(a)
		if err != nil {
			return 0, fmt.Errorf("invalid deb version %q: %w", a, err)
		}
		vb, err := deb.NewVersion(b)
		if err != nil {
			return 0, fmt.Errorf("invalid deb version %q: %w", b, err)
		}
		return va.Compare(vb), nil
	case RPM:
		if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
			return 0, fmt.Errorf("empty rpm version")
		}
		va, vb := rpm.NewVersion(a), rpm.NewVersion(b)
		return va.Compare(vb), nil
	case Upstream:
		for _, v := range []string{a, b} {
			if !upstreamVersion.MatchString(v) {
				return 0, fmt.Errorf("invalid upstream version %q", v)
			}
		}
		// No epoch and no release: compare the version string alone.
		va, vb := rpm.NewVersion("0:"+a), rpm.NewVersion("0:"+b)
		return va.Compare(vb), nil
	case Go:
		va, vb := "v"+a, "v"+b
		for _, v := range []string{va, vb} {
			if !semver.IsValid(v) {
				return 0, fmt.Errorf("invalid Go version %q", v[1:])
			}
		}
		return semver.Compare(va, vb), nil
	case APK:
		va, err := apk.NewVersion(a)
		if err != nil {
			return 0, fmt.Errorf("invalid apk version %q: %w", a, err)
		}
		vb, err := apk.NewVersion(b)
		if err != nil {
			return 0, fmt.Errorf("invalid apk version %q: %w", b, err)
		}
		return va.Compare(vb), nil
	}
	return 0, fmt.Errorf("unsupported version kind %q", kind)
}

// Event is one OSV range event; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

func (e Event) value() string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.LastAffected != "":
		return e.LastAffected
	default:
		return e.Limit
	}
}

// Affected evaluates OSV ECOSYSTEM range events against v using the algorithm
// from the OSV schema: sort events by version, then walk them in order,
// switching the affected state on at introduced and off at fixed / after
// last_affected. limit bounds the search.
func Affected(kind Kind, v string, events []Event) (bool, error) {
	sorted := make([]Event, 0, len(events))
	for _, e := range events {
		if e.value() == "" {
			return false, fmt.Errorf("empty range event")
		}
		sorted = append(sorted, e)
	}
	var sortErr error
	sort.SliceStable(sorted, func(i, j int) bool {
		c, err := Compare(kind, sorted[i].value(), sorted[j].value())
		if err != nil && sortErr == nil {
			sortErr = err
		}
		return c < 0
	})
	if sortErr != nil {
		return false, sortErr
	}
	affected := false
	for _, e := range sorted {
		c, err := Compare(kind, v, e.value())
		if err != nil {
			return false, err
		}
		switch {
		case e.Introduced != "":
			if c >= 0 {
				affected = true
			}
		case e.Fixed != "":
			if c >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			if c > 0 {
				affected = false
			}
		case e.Limit != "":
			if c >= 0 {
				// Versions at or beyond limit are outside this range entirely.
				return false, nil
			}
		}
	}
	return affected, nil
}

// FirstFixAbove returns the smallest fixed version strictly greater than v,
// i.e. the upgrade target that ends the affected interval containing v.
func FirstFixAbove(kind Kind, v string, events []Event) (string, error) {
	best := ""
	for _, e := range events {
		if e.Fixed == "" {
			continue
		}
		c, err := Compare(kind, e.Fixed, v)
		if err != nil {
			return "", err
		}
		if c <= 0 {
			continue
		}
		if best == "" {
			best = e.Fixed
			continue
		}
		if c2, err := Compare(kind, e.Fixed, best); err != nil {
			return "", err
		} else if c2 < 0 {
			best = e.Fixed
		}
	}
	return best, nil
}
