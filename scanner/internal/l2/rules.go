// Package l2 finds software installed outside the package manager (BaoTa panel,
// one-click LNMP scripts, source builds, official binaries, nvm/fnm/volta) and
// third-party repository packages, and determines their upstream versions
// (layer L2 of docs/ARCHITECTURE.md D3).
//
// Detection rules are compiled into the binary (see rules/products/README.md):
// they decide which programs may be executed, so they must never come from the
// network.
package l2

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//go:embed rules/*.json
var embedded embed.FS

// Rule describes one product.
type Rule struct {
	Slug    string            `json:"slug"`
	Name    string            `json:"name"`
	Detect  Detect            `json:"detect"`
	Upgrade map[string]string `json:"upgrade"`

	versionRe        *regexp.Regexp
	pathVersionRe    *regexp.Regexp
	packageVersionRe *regexp.Regexp
	sourceRe         *regexp.Regexp
}

type Detect struct {
	Binaries            []Binary  `json:"binaries"`
	ProcessNames        []string  `json:"process_names"`
	VersionArgs         []string  `json:"version_args"`
	VersionRegex        string    `json:"version_regex"`
	PathVersionRegex    string    `json:"path_version_regex"`
	PackageVersionRegex string    `json:"package_version_regex"`
	Bundled             []Bundled `json:"bundled"`
	Variants            []Variant `json:"variants"`
	Packages            Packages  `json:"packages"`
}

type Binary struct {
	Glob   string `json:"glob"`
	Method string `json:"method"`
}

type Bundled struct {
	Product string `json:"product"`
	Regex   string `json:"regex"`
	re      *regexp.Regexp
}

type Variant struct {
	Contains     string `json:"contains"`
	Product      string `json:"product"`
	VersionRegex string `json:"version_regex"`
	re           *regexp.Regexp
}

type Packages struct {
	Names       []string `json:"names"`
	SourceRegex string   `json:"source_regex"`
}

// defaultPackageVersion extracts the upstream version from a distro package
// version: optional epoch, then dotted numbers (OpenSSH-style pN allowed).
var defaultPackageVersion = regexp.MustCompile(`^(?:[0-9]+:)?([0-9]+(?:\.[0-9]+)+(?:p[0-9]+)?)`)

var (
	safeArg    = regexp.MustCompile(`^(?:-{1,2}[A-Za-z][A-Za-z-]*|version)$`)
	methods    = map[string]bool{"baota": true, "lnmp": true, "source": true, "binary": true, "nvm": true, "fnm": true, "volta": true, "n": true}
	slugRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	procNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
)

func (r *Rule) compile() error {
	if !slugRe.MatchString(r.Slug) || r.Name == "" {
		return fmt.Errorf("bad slug/name %q", r.Slug)
	}
	for _, b := range r.Detect.Binaries {
		if !filepath.IsAbs(b.Glob) || strings.Contains(b.Glob, "..") || !methods[b.Method] {
			return fmt.Errorf("%s: bad binary glob %q / method %q", r.Slug, b.Glob, b.Method)
		}
		if _, err := filepath.Match(b.Glob, "/"); err != nil {
			return fmt.Errorf("%s: bad glob %q: %w", r.Slug, b.Glob, err)
		}
	}
	for _, a := range r.Detect.VersionArgs {
		if !safeArg.MatchString(a) {
			return fmt.Errorf("%s: version argument %q is not a plain flag", r.Slug, a)
		}
	}
	for _, p := range r.Detect.ProcessNames {
		if !procNameRe.MatchString(p) {
			return fmt.Errorf("%s: bad process name %q", r.Slug, p)
		}
	}
	var err error
	compile := func(expr string) *regexp.Regexp {
		if expr == "" || err != nil {
			return nil
		}
		re, e := regexp.Compile(expr)
		if e != nil {
			err = fmt.Errorf("%s: regex %q: %w", r.Slug, expr, e)
			return nil
		}
		if re.NumSubexp() < 1 {
			err = fmt.Errorf("%s: regex %q needs a capture group", r.Slug, expr)
		}
		return re
	}
	if r.Detect.VersionRegex == "" {
		return fmt.Errorf("%s: version_regex is required", r.Slug)
	}
	r.versionRe = compile(r.Detect.VersionRegex)
	r.pathVersionRe = compile(r.Detect.PathVersionRegex)
	r.packageVersionRe = compile(r.Detect.PackageVersionRegex)
	if r.Detect.Packages.SourceRegex != "" && err == nil {
		r.sourceRe, err = regexp.Compile(r.Detect.Packages.SourceRegex)
	}
	for i := range r.Detect.Bundled {
		r.Detect.Bundled[i].re = compile(r.Detect.Bundled[i].Regex)
	}
	for i := range r.Detect.Variants {
		r.Detect.Variants[i].re = compile(r.Detect.Variants[i].VersionRegex)
	}
	return err
}

// LoadRules returns the compiled-in rules, validated, sorted by slug.
func LoadRules() ([]*Rule, error) {
	entries, err := embedded.ReadDir("rules")
	if err != nil {
		return nil, err
	}
	var rules []*Rule
	for _, e := range entries {
		raw, err := embedded.ReadFile("rules/" + e.Name())
		if err != nil {
			return nil, err
		}
		r := &Rule{}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		if err := dec.Decode(r); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if r.Slug+".json" != e.Name() {
			return nil, fmt.Errorf("%s: slug %q does not match file name", e.Name(), r.Slug)
		}
		if err := r.compile(); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Slug < rules[j].Slug })
	return rules, nil
}

// UpgradeText renders the guidance for an install method.
func (r *Rule) UpgradeText(method, fixed string) string {
	t := r.Upgrade[method]
	if t == "" {
		t = r.Upgrade["process"]
	}
	if fixed == "" {
		fixed = "最新的受支持版本"
	}
	return strings.NewReplacer("{name}", r.Name, "{fixed}", fixed).Replace(t)
}
