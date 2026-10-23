// Command mkbundle builds signed test bundles with a throwaway key. It exists
// for tests and CI container checks only and is not part of any release.
//
//	mkbundle -distro debian -release 12 -in entries.json [-upstream-in up.json] -out DIR
//
// entries.json maps a package name to a list of bundle entries. With
// -upstream-in, an upstream-1 bundle signed by the same key is written too.
// The bundle paths are printed one per line.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/testutil"
	"github.com/ly2u/sec/scanner/internal/testutil/fixture"
)

func load(path string) map[string][]bundle.Entry {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	var pkgs map[string][]bundle.Entry
	if err := json.Unmarshal(raw, &pkgs); err != nil {
		fail(err)
	}
	return pkgs
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "mkbundle:", err)
	os.Exit(1)
}

func main() {
	distro := flag.String("distro", "", "")
	release := flag.String("release", "", "")
	key := flag.String("package-key", "source", "")
	in := flag.String("in", "", "")
	upstreamIn := flag.String("upstream-in", "", "")
	out := flag.String("out", "", "")
	flag.Parse()
	s, err := testutil.NewSigner()
	if err != nil {
		fail(err)
	}
	path, err := fixture.WriteBundleSigned(s, *distro, *release, *key, load(*in), *out)
	if err != nil {
		fail(err)
	}
	fmt.Println(path)
	if *upstreamIn != "" {
		up, err := fixture.WriteBundleSigned(s, "upstream", "1", "product", load(*upstreamIn), *out)
		if err != nil {
			fail(err)
		}
		fmt.Println(up)
	}
	if err := os.WriteFile(filepath.Join(*out, "key.pub"), s.PublicKeyFile(), 0o644); err != nil {
		fail(err)
	}
}
