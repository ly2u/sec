// Command mkbundle builds a signed test bundle with a throwaway key. It exists
// for tests and CI container checks only and is not part of any release.
//
//	mkbundle -distro debian -release 12 -in entries.json -out DIR
//
// entries.json maps a package name to a list of bundle entries.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/testutil/fixture"
)

func main() {
	distro := flag.String("distro", "", "")
	release := flag.String("release", "", "")
	key := flag.String("package-key", "source", "")
	in := flag.String("in", "", "")
	out := flag.String("out", "", "")
	flag.Parse()
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkbundle:", err)
		os.Exit(1)
	}
	var pkgs map[string][]bundle.Entry
	if err := json.Unmarshal(raw, &pkgs); err != nil {
		fmt.Fprintln(os.Stderr, "mkbundle:", err)
		os.Exit(1)
	}
	path, err := fixture.WriteBundle(*distro, *release, *key, pkgs, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkbundle:", err)
		os.Exit(1)
	}
	fmt.Println(path)
}
