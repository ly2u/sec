// Package fixture writes signed test bundles. Tests and CI only.
package fixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/testutil"
)

// WriteBundle writes key.pub, the bundle and its .minisig into out, signed
// with a fresh throwaway key, and returns the bundle path.
func WriteBundle(distro, release, key string, pkgs map[string][]bundle.Entry, out string) (string, error) {
	payload, err := json.Marshal(bundle.Bundle{
		Schema: 1, Distro: distro, Release: release, PackageKey: key,
		GeneratedAt: time.Now().UTC(), SourcePackages: pkgs, Sources: map[string]string{"test": "1"},
		Coverage: bundle.Coverage{Status: "available", MissingPackageMeans: "unknown"},
	})
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(payload); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	data := buf.Bytes()
	s, err := testutil.NewSigner()
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s.%s.json.zst", distro, release, bundle.SHA256Hex(data)[:12])
	if err := os.MkdirAll(out, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(out, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(path+".minisig", s.Sign(data, s.BundleComment(name)), 0o644); err != nil {
		return "", err
	}
	return path, os.WriteFile(filepath.Join(out, "key.pub"), s.PublicKeyFile(), 0o644)
}
