package bundle

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jedisct1/go-minisign"
	"github.com/klauspost/compress/zstd"

	"github.com/ly2u/sec/scanner/internal/testutil"
)

func compressJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, _ := zstd.NewWriter(&buf)
	w.Write(raw)
	w.Close()
	return buf.Bytes()
}

func fixture(t *testing.T) (*testutil.Signer, map[string]minisign.PublicKey, []byte, string) {
	t.Helper()
	s, err := testutil.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ParsePublicKey(s.PublicKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	data := compressJSON(t, map[string]any{
		"schema": 1, "distro": "debian", "release": "12", "package_key": "source",
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"source_packages": map[string]any{}, "sources": map[string]string{},
		"coverage": map[string]any{"status": "available", "missing_package_means": "unknown"},
	})
	name := "debian-12." + SHA256Hex(data)[:12] + ".json.zst"
	return s, map[string]minisign.PublicKey{KeyID(pk): pk}, data, name
}

func TestLoadAcceptsValidBundle(t *testing.T) {
	s, keys, data, name := fixture(t)
	res, err := Load(data, s.Sign(data, s.BundleComment(name)), name, "debian", "12", keys)
	if err != nil {
		t.Fatal(err)
	}
	if res.Bundle.PackageKey != "source" || res.KeyID != s.KeyID() {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestTamperedBundleIsRejected(t *testing.T) {
	s, keys, data, name := fixture(t)
	sig := s.Sign(data, s.BundleComment(name))
	tampered := append([]byte{}, data...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := Load(tampered, sig, name, "debian", "12", keys); err == nil {
		t.Fatal("a one-byte change must fail verification")
	}
}

func TestUntrustedKeyIsRejected(t *testing.T) {
	_, keys, data, name := fixture(t)
	other, _ := testutil.NewSigner()
	if _, err := Load(data, other.Sign(data, other.BundleComment(name)), name, "debian", "12", keys); err == nil {
		t.Fatal("signature from an unknown key must be rejected")
	}
}

// A validly signed bundle for one release must not be accepted as another:
// the trusted comment binds the signature to the exact file name.
func TestSignatureIsBoundToFileName(t *testing.T) {
	s, keys, data, name := fixture(t)
	sig := s.Sign(data, s.BundleComment("debian-11.000000000000.json.zst"))
	if _, err := Load(data, sig, name, "debian", "12", keys); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("expected binding error, got %v", err)
	}
}

func TestPayloadMustMatchRequestedRelease(t *testing.T) {
	s, keys, data, _ := fixture(t)
	name := "debian-11." + SHA256Hex(data)[:12] + ".json.zst"
	if _, err := Load(data, s.Sign(data, s.BundleComment(name)), name, "debian", "11", keys); err == nil {
		t.Fatal("payload says debian 12; must not be accepted for debian 11")
	}
}

func TestManifestRejectsUnsafeNames(t *testing.T) {
	bad := `{"schema":1,"bundles":{"debian-12":{"file":"../../etc/passwd","signature":"x","sha256":"` + strings.Repeat("a", 64) + `"}}}`
	if _, err := ParseManifest([]byte(bad)); err == nil {
		t.Fatal("path traversal in manifest must be rejected")
	}
}

func TestEmbeddedProductionKeyMatchesRepository(t *testing.T) {
	embedded, err := embeddedKeys.ReadFile("keys/bundle-signing.pub")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := os.ReadFile(filepath.Join("..", "..", "..", "keys", "bundle-signing.pub"))
	if err != nil {
		t.Skip("repository key not available outside the monorepo")
	}
	if !bytes.Equal(bytes.TrimSpace(embedded), bytes.TrimSpace(repo)) {
		t.Fatal("scanner/internal/bundle/keys/bundle-signing.pub differs from keys/bundle-signing.pub")
	}
	keys, err := TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["D7B7CA69ADC798BC"]; !ok {
		t.Fatalf("expected production key id, got %v", keys)
	}
}

func TestManifestLatestScannerIsValidated(t *testing.T) {
	m, err := ParseManifest([]byte(`{"schema":1,"bundles":{},"scanner":{"latest":"v0.1.4"}}`))
	if err != nil || m.Scanner == nil || !releaseTag.MatchString(m.Scanner.Latest) {
		t.Fatalf("%+v %v", m, err)
	}
	for _, bad := range []string{"v0.1.4\x1b[2J", "latest", "v1.2", "0.1.4"} {
		if releaseTag.MatchString(bad) {
			t.Errorf("%q must be rejected", bad)
		}
	}
}
