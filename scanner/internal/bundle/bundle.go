// Package bundle downloads, verifies and decodes SecWatch distro data bundles.
//
// Trust model: a bundle is accepted only if (1) its minisign signature verifies
// against a trusted public key, (2) the signed trusted comment binds it to the
// exact file name and key id, and (3) the decoded payload names the distro and
// release the caller asked for. Bundles carry facts only; nothing in them is
// ever executed.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/jedisct1/go-minisign"
	"github.com/klauspost/compress/zstd"

	"github.com/ly2u/sec/scanner/internal/version"
)

const (
	MaxManifestBytes     = 1 << 20
	MaxCompressedBytes   = 128 << 20
	MaxUncompressedBytes = 1 << 30
	MaxSignatureBytes    = 4 << 10
)

//go:embed keys/*.pub
var embeddedKeys embed.FS

// FileName is the only accepted shape of a bundle file name.
var FileName = regexp.MustCompile(`^[a-z]+-[0-9][0-9.]*\.[0-9a-f]{12}\.json\.zst$`)

// Bundle is one distro release's vulnerability facts.
type Bundle struct {
	Schema         int                `json:"schema"`
	Distro         string             `json:"distro"`
	Release        string             `json:"release"`
	PackageKey     string             `json:"package_key"`
	GeneratedAt    time.Time          `json:"generated_at"`
	SourcePackages map[string][]Entry `json:"source_packages"`
	Sources        map[string]string  `json:"sources"`
	Coverage       Coverage           `json:"coverage"`
}

type Coverage struct {
	Status              string   `json:"status"`
	MissingPackageMeans string   `json:"missing_package_means"`
	ExcludedChannels    []string `json:"excluded_channels"`
}

type Range struct {
	Type   string          `json:"type"`
	Events []version.Event `json:"events"`
}

type Fix struct {
	Version              string `json:"version"`
	RequiresSubscription bool   `json:"requires_subscription"`
}

type Entry struct {
	ID                   string   `json:"id"`
	AdvisoryID           string   `json:"advisory_id"`
	Aliases              []string `json:"aliases"`
	CVEIDs               []string `json:"cve_ids"`
	Ecosystem            string   `json:"ecosystem"`
	Status               string   `json:"status"`
	FixedVersion         *string  `json:"fixed_version"`
	Ranges               []Range  `json:"ranges"`
	RequiresSubscription bool     `json:"requires_subscription"`
	Fixes                []Fix    `json:"fixes"`
	Severity             *string  `json:"severity"`
	CVSS                 *float64 `json:"cvss"`
	KEV                  bool     `json:"kev"`
	// Ransomware: CISA lists the vulnerability as used in ransomware campaigns.
	Ransomware bool     `json:"ransomware,omitempty"`
	EPSS       *float64 `json:"epss"`
	Ref        string   `json:"ref"`
	// Urgency is the Debian security tracker rating (unimportant, low, medium,
	// high, end-of-life); absent for other distros.
	Urgency *string `json:"urgency"`
}

// Manifest points at the current bundle of each distro release.
type Manifest struct {
	Schema      int                      `json:"schema"`
	KeyID       string                   `json:"key_id"`
	GeneratedAt string                   `json:"generated_at"`
	Bundles     map[string]ManifestEntry `json:"bundles"`
}

type ManifestEntry struct {
	File        string `json:"file"`
	Signature   string `json:"signature"`
	SHA256      string `json:"sha256"`
	KeyID       string `json:"key_id"`
	Entries     int    `json:"entries"`
	GeneratedAt string `json:"generated_at"`
}

// TrustedKeys returns the public keys compiled into the binary, by key id.
func TrustedKeys() (map[string]minisign.PublicKey, error) {
	entries, err := embeddedKeys.ReadDir("keys")
	if err != nil {
		return nil, err
	}
	keys := map[string]minisign.PublicKey{}
	for _, e := range entries {
		raw, err := embeddedKeys.ReadFile("keys/" + e.Name())
		if err != nil {
			return nil, err
		}
		pk, err := ParsePublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("embedded key %s: %w", e.Name(), err)
		}
		keys[KeyID(pk)] = pk
	}
	if len(keys) == 0 {
		return nil, errors.New("no trusted keys compiled in")
	}
	return keys, nil
}

// ParsePublicKey reads a minisign public key file (comment line + base64 line).
func ParsePublicKey(raw []byte) (minisign.PublicKey, error) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	b64 := strings.TrimSpace(lines[len(lines)-1])
	pk, err := minisign.NewPublicKey(b64)
	if err != nil {
		return pk, err
	}
	if pk.SignatureAlgorithm != [2]byte{'E', 'd'} {
		return pk, errors.New("unsupported public key algorithm")
	}
	return pk, nil
}

// KeyID renders a key id the way minisign prints it.
func KeyID(pk minisign.PublicKey) string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = pk.KeyId[7-i]
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func signatureKeyID(sig minisign.Signature) string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = sig.KeyId[7-i]
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// Verify checks data against a minisign signature and binds it to fileName.
func Verify(data, sigText []byte, fileName string, keys map[string]minisign.PublicKey) error {
	if len(sigText) > MaxSignatureBytes {
		return errors.New("signature too large")
	}
	sig, err := minisign.DecodeSignature(string(sigText))
	if err != nil {
		return fmt.Errorf("malformed signature: %w", err)
	}
	keyID := signatureKeyID(sig)
	pk, ok := keys[keyID]
	if !ok {
		return fmt.Errorf("signature key %s is not trusted", keyID)
	}
	if ok, err := pk.Verify(data, sig); !ok || err != nil {
		if err == nil {
			err = errors.New("invalid signature")
		}
		return fmt.Errorf("signature verification failed: %w", err)
	}
	// The trusted comment is covered by the global signature verified above.
	fields := map[string]string{}
	for _, f := range strings.Fields(strings.TrimPrefix(sig.TrustedComment, "trusted comment: ")) {
		if k, v, found := strings.Cut(f, "="); found {
			fields[k] = v
		}
	}
	if fields["schema"] != "1" || fields["key_id"] != keyID || fields["file"] != fileName {
		return fmt.Errorf("signature is not bound to %s (trusted comment %q)", fileName, sig.TrustedComment)
	}
	return nil
}

// Decode decompresses and parses a verified bundle, enforcing size limits and
// checking that it describes the expected distro release.
func Decode(compressed []byte, distro, release string) (*Bundle, error) {
	dec, err := zstd.NewReader(bytes.NewReader(compressed), zstd.WithDecoderMaxMemory(MaxUncompressedBytes))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	raw, err := io.ReadAll(io.LimitReader(dec, MaxUncompressedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	if len(raw) > MaxUncompressedBytes {
		return nil, errors.New("bundle exceeds size limit")
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	if b.Schema != 1 {
		return nil, fmt.Errorf("unsupported bundle schema %d", b.Schema)
	}
	if b.Distro != distro || b.Release != release {
		return nil, fmt.Errorf("bundle is for %s %s, expected %s %s", b.Distro, b.Release, distro, release)
	}
	switch b.PackageKey {
	case "source", "binary", "origin", "product", "module":
	default:
		return nil, fmt.Errorf("unknown package_key %q", b.PackageKey)
	}
	return &b, nil
}

// SHA256Hex returns the hex digest of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ParseManifest validates a manifest's structure and file names.
func ParseManifest(raw []byte) (*Manifest, error) {
	if len(raw) > MaxManifestBytes {
		return nil, errors.New("manifest too large")
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Schema != 1 {
		return nil, fmt.Errorf("unsupported manifest schema %d", m.Schema)
	}
	for slug, e := range m.Bundles {
		if !FileName.MatchString(e.File) || e.Signature != e.File+".minisig" || !strings.HasPrefix(e.File, slug+".") {
			return nil, fmt.Errorf("manifest entry %s has an unsafe file name", slug)
		}
		if len(e.SHA256) != 64 {
			return nil, fmt.Errorf("manifest entry %s has an invalid digest", slug)
		}
	}
	return &m, nil
}
