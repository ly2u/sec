// Package testutil produces minisign-compatible keys and signatures for tests
// and for the sigtool helper. It is never used by the scanner binary
// itself, which only verifies.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Signer holds a throwaway Ed25519 key in minisign framing.
type Signer struct {
	priv  ed25519.PrivateKey
	keyID [8]byte
}

func NewSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s := &Signer{priv: priv}
	if _, err := rand.Read(s.keyID[:]); err != nil {
		return nil, err
	}
	return s, nil
}

// Secret encodes the key as base64(key id || Ed25519 seed) for sigtool.
func (s *Signer) Secret() string {
	return base64.StdEncoding.EncodeToString(append(append([]byte{}, s.keyID[:]...), s.priv.Seed()...))
}

// SignerFromSecret is the inverse of Secret.
func SignerFromSecret(secret string) (*Signer, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil || len(raw) != 8+ed25519.SeedSize {
		return nil, errors.New("signing key: expected base64 of 40 bytes")
	}
	s := &Signer{priv: ed25519.NewKeyFromSeed(raw[8:])}
	copy(s.keyID[:], raw[:8])
	return s, nil
}

// PublicKeyLine is the second line of the minisign .pub file.
func (s *Signer) PublicKeyLine() string {
	raw := append([]byte("Ed"), s.keyID[:]...)
	return base64.StdEncoding.EncodeToString(append(raw, s.priv.Public().(ed25519.PublicKey)...))
}

// KeyID renders the key id the way minisign prints it.
func (s *Signer) KeyID() string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = s.keyID[7-i]
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// PublicKeyFile returns the contents of a minisign .pub file.
func (s *Signer) PublicKeyFile() []byte {
	return []byte(fmt.Sprintf("untrusted comment: minisign public key %s\n%s\n", s.KeyID(), s.PublicKeyLine()))
}

// Sign returns a prehashed ("ED") minisign signature, as minisign -S -H makes.
func (s *Signer) Sign(data []byte, trustedComment string) []byte {
	digest := blake2b.Sum512(data)
	sig := ed25519.Sign(s.priv, digest[:])
	line := append([]byte("ED"), s.keyID[:]...)
	line = append(line, sig...)
	global := ed25519.Sign(s.priv, append(append([]byte{}, sig...), []byte(trustedComment)...))
	return []byte(fmt.Sprintf("untrusted comment: secwatch signature\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(line), trustedComment, base64.StdEncoding.EncodeToString(global)))
}

// BundleComment is the trusted comment the SecWatch server signs bundles with.
func (s *Signer) BundleComment(file string) string {
	return fmt.Sprintf("secwatch schema=1 key_id=%s file=%s", s.KeyID(), file)
}
