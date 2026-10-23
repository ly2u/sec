// Package testutil produces minisign-compatible keys and signatures for tests.
// It is never used by the scanner binary itself, which only verifies.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
	raw := append([]byte("Ed"), s.keyID[:]...)
	raw = append(raw, s.priv.Public().(ed25519.PublicKey)...)
	return []byte(fmt.Sprintf("untrusted comment: minisign public key %s\n%s\n", s.KeyID(), base64.StdEncoding.EncodeToString(raw)))
}

// Sign returns a prehashed ("ED") minisign signature, as minisign -S -H makes.
func (s *Signer) Sign(data []byte, trustedComment string) []byte {
	digest := blake2b.Sum512(data)
	sig := ed25519.Sign(s.priv, digest[:])
	line := append([]byte("ED"), s.keyID[:]...)
	line = append(line, sig...)
	global := ed25519.Sign(s.priv, append(append([]byte{}, sig...), []byte(trustedComment)...))
	return []byte(fmt.Sprintf("untrusted comment: signature from secwatch tests\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(line), trustedComment, base64.StdEncoding.EncodeToString(global)))
}

// BundleComment is the trusted comment the SecWatch server signs bundles with.
func (s *Signer) BundleComment(file string) string {
	return fmt.Sprintf("secwatch schema=1 key_id=%s file=%s", s.KeyID(), file)
}
