// Command sigtool is a minisign helper for CI and release preparation. It is
// never shipped. Releases themselves are signed with the real minisign CLI.
//
//	sigtool pubinfo -pub keys/release-signing.pub   # constants for install.sh
//	sigtool keygen -pub FILE -secret FILE           # throwaway key (tests)
//	SIGTOOL_KEY=... sigtool sign -in FILE -comment "..."
//
// pubinfo and keygen print the constants install.sh embeds, as shell
// assignments.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ly2u/sec/scanner/internal/testutil"
)

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sigtool:", err)
	os.Exit(1)
}

func constants(line string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil || len(raw) != 42 || !bytes.Equal(raw[:2], []byte("Ed")) {
		return "", errors.New("not a minisign Ed25519 public key")
	}
	id := make([]byte, 8)
	for i := range id {
		id[i] = raw[9-i]
	}
	der := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, raw[10:]...)
	return fmt.Sprintf("KEY_ID='%s'\nKEY_ID_RAW='%s'\nMINISIGN_PUB='%s'\nPUB_PEM='%s'\n",
		strings.ToUpper(hex.EncodeToString(id)), hex.EncodeToString(raw[2:10]),
		strings.TrimSpace(line), base64.StdEncoding.EncodeToString(der)), nil
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: sigtool pubinfo|keygen|sign ..."))
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	switch os.Args[1] {
	case "pubinfo":
		pub := fs.String("pub", "", "minisign public key file")
		_ = fs.Parse(os.Args[2:])
		data, err := os.ReadFile(*pub)
		if err != nil {
			fail(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "untrusted comment:") {
			fail(errors.New("expected a two-line minisign .pub file"))
		}
		out, err := constants(lines[1])
		if err != nil {
			fail(err)
		}
		fmt.Print(out)
	case "keygen":
		pub := fs.String("pub", "", "public key file to write")
		secret := fs.String("secret", "", "secret key file to write (mode 0600)")
		_ = fs.Parse(os.Args[2:])
		if *pub == "" || *secret == "" {
			fail(errors.New("keygen needs -pub and -secret"))
		}
		s, err := testutil.NewSigner()
		if err != nil {
			fail(err)
		}
		if err := os.WriteFile(*secret, []byte(s.Secret()+"\n"), 0o600); err != nil {
			fail(err)
		}
		if err := os.WriteFile(*pub, s.PublicKeyFile(), 0o644); err != nil {
			fail(err)
		}
		out, _ := constants(s.PublicKeyLine())
		fmt.Print(out)
	case "sign":
		in := fs.String("in", "", "file to sign; writes FILE.minisig")
		comment := fs.String("comment", "", "trusted comment")
		_ = fs.Parse(os.Args[2:])
		s, err := testutil.SignerFromSecret(os.Getenv("SIGTOOL_KEY"))
		if err != nil {
			fail(err)
		}
		data, err := os.ReadFile(*in)
		if err != nil {
			fail(err)
		}
		if *comment == "" {
			fail(errors.New("sign needs -comment"))
		}
		if err := os.WriteFile(*in+".minisig", s.Sign(data, *comment), 0o644); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}
