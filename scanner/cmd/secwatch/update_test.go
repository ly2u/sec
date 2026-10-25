package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jedisct1/go-minisign"

	"github.com/ly2u/sec/scanner/internal/testutil"
)

// The embedded key is the published release key.
func TestReleaseKeyMatchesPublishedKey(t *testing.T) {
	for _, p := range []string{"../../../keys/release-signing.pub", "../../install.sh"} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), ReleaseKey) {
			t.Errorf("%s does not hold the release key", p)
		}
	}
}

type fakeRelease struct {
	ver, comment string
	bin          []byte
	sums         string
	signer       *testutil.Signer
}

func newRelease(t *testing.T, ver string) (*fakeRelease, *httptest.Server) {
	s, _ := testutil.NewSigner()
	r := &fakeRelease{ver: ver, bin: []byte("new secwatch " + ver), signer: s, comment: "secwatch release=" + ver + " file=SHA256SUMS"}
	sum := sha256.Sum256(r.bin)
	r.sums = hex.EncodeToString(sum[:]) + "  secwatch-linux-amd64\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch filepath.Base(req.URL.Path) {
		case "SHA256SUMS":
			w.Write([]byte(r.sums))
		case "SHA256SUMS.minisig":
			w.Write(r.signer.Sign([]byte(r.sums), r.comment))
		case "secwatch-linux-amd64":
			w.Write(r.bin)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(srv.Close)
	return r, srv
}

func testUpdater(t *testing.T, r *fakeRelease, srv *httptest.Server, current string) (*updater, string, *bytes.Buffer) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "secwatch")
	os.WriteFile(exe, []byte("old secwatch"), 0o755)
	pk, err := minisign.NewPublicKey(strings.TrimSpace(r.signer.PublicKeyLine()))
	if err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	return &updater{
		base: srv.URL, key: pk, exe: exe, current: current, arch: "amd64", out: out, client: srv.Client(),
		version: func(p string) (string, error) {
			data, _ := os.ReadFile(p)
			return strings.TrimPrefix(string(data), "new "), nil
		},
	}, exe, out
}

func TestUpdateInstallsVerifiedRelease(t *testing.T) {
	r, srv := newRelease(t, "v0.2.0")
	u, exe, out := testUpdater(t, r, srv, "v0.1.9")
	ver, err := u.run()
	if err != nil || ver != "v0.2.0" {
		t.Fatalf("%q %v\n%s", ver, err, out)
	}
	if data, _ := os.ReadFile(exe); string(data) != "new secwatch v0.2.0" {
		t.Errorf("binary not replaced: %q", data)
	}
	if st, _ := os.Stat(exe); st.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", st.Mode())
	}
	if target, err := os.Readlink(filepath.Join(filepath.Dir(exe), ShortName)); err != nil || target != "secwatch" {
		t.Errorf("short name: %q %v", target, err)
	}
	for _, want := range []string{"签名有效", "已更新到 v0.2.0", "SECWATCH_VERSION=v0.1.9", "已创建短命令 lysec"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// Up to date now.
	u.current = "v0.2.0"
	if ver, err := u.run(); ver != "" || err != nil || !strings.Contains(out.String(), "已经是最新版本 v0.2.0") {
		t.Errorf("%q %v", ver, err)
	}
}

func TestUpdateRefusesAnythingUnverified(t *testing.T) {
	for name, spoil := range map[string]func(r *fakeRelease){
		"other key":       func(r *fakeRelease) { r.signer, _ = testutil.NewSigner() },
		"wrong comment":   func(r *fakeRelease) { r.comment = "something else" },
		"tampered binary": func(r *fakeRelease) { r.bin = []byte("evil") },
		"no asset":        func(r *fakeRelease) { r.sums = strings.Replace(r.sums, "amd64", "riscv", 1) },
	} {
		r, srv := newRelease(t, "v0.2.0")
		u, exe, _ := testUpdater(t, r, srv, "v0.1.9")
		spoil(r)
		if _, err := u.run(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if data, _ := os.ReadFile(exe); string(data) != "old secwatch" {
			t.Errorf("%s: binary changed", name)
		}
		entries, _ := os.ReadDir(filepath.Dir(exe))
		if len(entries) != 1 {
			t.Errorf("%s: left files behind: %v", name, entries)
		}
	}
	// A new binary that does not run is not installed.
	r, srv := newRelease(t, "v0.2.0")
	u, exe, _ := testUpdater(t, r, srv, "v0.1.9")
	u.version = func(string) (string, error) { return "", errors.New("exec format error") }
	if _, err := u.run(); err == nil {
		t.Error("broken binary accepted")
	}
	if data, _ := os.ReadFile(exe); string(data) != "old secwatch" {
		t.Error("binary changed")
	}
	// Development builds are not replaced.
	u.current = "dev"
	if _, err := u.run(); err == nil {
		t.Error("dev build updated")
	}
}

// The short name never takes over another program's name.
func TestShortNameDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ShortName), []byte("someone else"), 0o755)
	if msg := ensureShortName(dir); !strings.Contains(msg, "已被其他程序占用") {
		t.Errorf("%q", msg)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, ShortName)); string(data) != "someone else" {
		t.Error("overwritten")
	}
}
