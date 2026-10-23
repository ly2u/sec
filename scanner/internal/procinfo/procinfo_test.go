package procinfo

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseProcNetLine(t *testing.T) {
	cases := []struct {
		line   string
		addr   string
		port   int
		public bool
		ok     bool
	}{
		// 0.0.0.0:22 LISTEN
		{"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0", "0.0.0.0", 22, true, true},
		// 127.0.0.1:5432 LISTEN
		{"   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   105        0 23456 1 0000000000000000 100 0 0 10 0", "127.0.0.1", 5432, false, true},
		// ESTABLISHED socket is ignored
		{"   2: 0100007F:1538 0100007F:D2F4 01 00000000:00000000 00:00000000 00000000   105        0 34567 1 0000000000000000 20 4 30 10 -1", "", 0, false, false},
		// [::]:443 LISTEN
		{"   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 45678 1 0000000000000000 100 0 0 10 0", "::", 443, true, true},
		// [::1]:6379 LISTEN
		{"   1: 00000000000000000000000001000000:18EB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 56789 1 0000000000000000 100 0 0 10 0", "::1", 6379, false, true},
	}
	for _, c := range cases {
		l, _, ok := ParseProcNetLine(c.line)
		if ok != c.ok {
			t.Fatalf("%q: ok=%v want %v", c.line, ok, c.ok)
		}
		if !ok {
			continue
		}
		if l.Address != c.addr || l.Port != c.port || l.Public != c.public {
			t.Errorf("got %+v, want %s:%d public=%v", l, c.addr, c.port, c.public)
		}
	}
}

func TestDeletedLibraries(t *testing.T) {
	maps := []byte(`55d0c1a00000-55d0c1a2c000 r--p 00000000 fd:01 1234 /usr/sbin/nginx
7f1c2a000000-7f1c2a0a0000 r--p 00000000 fd:01 5678 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f1c2b000000-7f1c2b0a0000 r--p 00000000 fd:01 5679 /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)
7f1c2c000000-7f1c2c001000 rw-s 00000000 00:01 42 /memfd:wayland-shm (deleted)
7f1c2d000000-7f1c2d001000 rw-s 00000000 00:01 43 /dev/shm/foo (deleted)
7f1c2e000000-7f1c2e0a0000 r--p 00000000 fd:01 5680 /usr/lib/x86_64-linux-gnu/libz.so.1.2.13
`)
	got := deletedLibraries(maps)
	want := []string{"/usr/lib/x86_64-linux-gnu/libcrypto.so.3", "/usr/lib/x86_64-linux-gnu/libssl.so.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestNormaliseUsrMerge(t *testing.T) {
	if normalise("/usr/lib/x86_64-linux-gnu/libssl.so.3") != normalise("/lib/x86_64-linux-gnu/libssl.so.3") {
		t.Fatal("usr-merged paths must normalise to the same key")
	}
	if normalise("/usr/sbin/nginx") != "/sbin/nginx" {
		t.Fatal("sbin alias")
	}
}

func TestUnitOf(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::/system.slice/nginx.service\n"), 0o644)
	if u := unitOf(dir); u != "nginx.service" {
		t.Fatalf("got %q", u)
	}
	os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::/user.slice/user-0.slice/session-3.scope\n"), 0o644)
	if u := unitOf(dir); u != "" {
		t.Fatalf("session scope is not a service: %q", u)
	}
}
