package container

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, data string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func proc(t *testing.T, dir, pid, ns, cgroup string) {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, pid, "ns"), 0o755)
	os.Symlink(ns, filepath.Join(dir, pid, "ns/mnt"))
	write(t, filepath.Join(dir, pid, "cgroup"), cgroup)
}

func TestDiscoverOneTargetPerContainer(t *testing.T) {
	dir := t.TempDir()
	p, docker := filepath.Join(dir, "proc"), filepath.Join(dir, "docker")
	full := "3f2a9c1d4e5b6a7980112233445566778899aabbccddeeff0011223344556677"
	os.MkdirAll(filepath.Join(p, "self/ns"), 0o755)
	os.Symlink("mnt:[1]", filepath.Join(p, "self/ns/mnt"))
	proc(t, p, "1", "mnt:[1]", "0::/init.scope\n")                                                                     // host
	proc(t, p, "700", "mnt:[9]", "0::/system.slice/systemd-logind.service\n")                                          // systemd sandbox
	proc(t, p, "812", "mnt:[5]", "0::/system.slice/docker-"+full+".scope\n")                                           // container, 2nd process
	proc(t, p, "657", "mnt:[5]", "0::/system.slice/docker-"+full+".scope\n")                                           // container, lowest PID
	proc(t, p, "900", "mnt:[1]", "0::/system.slice/docker-"+full+".scope\n")                                           // same ns as host (e.g. --pid=host tool)
	proc(t, p, "950", "mnt:[7]", "12:pids:/docker/aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\n") // cgroup v1, no config
	write(t, filepath.Join(docker, "containers", full, "config.v2.json"), `{"Name":"/mariadb","Config":{"Image":"mariadb:11.4"}}`)

	got := Discover(p, docker)
	if len(got) != 2 {
		t.Fatalf("want 2 containers, got %+v", got)
	}
	if got[0].Label() != "aabbccddeeff" || got[0].Name != "" {
		t.Errorf("unnamed container falls back to its short ID: %+v", got[0])
	}
	m := got[1]
	if m.Name != "mariadb" || m.Image != "mariadb:11.4" || m.PID != 657 || m.Root != filepath.Join(p, "657/root") || m.ID != full[:12] {
		t.Errorf("mariadb: %+v", m)
	}
}

func TestDockerConfigRejectsOddValues(t *testing.T) {
	dir := t.TempDir()
	full := "3f2a9c1d4e5b6a7980112233445566778899aabbccddeeff0011223344556677"
	write(t, filepath.Join(dir, "containers", full, "config.v2.json"), "{\"Name\":\"/x;rm -rf /\",\"Config\":{\"Image\":\"img\\u001b[2J\"}}")
	if n, i := dockerConfig(dir, full); n != "" || i != "" {
		t.Errorf("got %q %q", n, i)
	}
}
