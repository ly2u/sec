// Package container finds running containers on the live host so their root
// filesystems can be scanned read-only through /proc/PID/root. It talks to no
// container runtime (no socket, no CLI): it reads /proc and, for display
// names, Docker's container config files.
package container

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

// Target is one running container.
type Target struct {
	ID    string `json:"id"`              // 12 hex digits
	Name  string `json:"name,omitempty"`  // from the runtime's config, if known
	Image string `json:"image,omitempty"` // as configured, e.g. "mariadb:11.4"
	PID   int    `json:"pid"`             // a process inside it
	Root  string `json:"-"`               // /proc/PID/root
}

// Label is what the report shows: the name, else the short ID.
func (t Target) Label() string {
	if t.Name != "" {
		return t.Name
	}
	return t.ID
}

var (
	pidDir  = regexp.MustCompile(`^[0-9]+$`)
	idRe    = regexp.MustCompile(`(?:docker|containerd|crio|libpod)[-/:]([0-9a-f]{64}|[0-9a-f]{12})`)
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	imageRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,199}$`)
)

// ID returns the container ID (full when known) of a process from its cgroup
// file, or "" for host processes. Systemd sandboxes and snaps have their own
// mount namespace too, so a runtime cgroup is what identifies a container.
func ID(procPid string) string {
	data, err := os.ReadFile(filepath.Join(procPid, "cgroup"))
	if err != nil {
		return ""
	}
	if m := idRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// Discover lists running containers, one target per container (its lowest
// PID). proc is normally "/proc" and docker "/var/lib/docker".
func Discover(proc, docker string) []Target {
	self, _ := os.Readlink(filepath.Join(proc, "self/ns/mnt"))
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil
	}
	byID := map[string]Target{}
	for _, e := range entries {
		if !pidDir.MatchString(e.Name()) {
			continue
		}
		base := filepath.Join(proc, e.Name())
		ns, err := os.Readlink(filepath.Join(base, "ns/mnt"))
		if err != nil || ns == self {
			continue
		}
		full := ID(base)
		if full == "" {
			continue
		}
		pid, _ := strconv.Atoi(e.Name())
		if t, ok := byID[full]; ok && t.PID < pid {
			continue
		}
		byID[full] = Target{ID: full[:12], PID: pid, Root: filepath.Join(base, "root")}
	}
	out := make([]Target, 0, len(byID))
	for full, t := range byID {
		t.Name, t.Image = dockerConfig(docker, full)
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label() < out[j].Label() })
	return out
}

// dockerConfig reads the name and image of a Docker container. Values that do
// not look like a name or an image reference are dropped.
func dockerConfig(docker, full string) (name, image string) {
	if docker == "" || len(full) != 64 {
		return "", ""
	}
	f, err := os.Open(filepath.Join(docker, "containers", full, "config.v2.json"))
	if err != nil {
		return "", ""
	}
	defer f.Close()
	var cfg struct {
		Name   string
		Config struct{ Image string }
	}
	if json.NewDecoder(f).Decode(&cfg) != nil {
		return "", ""
	}
	if n := trimSlash(cfg.Name); nameRe.MatchString(n) {
		name = n
	}
	if imageRe.MatchString(cfg.Config.Image) {
		image = cfg.Config.Image
	}
	return name, image
}

func trimSlash(s string) string {
	if len(s) > 0 && s[0] == '/' {
		return s[1:]
	}
	return s
}
