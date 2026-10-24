package system

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// confined resolves paths inside a directory as if it were the root
// directory (openat2 RESOLVE_IN_ROOT, Linux 5.6+). Used for container root
// filesystems reached through /proc/PID/root: an absolute or "../" symlink
// inside the container must never lead to a file on the host.
type confined struct{ fd int }

func openConfined(root string) (*confined, error) {
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: root, Err: err}
	}
	// Probe once so an old kernel fails here, not halfway through a scan.
	probe, err := unix.Openat2(fd, ".", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT})
	if err != nil {
		unix.Close(fd)
		return nil, &os.PathError{Op: "openat2", Path: root, Err: err}
	}
	unix.Close(probe)
	return &confined{fd: fd}, nil
}

func (c *confined) open(p string) (*os.File, error) {
	p = strings.TrimPrefix(p, "/")
	fd, err := unix.Openat2(c.fd, p, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOCTTY | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	// O_NONBLOCK only guards against FIFOs planted in the container; refuse
	// anything that is not a regular file or directory.
	st, err := f.Stat()
	if err != nil || !(st.Mode().IsRegular() || st.IsDir()) {
		f.Close()
		return nil, &os.PathError{Op: "open", Path: p, Err: unix.EINVAL}
	}
	return f, nil
}

func (c *confined) close() { unix.Close(c.fd) }
