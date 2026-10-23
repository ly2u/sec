package l2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	execTimeout   = 5 * time.Second
	maxExecOutput = 64 << 10
)

// errUnsafe explains why a program was not executed.
var errUnsafe = errors.New("unsafe to execute")

// SafeToExec reports whether path may be run as root: it must be a regular,
// root-owned file, and neither it nor any parent directory may be writable by
// group or others. Otherwise an unprivileged user could substitute the program
// and have the root scanner execute their code.
func SafeToExec(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: relative path", errUnsafe)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode()&0o111 == 0 {
		return fmt.Errorf("%w: not an executable regular file", errUnsafe)
	}
	for p := resolved; ; p = filepath.Dir(p) {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		sys, ok := info.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 {
			return fmt.Errorf("%w: %s is not owned by root", errUnsafe, p)
		}
		if info.Mode()&0o022 != 0 {
			return fmt.Errorf("%w: %s is writable by other users", errUnsafe, p)
		}
		if p == "/" {
			return nil
		}
	}
}

// limitedBuffer keeps at most max bytes and discards the rest.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// runVersion executes path with the rule's fixed arguments and returns the
// combined output. The exit status is ignored: some programs (sshd) print
// their version and exit non-zero.
func runVersion(path string, args []string) (string, error) {
	if err := SafeToExec(path); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	cmd.Dir = "/"
	cmd.Stdin = nil
	out := &limitedBuffer{max: maxExecOutput}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Kill the whole process group, not just the direct child.
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.String(), fmt.Errorf("timed out after %s", execTimeout)
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return out.String(), err
	}
	return out.String(), nil
}
