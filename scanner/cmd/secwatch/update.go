package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/jedisct1/go-minisign"

	"github.com/ly2u/sec/scanner/internal/report"
)

// `secwatch update` (also in the menu) replaces the scanner with the latest
// release, the way install.sh does: it verifies the release signature
// (minisign, release key C7A3F417E9543893) and the SHA-256 checksum before
// touching anything, then swaps the file atomically. Like `schedule`, it
// runs only when the user asks; nothing ever updates by itself.

// ReleaseKey is the release signing key, the same as install.sh and
// keys/release-signing.pub (a test checks they match).
const ReleaseKey = "RWSTOFTpF/Sjx2fTAEQxNY5fo2IVpUt/2h+SRqBTalrVx0qmvEE/OEi6"

const releaseBase = "https://github.com/ly2u/sec/releases/latest/download"

// ShortName is the short command installed next to secwatch when no other
// program uses the name.
const ShortName = "lysec"

type updater struct {
	base    string // download location of the latest release
	key     minisign.PublicKey
	exe     string // the installed binary (symlinks resolved)
	current string // running version
	arch    string
	out     io.Writer
	client  *http.Client
	// version runs the new binary to confirm it works (replaced in tests).
	version func(path string) (string, error)
}

var commentRe = regexp.MustCompile(`^secwatch release=(v[0-9]+\.[0-9]+\.[0-9]+) file=SHA256SUMS$`)

func newUpdater(out io.Writer) (*updater, error) {
	pk, err := minisign.NewPublicKey(ReleaseKey)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil || !safeExe.MatchString(exe) {
		return nil, errors.New("无法确定程序位置；请用安装命令重新安装：" + report.InstallCommand)
	}
	base := releaseBase
	if b := os.Getenv("SECWATCH_DOWNLOAD_BASE"); b != "" {
		if !strings.HasPrefix(b, "https://") {
			return nil, errors.New("SECWATCH_DOWNLOAD_BASE 必须是 https 地址")
		}
		base = strings.TrimSuffix(b, "/")
	}
	return &updater{
		base: base, key: pk, exe: exe, current: Version, arch: runtime.GOARCH, out: out,
		client: &http.Client{Timeout: 5 * time.Minute}, version: runVersion,
	}, nil
}

// runVersion runs `<path> version` with fixed arguments, no shell, a timeout.
func runVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.Env = []string{"LANG=C", "PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func (u *updater) get(name string, limit int64) ([]byte, error) {
	resp, err := u.client.Get(u.base + "/" + name)
	if err != nil {
		return nil, fmt.Errorf("下载 %s 失败：%s", name, netErrorText(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载 %s 失败：HTTP %d", name, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("下载 %s 失败：%v", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s 超过大小上限", name)
	}
	return data, nil
}

// latest downloads and verifies the signed checksum list of the latest
// release and returns its version and the expected hash of our asset.
func (u *updater) latest() (ver, want string, err error) {
	sums, err := u.get("SHA256SUMS", 64<<10)
	if err != nil {
		return "", "", err
	}
	rawSig, err := u.get("SHA256SUMS.minisig", 4<<10)
	if err != nil {
		return "", "", err
	}
	sig, err := minisign.DecodeSignature(string(rawSig))
	if err != nil {
		return "", "", errors.New("签名文件格式不对，已中止")
	}
	if ok, err := u.key.Verify(sums, sig); err != nil || !ok {
		return "", "", errors.New("签名校验失败（不是 SecWatch 发布密钥 C7A3F417E9543893 签的），已中止")
	}
	m := commentRe.FindStringSubmatch(strings.TrimPrefix(sig.TrustedComment, "trusted comment: "))
	if m == nil {
		return "", "", errors.New("签名说明不符合预期，已中止")
	}
	asset := "secwatch-linux-" + u.arch
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && (f[1] == asset || f[1] == "*"+asset) {
			want = f[0]
		}
	}
	if len(want) != 64 {
		return "", "", fmt.Errorf("签名清单里没有 %s（不支持此架构？）", asset)
	}
	return m[1], want, nil
}

// run checks for and installs the latest release. It returns the new
// version, or "" when already up to date.
func (u *updater) run() (string, error) {
	if !strings.HasPrefix(u.current, "v") {
		return "", errors.New("这是开发版本，不能自动更新；请用安装命令安装正式版")
	}
	fmt.Fprintln(u.out, "正在检查新版本……")
	ver, want, err := u.latest()
	if err != nil {
		return "", err
	}
	if newerRelease(u.current, ver) == "" {
		fmt.Fprintf(u.out, "已经是最新版本 %s。\n", u.current)
		return "", nil
	}
	fmt.Fprintf(u.out, "发现新版本 %s（当前 %s），签名有效，正在下载……\n", ver, u.current)
	bin, err := u.get("secwatch-linux-"+u.arch, 64<<20)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != strings.ToLower(want) {
		return "", errors.New("下载的文件与签名清单的 SHA-256 不一致，已中止，没有改动任何文件")
	}

	// Next to the old file, then an atomic rename over it.
	dir := filepath.Dir(u.exe)
	tmp, err := os.CreateTemp(dir, ".secwatch-update-")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return "", fmt.Errorf("没有权限写入 %s：请用 sudo %s update", dir, report.Cmd)
		}
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	got, err := u.version(tmp.Name())
	if err != nil || got != "secwatch "+ver {
		return "", fmt.Errorf("新版本无法在这台机器上运行（%q），已中止，没有改动任何文件", got)
	}
	if err := os.Rename(tmp.Name(), u.exe); err != nil {
		return "", err
	}
	fmt.Fprintf(u.out, "已更新到 %s（%s）。\n", ver, u.exe)
	fmt.Fprintf(u.out, "如需退回旧版本：curl -fsSL https://sec.ly2u.com/install.sh | SECWATCH_VERSION=%s sh\n", u.current)
	if msg := ensureShortName(dir); msg != "" {
		fmt.Fprintln(u.out, msg)
	}
	return ver, nil
}

// netErrorText drops the request URL from a network error.
func netErrorText(err error) string {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		if inner := ue.Unwrap(); inner != nil {
			err = inner
		}
	}
	return err.Error()
}

// ensureShortName links lysec -> secwatch in dir unless the name is taken by
// something else anywhere on PATH. It returns a line for the user, or "".
func ensureShortName(dir string) string {
	link := filepath.Join(dir, ShortName)
	if target, err := os.Readlink(link); err == nil {
		if target == "secwatch" || target == filepath.Join(dir, "secwatch") {
			return "" // ours already
		}
	}
	if _, err := os.Lstat(link); err == nil {
		return fmt.Sprintf("提示：%s 已被其他程序占用，没有创建短命令，请继续使用 secwatch。", link)
	}
	if p, err := exec.LookPath(ShortName); err == nil {
		return fmt.Sprintf("提示：%s 已被其他程序占用（%s），没有创建短命令，请继续使用 secwatch。", ShortName, p)
	}
	if err := os.Symlink("secwatch", link); err != nil {
		return ""
	}
	return fmt.Sprintf("已创建短命令 %s：以后可以用 sudo %s 打开菜单、%s scan 扫描。", ShortName, ShortName, ShortName)
}

// commandName is how suggested commands should start: the short name when
// it was used or links to this program, else secwatch.
func commandName() string {
	if filepath.Base(os.Args[0]) == ShortName {
		return ShortName
	}
	self, err := os.Executable()
	if err != nil {
		return "secwatch"
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}
	if real, err := filepath.EvalSymlinks(filepath.Join(filepath.Dir(self), ShortName)); err == nil && real == self {
		return ShortName
	}
	return "secwatch"
}

func update(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	u, err := newUpdater(stdout)
	if err == nil {
		_, err = u.run()
	}
	if err != nil {
		fmt.Fprintf(stderr, "secwatch: %v\n", err)
		return exitError
	}
	return exitOK
}
