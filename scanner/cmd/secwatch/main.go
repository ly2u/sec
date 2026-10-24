// Command secwatch is the LY2U SecWatch read-only vulnerability self-check.
//
// It never modifies the system, never uploads anything and never executes
// remediation commands; it only prints them.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jedisct1/go-minisign"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/container"
	"github.com/ly2u/sec/scanner/internal/l2"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/procinfo"
	"github.com/ly2u/sec/scanner/internal/report"
	"github.com/ly2u/sec/scanner/internal/system"
	"github.com/ly2u/sec/scanner/internal/version"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "dev"

// Exit codes, stable for scripts and cron jobs.
const (
	exitOK        = 0 // nothing needs urgent action
	exitError     = 1 // the scan could not complete
	exitUsage     = 2
	exitImportant = 3 // P0 or P1 findings exist
)

const usage = `用法：
  secwatch scan [选项]     只读扫描本机漏洞
  secwatch version         显示版本

scan 选项：
  --format table|json      输出格式（默认 table）
  --pkg NAME               只看一个软件包：全部漏洞、修复与验证命令（源码包名、软件包名或软件名）
  --container NAME         只看一个容器的结果（容器名或 ID），可与 --pkg、--all 组合
  --no-containers          不检查运行中的容器
  --all                    显示完整报告（全部漏洞、每个软件包的命令与参考链接）
  --no-color               不使用颜色（也可设置环境变量 NO_COLOR）
  --fail-on P0|P1|P2|P3|none  达到该优先级（或存在已被在野利用的漏洞）时退出码为 3，默认 P1
  --offline                不联网，使用 --bundle 指定的数据包
  --bundle FILE            离线数据包（*.json.zst），签名默认为 FILE.minisig
  --signature FILE         离线数据包的签名文件
  --upstream-bundle FILE   离线上游软件数据包（upstream-1.*.json.zst），用于检测非包管理安装的软件
  --bundle-url URL         自建数据源地址（必须 https）
  --pubkey FILE            信任指定的公钥（替代内置公钥，用于自建数据源）
  --root DIR               扫描挂载在 DIR 的文件系统（不检查进程与内核）
  --no-exec                不调用任何外部程序（RPM 系统需要调用 rpm，无法使用）
  --no-cache               不读写本地缓存（~/.cache/secwatch）

退出码：0 无紧急问题 · 3 存在可处理的 P0/P1 问题（见 --fail-on）或已被在野利用的漏洞 · 1 扫描失败 · 2 参数错误
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(scan(os.Args[2:], os.Stdout, os.Stderr))
	case "version", "--version", "-v":
		fmt.Println("secwatch", Version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}
}

func scan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "table", "")
	all := fs.Bool("all", false, "")
	only := fs.String("pkg", "", "")
	noColor := fs.Bool("no-color", false, "")
	failOn := fs.String("fail-on", "P1", "")
	onlyContainer := fs.String("container", "", "")
	noContainers := fs.Bool("no-containers", false, "")
	offline := fs.Bool("offline", false, "")
	bundlePath := fs.String("bundle", "", "")
	sigPath := fs.String("signature", "", "")
	upstreamPath := fs.String("upstream-bundle", "", "")
	baseURL := fs.String("bundle-url", bundle.DefaultBaseURL, "")
	pubkey := fs.String("pubkey", "", "")
	root := fs.String("root", "/", "")
	noExec := fs.Bool("no-exec", false, "")
	noCache := fs.Bool("no-cache", false, "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintln(stderr, "--format 只能是 table 或 json")
		return exitUsage
	}
	switch *failOn {
	case "P0", "P1", "P2", "P3", "none":
	default:
		fmt.Fprintln(stderr, "--fail-on 只能是 P0、P1、P2、P3 或 none")
		return exitUsage
	}
	if *offline && *bundlePath == "" {
		fmt.Fprintln(stderr, "--offline 需要同时指定 --bundle")
		return exitUsage
	}

	fail := func(msg string, err error) int {
		fmt.Fprintf(stderr, "secwatch: %s：%v\n", msg, err)
		return exitError
	}

	keys, err := trustedKeys(*pubkey)
	if err != nil {
		return fail("加载公钥失败", err)
	}
	host := system.Host{Root: *root, NoExec: *noExec}
	osInfo, err := system.DetectOS(host)
	if err != nil {
		return fail("无法识别操作系统", err)
	}
	if !osInfo.Supported {
		return fail("暂不支持该系统", fmt.Errorf("%s %s（支持 Debian 11–13、Ubuntu 20.04/22.04/24.04、Rocky/Alma 8–9、Alpine 3.22–3.24）", osInfo.ID, osInfo.VersionID))
	}

	var notes []string
	if host.Live() && os.Geteuid() != 0 {
		notes = append(notes, "未以 root 运行：其他用户的进程无法检查，补丁生效状态与暴露面可能不完整，容器内部也无法检查。")
	}

	var res, upstream *bundle.Result
	var fetch fetchFunc
	if *bundlePath != "" {
		fetch = func(distro, release string) (*bundle.Result, error) {
			if distro == osInfo.Distro && release == osInfo.Release {
				return res, nil
			}
			return nil, errors.New("离线模式只提供了本机系统的数据包")
		}
		res, err = loadOffline(*bundlePath, *sigPath, osInfo.Distro, osInfo.Release, keys)
		if err == nil && *upstreamPath != "" {
			var uerr error
			if upstream, uerr = loadOffline(*upstreamPath, "", "upstream", "1", keys); uerr != nil {
				return fail("上游数据包校验失败", uerr)
			}
		} else if err == nil {
			notes = append(notes, "离线模式未提供上游数据包（--upstream-bundle），非包管理安装的软件只列出、不判定漏洞。")
		}
	} else {
		src := &bundle.Source{BaseURL: *baseURL, Keys: keys, Version: Version}
		if !*noCache {
			src.CacheDir = cacheDir()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		fetch = cachedFetch(func(distro, release string) (*bundle.Result, error) {
			return src.Fetch(ctx, distro, release)
		})
		res, err = fetch(osInfo.Distro, osInfo.Release)
		if err == nil {
			var uerr error
			if upstream, uerr = src.Fetch(ctx, "upstream", "1"); uerr != nil {
				upstream = nil
				notes = append(notes, "上游软件数据获取失败（"+uerr.Error()+"），非包管理安装的软件只列出、不判定漏洞。")
			}
		}
	}
	if err != nil {
		return fail("获取漏洞数据失败", err)
	}
	notes = append(notes, res.Warnings...)
	if upstream != nil {
		notes = append(notes, upstream.Warnings...)
	}

	inv, err := system.ReadPackages(host, osInfo)
	if err != nil {
		return fail("读取已安装软件包失败", err)
	}
	rt := procinfo.Collect(host, osInfo, inv)
	result := match.Evaluate(match.Input{
		OS: osInfo, Inventory: inv, Bundle: res.Bundle, RunningKernel: rt.RunningKernel,
	})

	rules, err := l2.LoadRules()
	if err != nil {
		return fail("内置产品规则无效", err)
	}
	owners := procinfo.NewOwners(host, osInfo, inv)
	found := l2.Discover(l2.Env{Host: host, Inventory: inv, Owner: owners.Owner}, rules)
	var outcome *l2.Outcome
	if upstream != nil {
		o := l2.Evaluate(found, upstream.Bundle, rules, exposedFn(rt))
		outcome = &o
	}

	rep := report.Build(Version, osInfo, inv, result, rt, report.DataInfo{
		File: res.File, GeneratedAt: res.Bundle.GeneratedAt, KeyID: res.KeyID, FromCache: res.FromCache,
		Offline: *bundlePath != "",
	}, notes, *all, &found, outcome)
	if host.Live() && !*noContainers && os.Geteuid() == 0 {
		rep.AddContainers(scanContainers(container.Discover("/proc", "/var/lib/docker"), fetch, *all), true)
	}

	if *only != "" {
		rep.FilterPackage(*only)
	}
	rep.Color = !*noColor && colorTerminal(stdout)
	if *onlyContainer != "" {
		sub, ok := rep.SelectContainer(*onlyContainer)
		if !ok {
			fmt.Fprintf(stderr, "secwatch: 没有找到已检查的容器 %q（用 secwatch scan 查看容器列表；需要以 root 运行）\n", *onlyContainer)
			return exitUsage
		}
		rep = sub
	}
	if *format == "json" {
		if err := rep.WriteJSON(stdout); err != nil {
			return fail("输出失败", err)
		}
	} else {
		rep.WriteText(stdout)
	}
	if rep.Exceeds(*failOn) {
		return exitImportant
	}
	return exitOK
}

func trustedKeys(path string) (map[string]minisign.PublicKey, error) {
	if path == "" {
		return bundle.TrustedKeys()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pk, err := bundle.ParsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	return map[string]minisign.PublicKey{bundle.KeyID(pk): pk}, nil
}

// exposedFn reports whether an L2 install is served by a publicly listening process.
func exposedFn(rt *procinfo.Report) func(l2.Install) bool {
	return func(in l2.Install) bool {
		for _, p := range in.Packages {
			if rt.Exposed[p] {
				return true
			}
		}
		if in.Path == "" {
			return false
		}
		real, err := filepath.EvalSymlinks(in.Path)
		if err != nil {
			real = in.Path
		}
		for _, l := range rt.Listeners {
			if l.Public && (l.Exe == in.Path || l.Exe == real) {
				return true
			}
		}
		return false
	}
}

func loadOffline(path, sig, distro, release string, keys map[string]minisign.PublicKey) (*bundle.Result, error) {
	if sig == "" {
		sig = path + ".minisig"
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > bundle.MaxCompressedBytes {
		return nil, errors.New("数据包超过大小上限")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sigData, err := os.ReadFile(sig)
	if err != nil {
		return nil, fmt.Errorf("读取签名：%w", err)
	}
	return bundle.Load(data, sigData, filepath.Base(path), distro, release, keys)
}

func cacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "secwatch")
}

// colorTerminal reports whether w is a terminal that should get colours.
func colorTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

type fetchFunc func(distro, release string) (*bundle.Result, error)

// cachedFetch fetches each distro bundle once, however many containers use it.
func cachedFetch(f fetchFunc) fetchFunc {
	type entry struct {
		res *bundle.Result
		err error
	}
	seen := map[string]entry{}
	return func(distro, release string) (*bundle.Result, error) {
		k := distro + "-" + release
		if e, ok := seen[k]; ok {
			return e.res, e.err
		}
		res, err := f(distro, release)
		seen[k] = entry{res, err}
		return res, err
	}
}

// maxContainers bounds the work on hosts running very many containers.
const maxContainers = 50

func scanContainers(targets []container.Target, fetch fetchFunc, all bool) []report.ContainerResult {
	out := []report.ContainerResult{}
	for i, t := range targets {
		if i == maxContainers {
			break
		}
		out = append(out, scanContainer(t, fetch, all))
	}
	return out
}

// noteNoListsInImage replaces the host advice (apt-get update) for images,
// which routinely delete their package indexes.
const noteNoListsInImage = "镜像里没有软件源索引（为减小体积常被删除），无法核实软件包来源，结论标为“可能受影响”。"

// scanContainer evaluates the system packages inside one container, reading
// its root filesystem through /proc/PID/root without executing anything.
func scanContainer(t container.Target, fetch fetchFunc, all bool) report.ContainerResult {
	c := report.ContainerResult{Target: t, Status: report.ContainerSkipped}
	h, err := system.ContainerHost(t.Root)
	if err != nil {
		c.Reason = "无法读取容器的文件系统（需要 root 权限和 5.6 以上的内核）"
		return c
	}
	defer h.Close()
	o, err := system.DetectOS(h)
	if err != nil {
		c.Reason = "精简镜像（没有系统信息和软件包数据库）"
		return c
	}
	c.OS = report.OSLabel(o.ID, o.Distro, o.Release, o.VersionID)
	switch {
	case !o.Supported:
		c.Reason = "暂不支持该系统版本；如果是已停止维护的旧版本，建议换用新版本的基础镜像"
		return c
	case o.Kind == version.RPM:
		c.Reason = "暂不支持 RPM 系统的容器"
		return c
	}
	inv, err := system.ReadPackages(h, o)
	if err != nil {
		c.Reason = "读取容器内的软件包数据库失败"
		return c
	}
	for i, n := range inv.Notes {
		if n == system.NoteNoAptLists {
			inv.Notes[i] = noteNoListsInImage
		}
	}
	b, err := fetch(o.Distro, o.Release)
	if err != nil {
		c.Reason = "获取 " + c.OS + " 的漏洞数据失败：" + err.Error()
		return c
	}
	result := match.Evaluate(match.Input{OS: o, Inventory: inv, Bundle: b.Bundle})
	c.Report = report.Build(Version, o, inv, result, nil, report.DataInfo{
		File: b.File, GeneratedAt: b.Bundle.GeneratedAt, KeyID: b.KeyID, FromCache: b.FromCache,
	}, b.Warnings, all, nil, nil)
	c.Status = report.ContainerScanned
	return c
}
