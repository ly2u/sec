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
	"regexp"
	"strings"
	"time"

	"github.com/jedisct1/go-minisign"

	"github.com/ly2u/sec/scanner/internal/bundle"
	"github.com/ly2u/sec/scanner/internal/container"
	"github.com/ly2u/sec/scanner/internal/gobin"
	"github.com/ly2u/sec/scanner/internal/l2"
	"github.com/ly2u/sec/scanner/internal/match"
	"github.com/ly2u/sec/scanner/internal/notify"
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
  secwatch                 打开菜单（在终端里不带参数运行）
  secwatch scan [选项]     只读扫描本机漏洞
  secwatch schedule [选项] 开启定时检查，发现新问题时通知你的 Telegram 或 Webhook（需要 root）
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
  --go-bundle FILE         离线 Go 漏洞数据包（golang-1.*.json.zst），用于检测 Go 编译的程序
  --bundle-url URL         自建数据源地址（必须 https）
  --pubkey FILE            信任指定的公钥（替代内置公钥，用于自建数据源）
  --root DIR               扫描挂载在 DIR 的文件系统（不检查进程与内核）
  --no-exec                不调用任何外部程序（RPM 系统需要调用 rpm，无法使用）
  --no-cache               不读写本地缓存（~/.cache/secwatch）

schedule 选项：
  --every 1                检查间隔，整数小时，1–720（例如 1、6、24），默认 1
  --notify-on P1           达到该级别（或有漏洞已被在野利用）时通知：P0、P1、P2，默认 P1
  --telegram-chat ID       Telegram Chat ID；Token 交互输入，或用环境变量 SECWATCH_TELEGRAM_TOKEN
  --telegram-api URL       自建的 Telegram API 反代（https），国内机器可用
  --webhook URL            Webhook 地址（POST JSON）
  --status                 查看定时检查的设置与状态
  --remove                 关闭定时检查，删除配置、定时器与通知记录
  不带渠道参数时会逐项询问。开启前先发一条测试消息；新问题立即通知，未修复的每天最多提醒一次，
  修好后通知“已恢复”。只发到你自己的渠道，不经过 SecWatch 服务器；不会自动修复。

退出码：0 无紧急问题 · 3 存在可处理的 P0/P1 问题（见 --fail-on）或已被在野利用的漏洞 · 1 扫描失败 · 2 参数错误
`

func main() {
	if len(os.Args) < 2 {
		if interactive() {
			os.Exit(runMenu())
		}
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(scan(os.Args[2:], os.Stdout, os.Stderr))
	case "schedule":
		os.Exit(schedule(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	case "version", "--version", "-v":
		fmt.Println("secwatch", Version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}
}

// scanOpts are the scan command's flags.
type scanOpts struct {
	format, only, failOn, onlyContainer         string
	notifyConfig, notifyState                   string
	bundlePath, sigPath, upstreamPath, goPath   string
	baseURL, pubkey, root                       string
	all, noColor, noContainers, notify, offline bool
	noExec, noCache                             bool
}

// parseScan reads the scan flags; ok is false after a usage error.
func parseScan(args []string, stderr io.Writer) (o scanOpts, ok bool) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.format, "format", "table", "")
	fs.BoolVar(&o.all, "all", false, "")
	fs.StringVar(&o.only, "pkg", "", "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	fs.StringVar(&o.failOn, "fail-on", "P1", "")
	fs.StringVar(&o.onlyContainer, "container", "", "")
	fs.BoolVar(&o.noContainers, "no-containers", false, "")
	fs.BoolVar(&o.notify, "notify", false, "")
	fs.StringVar(&o.notifyConfig, "notify-config", "/"+configFile, "")
	fs.StringVar(&o.notifyState, "notify-state", "/"+stateFile, "")
	fs.BoolVar(&o.offline, "offline", false, "")
	fs.StringVar(&o.bundlePath, "bundle", "", "")
	fs.StringVar(&o.sigPath, "signature", "", "")
	fs.StringVar(&o.upstreamPath, "upstream-bundle", "", "")
	fs.StringVar(&o.goPath, "go-bundle", "", "")
	fs.StringVar(&o.baseURL, "bundle-url", bundle.DefaultBaseURL, "")
	fs.StringVar(&o.pubkey, "pubkey", "", "")
	fs.StringVar(&o.root, "root", "/", "")
	fs.BoolVar(&o.noExec, "no-exec", false, "")
	fs.BoolVar(&o.noCache, "no-cache", false, "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return o, false
	}
	if o.format != "table" && o.format != "json" {
		fmt.Fprintln(stderr, "--format 只能是 table 或 json")
		return o, false
	}
	switch o.failOn {
	case "P0", "P1", "P2", "P3", "none":
	default:
		fmt.Fprintln(stderr, "--fail-on 只能是 P0、P1、P2、P3 或 none")
		return o, false
	}
	if o.offline && o.bundlePath == "" {
		fmt.Fprintln(stderr, "--offline 需要同时指定 --bundle")
		return o, false
	}
	return o, true
}

func scan(args []string, stdout, stderr io.Writer) int {
	o, ok := parseScan(args, stderr)
	if !ok {
		return exitUsage
	}
	rep, update, err := buildReport(o, stderr)
	if err != nil {
		if o.notify {
			notifyFailure(o.notifyConfig, o.notifyState, stderr, notifySender, time.Now())
		}
		return exitError
	}
	if o.notify {
		return runNotify(rep, o.notifyConfig, o.notifyState, stdout, stderr, notifySender, time.Now())
	}
	if o.only != "" {
		rep.FilterPackage(o.only)
	}
	rep.Color = !o.noColor && colorTerminal(stdout)
	if o.onlyContainer != "" {
		sub, ok := rep.SelectContainer(o.onlyContainer)
		if !ok {
			fmt.Fprintf(stderr, "secwatch: 没有找到已检查的容器 %q（用 secwatch scan 查看容器列表；需要以 root 运行）\n", o.onlyContainer)
			return exitUsage
		}
		rep = sub
	}
	rep.Update = update
	if o.root == "/" {
		_, err := os.Stat("/" + configFile)
		rep.MenuHint = errors.Is(err, os.ErrNotExist)
	}
	if o.format == "json" {
		if err := rep.WriteJSON(stdout); err != nil {
			fmt.Fprintf(stderr, "secwatch: 输出失败：%v\n", err)
			return exitError
		}
	} else {
		rep.WriteText(stdout)
	}
	if rep.Exceeds(o.failOn) {
		return exitImportant
	}
	return exitOK
}

// errReported means the error was already printed for the user.
var errReported = errors.New("scan failed")

// buildReport runs the whole read-only check and returns the report and the
// newer scanner release, if any. Errors are printed to stderr.
func buildReport(o scanOpts, stderr io.Writer) (*report.Report, string, error) {
	fail := func(msg string, err error) (*report.Report, string, error) {
		fmt.Fprintf(stderr, "secwatch: %s：%v\n", msg, err)
		return nil, "", errReported
	}

	keys, err := trustedKeys(o.pubkey)
	if err != nil {
		return fail("加载公钥失败", err)
	}
	host := system.Host{Root: o.root, NoExec: o.noExec}
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
	if o.bundlePath != "" {
		fetch = cachedFetch(func(distro, release string) (*bundle.Result, error) {
			switch {
			case distro == osInfo.Distro && release == osInfo.Release:
				return res, nil
			case distro == "golang" && o.goPath != "":
				return loadOffline(o.goPath, "", "golang", "1", keys)
			case distro == "golang":
				return nil, errors.New("离线模式未提供 --go-bundle")
			}
			return nil, errors.New("离线模式只提供了本机系统的数据包")
		})
		res, err = loadOffline(o.bundlePath, o.sigPath, osInfo.Distro, osInfo.Release, keys)
		if err == nil && o.upstreamPath != "" {
			var uerr error
			if upstream, uerr = loadOffline(o.upstreamPath, "", "upstream", "1", keys); uerr != nil {
				return fail("上游数据包校验失败", uerr)
			}
		} else if err == nil {
			notes = append(notes, "离线模式未提供上游数据包（--upstream-bundle），非包管理安装的软件只列出、不判定漏洞。")
		}
	} else {
		src := &bundle.Source{BaseURL: o.baseURL, Keys: keys, Version: Version}
		if !o.noCache {
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

	// Go-compiled programs (借鉴 Trivy/Grype): running ones, hand-installed ones
	// and those from third-party packages not already covered above.
	var cands []gobin.Candidate
	if host.Live() {
		cands = gobin.HostProcesses("/proc")
	}
	var thirdNames []string
	for _, p := range result.ThirdParty {
		thirdNames = append(thirdNames, p.Name)
	}
	cands = append(cands, gobin.Files(host, gobin.DebFiles(host, thirdNames))...)
	progs := skipSelf(skipCovered(gobin.Collect(cands, ownerFn(owners, inv)), found))
	if len(progs) > 0 {
		goData, gerr := fetch("golang", "1")
		if gerr != nil {
			notes = append(notes, "Go 漏洞数据获取失败（"+gerr.Error()+"），Go 程序只列出、不判定漏洞。")
		} else {
			if outcome == nil {
				outcome = &l2.Outcome{}
			}
			outcome.Findings = append(outcome.Findings, gobin.Evaluate(progs, goData.Bundle, func(p gobin.Program) bool {
				return exposedFn(rt)(l2.Install{Path: p.Path, Packages: nonEmpty(p.Package)})
			})...)
		}
		found.Installs = append(found.Installs, goInstalls(progs)...)
	}

	rep := report.Build(Version, osInfo, inv, result, rt, report.DataInfo{
		File: res.File, GeneratedAt: res.Bundle.GeneratedAt, KeyID: res.KeyID, FromCache: res.FromCache,
		Offline: o.bundlePath != "",
	}, notes, o.all, &found, outcome)
	if host.Live() && !o.noContainers && os.Geteuid() == 0 {
		rep.AddContainers(scanContainers(container.Discover("/proc", "/var/lib/docker"), fetch, o.all), true)
	}

	rep.Hostname = hostname(host)
	return rep, newerRelease(Version, res.LatestScanner), nil
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

	// Go programs running in the container, read through /proc/PID/exe.
	progs := gobin.Collect(gobin.ContainerProcesses("/proc", t.PIDs), nil)
	var goFindings []match.Finding
	var goData *bundle.Result
	if len(progs) > 0 {
		if gd, err := fetch("golang", "1"); err == nil {
			goData = gd
			goFindings = gobin.Evaluate(progs, gd.Bundle, nil)
		}
	}
	goParts := func() (*l2.Result, *l2.Outcome) {
		if goData == nil {
			return nil, nil
		}
		return &l2.Result{Installs: goInstalls(progs)}, &l2.Outcome{Findings: goFindings}
	}

	o, err := system.DetectOS(h)
	if err != nil {
		if goData == nil {
			c.Reason = "精简镜像（没有系统信息和软件包数据库）"
			return c
		}
		// Distroless or scratch image: only its Go programs can be judged.
		c.OS = "精简镜像"
		found, outcome := goParts()
		c.Report = report.Build(Version, system.OS{PrettyName: "精简镜像（无系统软件包，只检查 Go 程序）"}, &system.Inventory{},
			match.Result{}, nil, report.DataInfo{File: goData.File, GeneratedAt: goData.Bundle.GeneratedAt, KeyID: goData.KeyID, FromCache: goData.FromCache},
			nil, all, found, outcome)
		c.Status = report.ContainerScanned
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
	found, outcome := goParts()
	c.Report = report.Build(Version, o, inv, result, nil, report.DataInfo{
		File: b.File, GeneratedAt: b.Bundle.GeneratedAt, KeyID: b.KeyID, FromCache: b.FromCache,
	}, b.Warnings, all, found, outcome)
	c.Status = report.ContainerScanned
	return c
}

// ownerFn tells gobin which package owns a file and whether that package is
// covered by the distribution's own data (anything not from a third party).
func ownerFn(owners *procinfo.Owners, inv *system.Inventory) gobin.Owner {
	origin := map[string]system.Origin{}
	for _, p := range inv.Packages {
		origin[p.Name] = p.Origin
	}
	return func(path string) (string, bool) {
		pkg := owners.Owner(path)
		if pkg == "" {
			return "", false
		}
		return pkg, origin[pkg] != system.ThirdParty
	}
}

// skipCovered drops programs that the product rules already evaluated (for
// example dockerd from Docker's repository), so nothing is reported twice.
func skipCovered(progs []gobin.Program, found l2.Result) []gobin.Program {
	paths, pkgs := map[string]bool{}, map[string]bool{}
	for _, in := range found.Installs {
		paths[in.Path] = true
		for _, p := range in.Packages {
			pkgs[p] = true
		}
	}
	var out []gobin.Program
	for _, p := range progs {
		if !paths[p.Path] && (p.Package == "" || !pkgs[p.Package]) {
			out = append(out, p)
		}
	}
	return out
}

// goInstalls lists Go programs with the other software found outside the
// distribution's packages (shown with --all and in JSON).
func goInstalls(progs []gobin.Program) []l2.Install {
	var out []l2.Install
	for _, p := range progs {
		method := "go"
		if p.Package != "" {
			method = "package"
		}
		v := p.Core.Version
		if v == "" {
			v = "版本未知"
		}
		out = append(out, l2.Install{
			Product: "go", ProductName: p.Display(), Version: v, Method: method, Path: p.Path,
			Packages: nonEmpty(p.Package), Running: p.Running, Note: p.Describe(),
		})
	}
	return out
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// newerRelease returns latest if it is a newer release than current.
func newerRelease(current, latest string) string {
	if latest == "" || !strings.HasPrefix(current, "v") {
		return "" // development builds never nag
	}
	c, err := version.Compare(version.Go, strings.TrimPrefix(latest, "v"), strings.TrimPrefix(current, "v"))
	if err != nil || c <= 0 {
		return ""
	}
	return latest
}

// skipSelf drops secwatch's own binary: it is kept current through the update
// hint, and its build is checked in CI (govulncheck), not on users' hosts.
func skipSelf(progs []gobin.Program) []gobin.Program {
	self, err := os.Executable()
	if err != nil {
		return progs
	}
	real, err := filepath.EvalSymlinks(self)
	if err != nil {
		real = self
	}
	var out []gobin.Program
	for _, p := range progs {
		if p.Path != self && p.Path != real {
			out = append(out, p)
		}
	}
	return out
}

// hostname names the scanned machine for the report header.
func hostname(h system.Host) string {
	var name string
	if h.Live() {
		name, _ = os.Hostname()
	} else if data, err := h.ReadFile("etc/hostname"); err == nil {
		name = strings.TrimSpace(string(data))
	}
	if !hostRe.MatchString(name) {
		return ""
	}
	return name
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$`)

// notifySender is replaced in tests.
var notifySender = sendNotification

func sendNotification(c *notify.Config, p notify.Payload) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return notify.Send(ctx, c, p)
}

// notifyFailure records a scheduled check that could not complete, and tells
// the user once when checks have been failing for FailAfter: silence must
// not look like "all is well".
func notifyFailure(cfgPath, statePath string, stderr io.Writer, send func(*notify.Config, notify.Payload) error, now time.Time) {
	st := notify.LoadState(statePath)
	if st.FailingSince.IsZero() {
		st.FailingSince = now
	}
	st.LastRun, st.LastTitle, st.LastResult = now, "检查未完成", "原因见 journalctl -u secwatch.service"
	if !st.FailNotified && now.Sub(st.FailingSince) >= notify.FailAfter {
		if c, err := notify.Load(cfgPath); err == nil {
			host := hostname(system.Host{Root: "/"})
			label := host
			if label == "" {
				label = "服务器"
			}
			text := fmt.Sprintf("⚠️ %s：SecWatch 定时检查从 %s 起一直没能完成\n查看原因：journalctl -u secwatch.service -n 20\n— LY2U SecWatch %s",
				label, st.FailingSince.Local().Format("01-02 15:04"), Version)
			if send(c, notify.Payload{Host: host, Kind: "failing", Level: "unknown", Title: "检查未完成", Text: text, Version: Version}) == nil {
				st.FailNotified = true
			}
		}
	}
	if err := notify.SaveState(statePath, st); err != nil {
		fmt.Fprintf(stderr, "secwatch: 保存通知记录失败：%v\n", err)
	}
}

// runNotify is the scheduled run (secwatch scan --notify): decide from this
// scan and what was already notified whether to send anything, and print
// one line for the journal.
func runNotify(rep *report.Report, cfgPath, statePath string, stdout, stderr io.Writer,
	send func(*notify.Config, notify.Payload) error, now time.Time) int {
	c, err := notify.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "secwatch: 读取通知配置失败：%v（开启定时检查：sudo secwatch schedule）\n", err)
		return exitError
	}
	level, title, msg := rep.Verdict()
	ev, next := notify.Decide(notify.LoadState(statePath), rep.Alerts(c.NotifyOn), now)
	result := "无需通知"
	if ev != nil {
		host := rep.Hostname
		if host == "" {
			host = "服务器"
		}
		text := notify.Message(host, title, msg, ev, Version)
		p := notify.Payload{Host: rep.Hostname, Kind: ev.Kind, Level: level, Title: title, Verdict: msg,
			New: notify.Texts(ev.New), Open: notify.Texts(ev.Open), Text: text, Version: Version}
		err := send(c, p)
		var partial *notify.PartialError
		if errors.As(err, &partial) {
			// Delivered somewhere: count it as sent, so the channels that got
			// it are not sent the same message again; report the others.
			fmt.Fprintf(stderr, "secwatch: 部分通知渠道发送失败：%v\n", err)
			err = nil
		}
		if err != nil {
			// What was notified stays as it was, so the next run tries again.
			prev := notify.LoadState(statePath)
			prev.LastRun, prev.LastTitle, prev.LastResult = now, title, "通知发送失败，下次重试"
			prev.FailingSince, prev.FailNotified = time.Time{}, false
			notify.SaveState(statePath, prev)
			fmt.Fprintf(stderr, "secwatch: 通知发送失败，下次检查会重试：%v\n", err)
			fmt.Fprintf(stdout, "%s：%s；通知发送失败\n", title, msg)
			return exitError
		}
		result = map[string]string{
			"new": fmt.Sprintf("已通知新发现的 %d 项", len(ev.New)), "reminder": "已发送每日提醒", "resolved": "已通知问题已恢复",
		}[ev.Kind]
		if partial != nil {
			result += "（部分渠道失败，见 journalctl -u secwatch.service）"
		}
	}
	next.LastRun, next.LastTitle, next.LastResult = now, title, result
	if err := notify.SaveState(statePath, next); err != nil {
		fmt.Fprintf(stderr, "secwatch: 保存通知记录失败：%v\n", err)
	}
	fmt.Fprintf(stdout, "%s：%s；%s\n", title, msg, result)
	if rep.Exceeds(c.NotifyOn) {
		return exitImportant
	}
	return exitOK
}
