package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ly2u/sec/scanner/internal/notify"
	"github.com/ly2u/sec/scanner/internal/system"
)

// secwatch schedule is the one part of secwatch that changes the system, and
// only when the user runs it: it writes /etc/secwatch/notify.json and a
// systemd timer that runs `secwatch scan --notify`. --remove undoes all of it.
// The scan itself stays read-only; the timer even runs it with the whole file
// system read-only except its cache and state directories.

const (
	configFile = "etc/secwatch/notify.json"
	stateFile  = "var/lib/secwatch/notify-state.json"
	unitDir    = "etc/systemd/system"
	unitName   = "secwatch"
)

type scheduler struct {
	root    string // "/" except in tests
	exe     string
	host    string
	in      *bufio.Reader
	out     io.Writer
	run     func(args ...string) (string, error) // systemctl with fixed arguments
	systemd bool
	send    func(*notify.Config, notify.Payload) error
}

func (s *scheduler) path(p string) string { return filepath.Join(s.root, p) }

var safeExe = regexp.MustCompile(`^/[A-Za-z0-9._+/-]{1,200}$`)

func schedule(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("schedule", flag.ContinueOnError)
	fs.SetOutput(stderr)
	every := fs.String("every", "1", "")
	level := fs.String("notify-on", "P1", "")
	chat := fs.String("telegram-chat", "", "")
	api := fs.String("telegram-api", "", "")
	hook := fs.String("webhook", "", "")
	noTest := fs.Bool("no-test", false, "")
	status := fs.Bool("status", false, "")
	remove := fs.Bool("remove", false, "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return exitUsage
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "secwatch schedule 需要 root：sudo secwatch schedule")
		return exitUsage
	}
	s := systemScheduler(bufio.NewReader(stdin), stdout)
	var err error
	switch {
	case *remove:
		err = s.remove()
	case *status:
		err = s.status()
	default:
		c := &notify.Config{Every: *every, NotifyOn: *level}
		if *chat != "" {
			c.Telegram = &notify.Telegram{ChatID: *chat, API: *api, Token: os.Getenv("SECWATCH_TELEGRAM_TOKEN")}
		}
		if *hook != "" {
			c.Webhook = &notify.Webhook{URL: *hook}
		}
		err = s.install(c, !*noTest)
	}
	if err != nil {
		fmt.Fprintf(stderr, "secwatch: %v\n", err)
		return exitError
	}
	return exitOK
}

// systemScheduler works on the real system.
func systemScheduler(in *bufio.Reader, out io.Writer) *scheduler {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil || !safeExe.MatchString(exe) {
		exe = "" // install refuses; status and remove still work
	}
	return &scheduler{
		root: "/", exe: exe, host: hostname(system.Host{Root: "/"}), in: in, out: out,
		run: systemctl, systemd: isDir("/run/systemd/system"), send: sendNotification,
	}
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// systemctl runs systemctl with fixed arguments, no shell, with a timeout.
func systemctl(args ...string) (string, error) {
	bin := ""
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			bin = p
			break
		}
	}
	if bin == "" {
		return "", errors.New("找不到 systemctl")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"LANG=C", "PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (s *scheduler) ask(prompt string) string {
	fmt.Fprint(s.out, prompt)
	line, _ := s.in.ReadString('\n')
	return strings.TrimSpace(line)
}

var levelNames = map[string]string{"P0": "立即处理", "P1": "尽快处理", "P2": "计划处理"}

func (s *scheduler) install(c *notify.Config, test bool) error {
	if s.exe == "" {
		return errors.New("无法确定程序路径；请先用安装脚本安装到 /usr/local/bin")
	}
	every, err := notify.ParseEvery(c.Every)
	if err != nil {
		return err
	}
	// Interactive setup when no channel was given on the command line.
	if c.Telegram == nil && c.Webhook == nil {
		fmt.Fprintln(s.out, "设置通知渠道（只发到你自己的渠道，不经过 SecWatch 服务器）。")
		if tok := s.ask("Telegram Bot Token（在 @BotFather 创建机器人获得；不用 Telegram 直接回车）："); tok != "" {
			c.Telegram = &notify.Telegram{Token: tok, ChatID: s.ask("Telegram Chat ID（你的数字用户 ID，或频道 @名称）：")}
			if a := s.ask("Telegram API 地址（直连 api.telegram.org 就直接回车；国内机器可填自建反代 https 地址）："); a != "" {
				c.Telegram.API = a
			}
		}
		if h := s.ask("Webhook 地址（不用直接回车）："); h != "" {
			c.Webhook = &notify.Webhook{URL: h}
		}
	} else if c.Telegram != nil && c.Telegram.Token == "" {
		c.Telegram.Token = s.ask("Telegram Bot Token：")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if test {
		if err := s.sendTest(c, "✅ %s：SecWatch 定时检查已开启"); err != nil {
			return fmt.Errorf("测试消息发送失败，未开启定时检查：%w", err)
		}
		fmt.Fprintln(s.out, "测试消息已发送，请在你的渠道里确认收到。")
	}
	if err := notify.Save(s.path(configFile), c); err != nil {
		return fmt.Errorf("写入配置失败：%w", err)
	}
	if !s.systemd {
		fmt.Fprintf(s.out, "配置已保存到 /%s。\n这台机器没有 systemd，请用 crontab -e 添加下面一行：\n  %s %s scan --notify >/dev/null 2>&1\n", configFile, cronSpec(every), s.exe)
		return nil
	}
	if err := writeFile(s.path(filepath.Join(unitDir, unitName+".service")), serviceUnit(s.exe)); err != nil {
		return err
	}
	if err := writeFile(s.path(filepath.Join(unitDir, unitName+".timer")), timerUnit(every)); err != nil {
		return err
	}
	if out, err := s.run("daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload 失败：%v %s", err, out)
	}
	if out, err := s.run("enable", "--now", unitName+".timer"); err != nil {
		return fmt.Errorf("启用定时器失败：%v %s", err, out)
	}
	fmt.Fprintf(s.out, `已开启：每 %s检查一次，出现「%s」及以上的新问题时通知。
  查看状态   sudo secwatch schedule --status
  运行记录   journalctl -u %s.service
  关闭       sudo secwatch schedule --remove
扫描只读，不会自动修复任何东西。
`, humanEvery(every), levelNames[c.NotifyOn], unitName)
	return nil
}

// sendTest sends a test message; headline has one %s for the host name.
func (s *scheduler) sendTest(c *notify.Config, headline string) error {
	every, _ := notify.ParseEvery(c.Every)
	text := fmt.Sprintf(headline+"\n每 %s检查一次，出现「%s」及以上（或已被在野利用）的新问题时通知你。\n— LY2U SecWatch %s（只读检查，不会自动修复）",
		s.hostLabel(), humanEvery(every), levelNames[c.NotifyOn], Version)
	return s.send(c, notify.Payload{Host: s.host, Kind: "test", Level: "ok", Title: "测试", Text: text, Version: Version})
}

// configure asks for every setting, offering the current ones (cur may be
// nil) as defaults, and returns the new configuration.
func (s *scheduler) configure(cur *notify.Config) (*notify.Config, bool) {
	c := &notify.Config{Every: "1", NotifyOn: "P1"}
	if cur != nil {
		c.Every, c.NotifyOn = cur.Every, cur.NotifyOn
	}
	for {
		d, _ := notify.ParseEvery(c.Every)
		a, ok := s.prompt(fmt.Sprintf("每隔几小时检查一次？单位：小时，最少 0.5（例如 0.5、1、6、24）；回车保持 %s：", humanEvery(d)))
		if !ok {
			return nil, false
		}
		if a == "" {
			break
		}
		if _, err := notify.ParseEvery(a); err != nil {
			fmt.Fprintln(s.out, "  "+err.Error())
			continue
		}
		c.Every = a
		break
	}
	levels := []string{"P0", "P1", "P2"}
	def := map[string]string{"P0": "1", "P1": "2", "P2": "3"}[c.NotifyOn]
	for {
		a, ok := s.prompt(fmt.Sprintf("什么级别通知你？1 只在需要立即处理时  2 尽快处理及以上（推荐）  3 计划处理及以上 [%s]：", def))
		if !ok {
			return nil, false
		}
		if a == "" {
			a = def
		}
		if a == "1" || a == "2" || a == "3" {
			c.NotifyOn = levels[a[0]-'1']
			break
		}
	}
	if cur != nil && cur.Telegram != nil {
		t := cur.Telegram
		if s.yes(fmt.Sprintf("保留现在的 Telegram（Chat %s · Token %s）？[Y/n]：", t.ChatID, notify.MaskToken(t.Token)), true) {
			tg := *t
			c.Telegram = &tg
		}
	}
	if c.Telegram == nil {
		if tok, _ := s.prompt("Telegram Bot Token（在 @BotFather 创建机器人获得；不用 Telegram 直接回车）："); tok != "" {
			chat, _ := s.prompt("Telegram Chat ID（先给机器人发一句话，再打开 https://api.telegram.org/bot<Token>/getUpdates 查看 chat 的 id）：")
			api, _ := s.prompt("Telegram API 地址（直连 api.telegram.org 就直接回车；国内机器可填自建反代 https 地址）：")
			c.Telegram = &notify.Telegram{Token: tok, ChatID: chat, API: api}
		}
	}
	if cur != nil && cur.Webhook != nil && s.yes(fmt.Sprintf("保留现在的 Webhook（%s）？[Y/n]：", cur.Webhook.URL), true) {
		c.Webhook = &notify.Webhook{URL: cur.Webhook.URL}
	}
	if c.Webhook == nil {
		if h, _ := s.prompt("Webhook 地址（不用直接回车）："); h != "" {
			c.Webhook = &notify.Webhook{URL: h}
		}
	}
	return c, true
}

// prompt reads one answer; ok is false at the end of input.
func (s *scheduler) prompt(q string) (string, bool) {
	fmt.Fprint(s.out, q)
	line, err := s.in.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(s.out)
		return "", false
	}
	return strings.TrimSpace(line), true
}

func (s *scheduler) yes(q string, def bool) bool {
	a, ok := s.prompt(q)
	if !ok {
		return false
	}
	switch strings.ToLower(a) {
	case "":
		return def
	case "y", "yes", "是":
		return true
	}
	return false
}

func (s *scheduler) hostLabel() string {
	if s.host == "" {
		return "服务器"
	}
	return s.host
}

func (s *scheduler) status() error {
	c, err := notify.Load(s.path(configFile))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(s.out, "没有开启定时检查。开启：sudo secwatch schedule")
		return nil
	}
	if err != nil {
		return err
	}
	every, _ := notify.ParseEvery(c.Every)
	fmt.Fprintf(s.out, "间隔       每 %s\n通知级别   %s及以上（或已被在野利用）\n", humanEvery(every), levelNames[c.NotifyOn])
	if t := c.Telegram; t != nil {
		api := t.API
		if api == "" {
			api = "api.telegram.org"
		}
		fmt.Fprintf(s.out, "Telegram   Chat %s · Token %s · %s\n", t.ChatID, notify.MaskToken(t.Token), api)
	}
	if w := c.Webhook; w != nil {
		fmt.Fprintf(s.out, "Webhook    %s\n", w.URL)
	}
	st := notify.LoadState(s.path(stateFile))
	if !st.LastRun.IsZero() {
		fmt.Fprintf(s.out, "上次检查   %s · %s · %s\n", st.LastRun.Local().Format("2006-01-02 15:04"), st.LastTitle, st.LastResult)
	}
	fmt.Fprintf(s.out, "未处理     %d 项已通知过", len(st.Open))
	if !st.LastReminder.IsZero() {
		fmt.Fprintf(s.out, "（上次通知 %s）", st.LastReminder.Local().Format("2006-01-02 15:04"))
	}
	fmt.Fprintln(s.out)
	if s.systemd {
		active, _ := s.run("is-active", unitName+".timer")
		fmt.Fprintf(s.out, "定时器     %s（下次运行：systemctl list-timers %s.timer）\n", active, unitName)
	}
	return nil
}

func (s *scheduler) remove() error {
	if s.systemd && fileExists(s.path(filepath.Join(unitDir, unitName+".timer"))) {
		if out, err := s.run("disable", "--now", unitName+".timer"); err != nil {
			return fmt.Errorf("停用定时器失败：%v %s", err, out)
		}
	}
	for _, p := range []string{
		filepath.Join(unitDir, unitName+".timer"), filepath.Join(unitDir, unitName+".service"), configFile, stateFile,
	} {
		if err := os.Remove(s.path(p)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	os.Remove(s.path("etc/secwatch"))
	os.Remove(s.path("var/lib/secwatch"))
	if s.systemd {
		s.run("daemon-reload")
	}
	fmt.Fprintln(s.out, "已关闭定时检查，并删除了配置、定时器和通知记录。")
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func writeFile(p, content string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(content), 0o644)
}

// humanEvery shows an interval in hours ("0.5 小时", "6 小时"), or days
// for whole days of two or more.
func humanEvery(d time.Duration) string {
	if d >= 48*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d 天", d/(24*time.Hour))
	}
	return strconv.FormatFloat(d.Hours(), 'f', -1, 64) + " 小时"
}

// cronSpec approximates the interval for systems without systemd.
func cronSpec(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("*/%d * * * *", d/time.Minute)
	case d < 24*time.Hour:
		return fmt.Sprintf("17 */%d * * *", d/time.Hour)
	}
	return fmt.Sprintf("17 3 */%d * *", d/(24*time.Hour))
}

func serviceUnit(exe string) string {
	return `[Unit]
Description=LY2U SecWatch scheduled vulnerability check (read-only)
Documentation=https://sec.ly2u.com/scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=` + exe + ` scan --notify --no-color
# Exit code 3 means "something to fix", not a failed run.
SuccessExitStatus=3
# The scan only reads: everything except its own cache and state is read-only.
Environment=XDG_CACHE_HOME=/var/cache
CacheDirectory=secwatch
StateDirectory=secwatch
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=15min
`
}

func timerUnit(every time.Duration) string {
	return fmt.Sprintf(`[Unit]
Description=Run LY2U SecWatch every %d minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=%ds
# Spread runs so that servers do not all check at the same moment.
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
`, int(every.Minutes()), int(every.Seconds()))
}
