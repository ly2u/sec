package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ly2u/sec/scanner/internal/notify"
	"github.com/ly2u/sec/scanner/internal/report"
	"github.com/ly2u/sec/scanner/internal/system"
)

// `secwatch` without arguments, in a terminal, opens a small menu for people
// who do not want to remember the commands. Scripts get the usage text, and
// every menu item is also an ordinary command.

type menu struct {
	in       *bufio.Reader
	out, err io.Writer
	color    bool
	root     bool // running as root
	title    string
	sched    *scheduler
	scanArgs []string       // extra scan flags (tests)
	rep      *report.Report // the last check, reused for details
	now      func() time.Time
	update   func() (string, error) // install the latest release; "" if current
}

// interactive reports whether both stdin and stdout are terminals.
func interactive() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		st, err := f.Stat()
		if err != nil || st.Mode()&os.ModeCharDevice == 0 {
			return false
		}
	}
	return true
}

func runMenu() int {
	in := bufio.NewReader(os.Stdin)
	m := &menu{
		in: in, out: os.Stdout, err: os.Stderr, color: colorTerminal(os.Stdout), root: os.Geteuid() == 0,
		sched: systemScheduler(in, os.Stdout), now: time.Now,
	}
	m.update = func() (string, error) {
		u, err := newUpdater(os.Stdout)
		if err != nil {
			return "", err
		}
		return u.run()
	}
	info := []string{}
	if h := hostname(system.Host{Root: "/"}); h != "" {
		info = append(info, h)
	}
	if o, err := system.DetectOS(system.Host{Root: "/"}); err == nil {
		info = append(info, report.OSLabel(o.ID, o.Distro, o.Release, o.VersionID))
	}
	m.title = strings.Join(info, " · ")
	return m.run()
}

func (m *menu) paint(code, s string) string {
	if !m.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// scheduled describes the scheduled check for the header. cfg is nil when
// it is off or cannot be read.
func (m *menu) scheduled() (line string, cfg *notify.Config, on bool) {
	path := m.sched.path(configFile)
	if !m.root {
		_, err := os.Stat(path)
		switch {
		case err == nil:
			return "已开启（用 sudo " + report.Cmd + " 打开菜单可查看和修改）", nil, true
		case errors.Is(err, os.ErrNotExist):
			return "未开启", nil, false
		}
		return "用 sudo " + report.Cmd + " 打开菜单才能查看", nil, false
	}
	c, err := notify.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return "未开启", nil, false
	}
	if err != nil {
		return "配置无法读取：" + err.Error(), nil, true
	}
	every, _ := notify.ParseEvery(c.Every)
	var ch []string
	if c.Telegram != nil {
		ch = append(ch, "Telegram")
	}
	if c.Webhook != nil {
		ch = append(ch, "Webhook")
	}
	line = fmt.Sprintf("已开启 · 每 %s · %s · %s及以上", humanEvery(every), strings.Join(ch, " + "), levelNames[c.NotifyOn])
	if m.sched.systemd {
		if active, _ := m.sched.run("is-active", unitName+".timer"); active != "active" {
			line = "已设置，但定时器没有运行（选 3 重新开启）"
		}
	}
	return line, c, true
}

func (m *menu) header() (cfg *notify.Config, on bool) {
	fmt.Fprintln(m.out)
	fmt.Fprintln(m.out, m.paint("1", "LY2U SecWatch "+Version)+"  "+m.paint("2", m.title))
	fmt.Fprintln(m.out)
	line, cfg, on := m.scheduled()
	fmt.Fprintln(m.out, "  定时检查  "+line)
	if m.root && on {
		if st := notify.LoadState(m.sched.path(stateFile)); !st.LastRun.IsZero() {
			when := st.LastRun.Local()
			layout := "01-02 15:04"
			if y, mo, d := m.now().Local().Date(); when.Year() == y && when.Month() == mo && when.Day() == d {
				layout = "15:04"
			}
			fmt.Fprintf(m.out, "  上次检查  %s · %s · %s\n", when.Format(layout), st.LastTitle, st.LastResult)
		}
	}
	fmt.Fprintln(m.out)
	return cfg, on
}

func (m *menu) item(key, text string) { fmt.Fprintf(m.out, "  %s  %s\n", m.paint("36", key), text) }

func (m *menu) run() int {
	for {
		cfg, on := m.header()
		m.item("1", "立即检查")
		m.item("2", "查看某个程序、软件包或容器的详情")
		updateKey := "4"
		if on {
			m.item("3", "修改定时检查与通知")
			m.item("4", "发一条测试通知")
			m.item("5", "关闭定时检查")
			updateKey = "6"
		} else {
			m.item("3", "开启定时检查与通知（有新问题时发到你的 Telegram 或 Webhook）")
		}
		if m.rep != nil && m.rep.Update != "" {
			m.item(updateKey, fmt.Sprintf("更新到 %s（当前 %s）", m.rep.Update, Version))
		} else {
			m.item(updateKey, fmt.Sprintf("检查更新（当前 %s）", Version))
		}
		m.item("0", "退出")
		fmt.Fprintln(m.out)
		choice, ok := m.sched.prompt("请选择 [1]：")
		if !ok {
			return exitOK
		}
		switch {
		case choice == "" || choice == "1":
			m.scanNow()
		case choice == "2":
			m.details()
		case choice == "3":
			m.setup(cfg)
		case choice == updateKey:
			if m.updateNow() {
				return exitOK
			}
		case choice == "4" && on:
			m.test(cfg)
		case choice == "5" && on:
			m.remove()
		case choice == "0" || choice == "q" || choice == "exit":
			return exitOK
		default:
			fmt.Fprintln(m.out, "没有这个选项。")
			continue
		}
		if a, ok := m.sched.prompt(m.paint("2", "回车返回菜单，输入 0 退出：")); !ok || a == "0" || a == "q" {
			return exitOK
		}
	}
}

// check runs a full scan and keeps the report for details.
func (m *menu) check() *report.Report {
	fmt.Fprintln(m.out, m.paint("2", "正在检查（只读，通常几秒到一分钟）…"))
	o, ok := parseScan(m.scanArgs, m.err)
	if !ok {
		return nil
	}
	rep, update, err := buildReport(o, m.err)
	if err != nil {
		return nil
	}
	rep.Color, rep.Update = m.color, update
	m.rep = rep
	return rep
}

func (m *menu) scanNow() {
	if rep := m.check(); rep != nil {
		fmt.Fprintln(m.out)
		rep.WriteText(m.out)
	}
}

var nameArg = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:@-]{0,63}$`)

func (m *menu) details() {
	rep := m.rep
	if rep == nil {
		if rep = m.check(); rep == nil {
			return
		}
	}
	topics := rep.Topics()
	q := "输入序号或名称（回车返回）："
	if len(topics) == 0 {
		fmt.Fprintln(m.out, "这次检查没有发现需要处理的软件包、程序或容器。")
		q = "也可以输入软件包、程序或容器的名称查看（回车返回）："
	} else {
		fmt.Fprintln(m.out)
		w := 0
		for _, t := range topics {
			w = max(w, min(len(t.Name), 24))
		}
		for i, t := range topics {
			fmt.Fprintf(m.out, "  %s  %-*s  %s\n", m.paint("36", fmt.Sprintf("%2d", i+1)), w, t.Name, m.paint("2", t.Detail))
		}
		fmt.Fprintln(m.out)
	}
	a, ok := m.sched.prompt(q)
	if !ok || a == "" {
		return
	}
	var pick report.Topic
	if n, err := strconv.Atoi(a); err == nil && n >= 1 && n <= len(topics) {
		pick = topics[n-1]
	} else if _, ok := rep.SelectContainer(a); ok {
		pick = report.Topic{Name: a, Container: true}
	} else if rep.Has(a) {
		pick = report.Topic{Name: a}
	} else {
		fmt.Fprintf(m.out, "没有找到 %q：它可能没有已知漏洞，或者名称不对（可以用软件包名、程序文件名或容器名）。\n", a)
		return
	}
	fmt.Fprintln(m.out)
	cmd := report.Cmd + " scan --pkg "
	if pick.Container {
		cmd = report.Cmd + " scan --container "
		sub, _ := rep.SelectContainer(pick.Name)
		sub.WriteText(m.out)
	} else {
		rep.FilterPackage(pick.Name)
		rep.WriteText(m.out)
		rep.FilterPackage("")
	}
	if nameArg.MatchString(pick.Name) {
		fmt.Fprintln(m.out)
		fmt.Fprintln(m.out, m.paint("2", " 下次可以直接运行："+cmd+pick.Name))
	}
}

// updateNow installs the latest release. It reports whether the program was
// replaced, in which case the menu ends: the new version starts next time.
func (m *menu) updateNow() bool {
	if m.needRoot() {
		return false
	}
	ver, err := m.update()
	if err != nil {
		fmt.Fprintf(m.out, "更新失败：%v\n", err)
		return false
	}
	if ver == "" {
		return false
	}
	fmt.Fprintf(m.out, "重新运行 sudo %s 即可使用 %s。\n", report.Cmd, ver)
	return true
}

func (m *menu) needRoot() bool {
	if !m.root {
		fmt.Fprintln(m.out, "这一项需要 root：请用 sudo "+report.Cmd+" 打开菜单。")
	}
	return !m.root
}

func (m *menu) setup(cur *notify.Config) {
	if m.needRoot() {
		return
	}
	fmt.Fprintln(m.out, "设置定时检查。通知只发到你自己的渠道，不经过 SecWatch 服务器；只提醒，不会自动修复。")
	c, ok := m.sched.configure(cur)
	if !ok {
		return
	}
	if err := c.Validate(); err != nil {
		fmt.Fprintf(m.out, "没有保存：%v\n", err)
		return
	}
	if err := m.sched.install(c, true); err != nil {
		fmt.Fprintf(m.out, "没有保存：%v\n", err)
	}
}

func (m *menu) test(c *notify.Config) {
	if m.needRoot() || c == nil {
		return
	}
	if err := m.sched.sendTest(c, "🔔 %s：SecWatch 测试通知"); err != nil {
		fmt.Fprintf(m.out, "发送失败：%v\n", err)
		return
	}
	fmt.Fprintln(m.out, "测试通知已发送，请在你的渠道里确认收到。")
}

func (m *menu) remove() {
	if m.needRoot() {
		return
	}
	if !m.sched.yes("确定关闭定时检查，并删除通知配置和记录？[y/N]：", false) {
		fmt.Fprintln(m.out, "没有改动。")
		return
	}
	if err := m.sched.remove(); err != nil {
		fmt.Fprintf(m.out, "关闭失败：%v\n", err)
	}
}
