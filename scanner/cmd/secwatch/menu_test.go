package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ly2u/sec/scanner/internal/notify"
)

func testMenu(t *testing.T, answers string, root bool) (*menu, *fakeSystem, *strings.Builder) {
	s, f, _ := newScheduler(t, answers, true)
	out := &strings.Builder{}
	s.out = out
	return &menu{in: s.in, out: out, err: out, root: root, title: "racknerd · Debian 12", sched: s, now: time.Now}, f, out
}

// Turn the scheduled check on from the menu, test it, then turn it off.
func TestMenuScheduleLifecycle(t *testing.T) {
	answers := "3\n" + // turn on
		"30m\n\n" + // every 30 minutes, default level
		testToken + "\n42\n\n" + // Telegram, direct API
		"\n" + // no webhook
		"\n" + // back to the menu
		"4\n\n" + // test notification
		"5\ny\n\n" + // turn off
		"0\n"
	m, f, out := testMenu(t, answers, true)
	if code := m.run(); code != exitOK {
		t.Fatal(code)
	}
	o := out.String()
	for _, want := range []string{
		"定时检查  未开启", "3  开启定时检查与通知",
		"定时检查  已开启 · 每 30 分钟 · Telegram · 尽快处理及以上", "5  关闭定时检查",
		"测试通知已发送", "已关闭定时检查",
	} {
		if !strings.Contains(o, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Count(o, "定时检查  未开启") != 2 {
		t.Error("the menu shows it is off again after removing")
	}
	if len(f.sent) != 2 || !strings.Contains(f.sent[1].Text, "SecWatch 测试通知") {
		t.Errorf("sent: %+v", f.sent)
	}
	if strings.Contains(o, testToken) {
		t.Error("never print the token")
	}
	if fileExists(m.sched.path(configFile)) {
		t.Error("config left behind")
	}
}

// Changing settings keeps the current ones on Enter.
func TestMenuModifyKeepsCurrent(t *testing.T) {
	m, f, out := testMenu(t, "3\n\n1\n\n\n0\n", true)
	notify.Save(m.sched.path(configFile), &notify.Config{Every: "6h", NotifyOn: "P1", Telegram: &notify.Telegram{Token: testToken, ChatID: "42"}})
	notify.SaveState(m.sched.path(stateFile), notify.State{LastRun: time.Now(), LastTitle: "状态良好", LastResult: "无需通知"})
	m.run()
	c, err := notify.Load(m.sched.path(configFile))
	if err != nil || c.Every != "6h" || c.NotifyOn != "P0" || c.Telegram.Token != testToken || c.Webhook != nil {
		t.Fatalf("%+v %v", c, err)
	}
	o := out.String()
	for _, want := range []string{"上次检查  ", "状态良好 · 无需通知", "回车保持 6 小时", "保留现在的 Telegram（Chat 42 · Token 123456789:…BcdE）"} {
		if !strings.Contains(o, want) {
			t.Errorf("missing %q:\n%s", want, o)
		}
	}
	if len(f.sent) != 1 {
		t.Errorf("a changed setting is tested before it is saved: %d", len(f.sent))
	}
}

func TestMenuNeedsRootForSettings(t *testing.T) {
	m, f, out := testMenu(t, "3\n\n0\n", false)
	m.run()
	if !strings.Contains(out.String(), "这一项需要 root：请用 sudo secwatch") || len(f.sent) != 0 || len(f.calls) != 0 {
		t.Errorf("%s", out)
	}
}

func TestMenuDetails(t *testing.T) {
	root, path, pub := debianHost(t)
	m, _, out := testMenu(t, "2\n1\n\n2\nnosuchthing\n\n0\n", false)
	m.scanArgs = []string{"--root", root, "--offline", "--bundle", path, "--pubkey", pub, "--no-cache"}
	m.run()
	o := out.String()
	for _, want := range []string{"正在检查", " 1  curl", "已被在野利用", "下次可以直接运行：secwatch scan --pkg curl", `没有找到 "nosuchthing"`} {
		if !strings.Contains(o, want) {
			t.Errorf("missing %q:\n%s", want, o)
		}
	}
	if strings.Count(o, "正在检查") != 1 {
		t.Error("the second lookup reuses the check")
	}
}
