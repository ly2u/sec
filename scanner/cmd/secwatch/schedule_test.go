package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ly2u/sec/scanner/internal/notify"
)

const testToken = "123456789:AAEhBP0av28F2Nn0WxWr3rS9Y2Lqo8pBcdE"

type fakeSystem struct {
	calls []string
	sent  []notify.Payload
	fail  error
}

func newScheduler(t *testing.T, answers string, systemd bool) (*scheduler, *fakeSystem, *bytes.Buffer) {
	f := &fakeSystem{}
	out := &bytes.Buffer{}
	s := &scheduler{
		root: t.TempDir(), exe: "/usr/local/bin/secwatch", host: "racknerd", in: bufio.NewReader(strings.NewReader(answers)), out: out,
		run: func(args ...string) (string, error) {
			f.calls = append(f.calls, strings.Join(args, " "))
			return "active", nil
		},
		systemd: systemd,
		send: func(c *notify.Config, p notify.Payload) error {
			f.sent = append(f.sent, p)
			return f.fail
		},
	}
	return s, f, out
}

func TestScheduleInstallInteractive(t *testing.T) {
	s, f, out := newScheduler(t, testToken+"\n-1001234567890\n\nhttps://hooks.example.invalid/x\n", true)
	if err := s.install(&notify.Config{Every: "30m", NotifyOn: "P1"}, true); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != 1 || f.sent[0].Kind != "test" || !strings.Contains(f.sent[0].Text, "每 0.5 小时检查一次") {
		t.Fatalf("a test message comes first: %+v", f.sent)
	}
	st, err := os.Stat(s.path(configFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config must be root-only: %v %v", st, err)
	}
	c, err := notify.Load(s.path(configFile))
	if err != nil || c.Telegram.ChatID != "-1001234567890" || c.Webhook.URL != "https://hooks.example.invalid/x" || c.Telegram.API != "" {
		t.Fatalf("%+v %v", c, err)
	}
	svc, _ := os.ReadFile(s.path("etc/systemd/system/secwatch.service"))
	timer, _ := os.ReadFile(s.path("etc/systemd/system/secwatch.timer"))
	for _, want := range []string{"ExecStart=/usr/local/bin/secwatch scan --notify --no-color", "ProtectSystem=strict", "SuccessExitStatus=3", "StateDirectory=secwatch"} {
		if !strings.Contains(string(svc), want) {
			t.Errorf("service missing %q", want)
		}
	}
	if !strings.Contains(string(timer), "OnUnitActiveSec=1800s") || !strings.Contains(string(timer), "RandomizedDelaySec") {
		t.Errorf("timer:\n%s", timer)
	}
	if strings.Join(f.calls, "|") != "daemon-reload|enable --now secwatch.timer" {
		t.Errorf("systemctl calls: %v", f.calls)
	}
	if !strings.Contains(out.String(), "sudo secwatch schedule --remove") {
		t.Errorf("tells how to turn it off:\n%s", out)
	}
	if strings.Contains(out.String(), testToken) {
		t.Error("never print the token")
	}

	// --status masks the token; --remove deletes everything it wrote.
	out.Reset()
	if err := s.status(); err != nil || !strings.Contains(out.String(), "123456789:…BcdE") || strings.Contains(out.String(), testToken) {
		t.Fatalf("status: %v\n%s", err, out)
	}
	f.calls = nil
	if err := s.remove(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{configFile, "etc/systemd/system/secwatch.service", "etc/systemd/system/secwatch.timer"} {
		if fileExists(s.path(p)) {
			t.Errorf("%s left behind", p)
		}
	}
	if strings.Join(f.calls, "|") != "disable --now secwatch.timer|daemon-reload" {
		t.Errorf("systemctl calls on remove: %v", f.calls)
	}
}

func TestScheduleRefusesBeforeWritingAnything(t *testing.T) {
	s, f, _ := newScheduler(t, "", true)
	f.fail = errors.New("Unauthorized")
	c := &notify.Config{Every: "1h", NotifyOn: "P1", Telegram: &notify.Telegram{Token: testToken, ChatID: "42"}}
	if err := s.install(c, true); err == nil || !strings.Contains(err.Error(), "测试消息发送失败") {
		t.Fatalf("%v", err)
	}
	if fileExists(s.path(configFile)) || len(f.calls) != 0 {
		t.Error("a failed test message leaves the system untouched")
	}
	for _, every := range []string{"10m", "5m"} {
		if err := s.install(&notify.Config{Every: every, NotifyOn: "P1", Telegram: c.Telegram}, false); err == nil {
			t.Errorf("%s is below the 30 minute minimum", every)
		}
	}
}

func TestScheduleWithoutSystemdPrintsCronLine(t *testing.T) {
	s, f, out := newScheduler(t, "", false)
	c := &notify.Config{Every: "6h", NotifyOn: "P0", Webhook: &notify.Webhook{URL: "https://hooks.example.invalid/x"}}
	if err := s.install(c, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "17 */6 * * * /usr/local/bin/secwatch scan --notify") || len(f.calls) != 0 {
		t.Errorf("%s %v", out, f.calls)
	}
}

// The scheduled run end to end: first run notifies, the next stays quiet.
func TestScanNotify(t *testing.T) {
	root, path, pub := debianHost(t) // curl has an exploited vulnerability
	dir := t.TempDir()
	cfg := filepath.Join(dir, "notify.json")
	state := filepath.Join(dir, "state.json")
	notify.Save(cfg, &notify.Config{Every: "1h", NotifyOn: "P1", Telegram: &notify.Telegram{Token: testToken, ChatID: "42"}})
	var sent []notify.Payload
	old := notifySender
	notifySender = func(c *notify.Config, p notify.Payload) error { sent = append(sent, p); return nil }
	defer func() { notifySender = old }()
	args := []string{"--root", root, "--offline", "--bundle", path, "--pubkey", pub, "--no-cache", "--notify", "--notify-config", cfg, "--notify-state", state}

	var stdout, stderr bytes.Buffer
	if code := scan(args, &stdout, &stderr); code != exitImportant {
		t.Fatalf("code %d: %s %s", code, stdout.String(), stderr.String())
	}
	if len(sent) != 1 || sent[0].Kind != "new" || !strings.Contains(sent[0].Text, "curl（立即处理 · 已被在野利用）") || sent[0].Level != "urgent" {
		t.Fatalf("%+v", sent)
	}
	if !strings.Contains(stdout.String(), "已通知新发现的 1 项") || strings.Contains(stdout.String(), "系统软件包") {
		t.Errorf("one line for the journal, not the whole report:\n%s", stdout.String())
	}
	stdout.Reset()
	scan(args, &stdout, &stderr)
	if len(sent) != 1 || !strings.Contains(stdout.String(), "无需通知") {
		t.Errorf("same problem is not sent again: %d %s", len(sent), stdout.String())
	}
	t.Log("\n" + sent[0].Text)
}
