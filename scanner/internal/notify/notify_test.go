package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ly2u/sec/scanner/internal/report"
)

const token = "123456789:AAEhBP0av28F2Nn0WxWr3rS9Y2Lqo8pBcdE"

func TestParseEvery(t *testing.T) {
	// Saved settings: whole hours, and the forms v0.1.7 wrote.
	for in, want := range map[string]time.Duration{
		"1": time.Hour, "24": 24 * time.Hour, "720": 720 * time.Hour,
		"30m": 30 * time.Minute, "2h": 2 * time.Hour, "1d": 24 * time.Hour,
	} {
		if got, err := ParseEvery(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"10m", "29m", "0.5d", "abc", "45d", "1d2h", "0", "0.5", "1.5", "721", "-1", ".5", "1e3", ""} {
		if _, err := ParseEvery(bad); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}

// What users type: whole hours only.
func TestParseHours(t *testing.T) {
	for _, ok := range []string{"1", "6", "24", "720"} {
		if _, err := ParseHours(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"0", "0.5", "1.5", "30m", "2h", "1d", "721", "", " 1"} {
		if _, err := ParseHours(bad); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	if _, err := ParseHours("0.5"); err == nil || !strings.Contains(err.Error(), "不支持小数") {
		t.Errorf("%v", err)
	}
}

func TestValidate(t *testing.T) {
	ok := Config{Every: "30m", NotifyOn: "P1", Telegram: &Telegram{Token: token, ChatID: "-1001234567890"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Config{
		"no channel": {Every: "30m", NotifyOn: "P1"},
		"bad token":  {Every: "30m", NotifyOn: "P1", Telegram: &Telegram{Token: "abc", ChatID: "1"}},
		"bad chat":   {Every: "30m", NotifyOn: "P1", Telegram: &Telegram{Token: token, ChatID: "1; rm"}},
		"http api":   {Every: "30m", NotifyOn: "P1", Telegram: &Telegram{Token: token, ChatID: "1", API: "http://x"}},
		"level":      {Every: "30m", NotifyOn: "P3", Telegram: &Telegram{Token: token, ChatID: "1"}},
		"webhook":    {Every: "30m", NotifyOn: "P1", Webhook: &Webhook{URL: "ftp://x"}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestLoadRefusesReadableConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.json")
	c := &Config{Every: "1h", NotifyOn: "P1", Webhook: &Webhook{URL: "https://example.invalid/hook"}}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if got, err := Load(path); err != nil || got.Webhook.URL != c.Webhook.URL {
		t.Fatalf("%+v %v", got, err)
	}
	os.Chmod(path, 0o644)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "权限过宽") {
		t.Fatalf("a world-readable token file must be refused: %v", err)
	}
}

func TestDecide(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	a := report.Alert{Key: "本机/openssh", Text: "openssh（立即处理 · 对外服务）"}
	b := report.Alert{Key: "本机/curl", Text: "curl（尽快处理）"}

	ev, s := Decide(State{Open: map[string]Item{}}, []report.Alert{a}, now)
	if ev == nil || ev.Kind != "new" || len(ev.New) != 1 {
		t.Fatalf("first sighting is sent: %+v", ev)
	}
	if ev, _ := Decide(s, []report.Alert{a}, now.Add(30*time.Minute)); ev != nil {
		t.Fatalf("same problem half an hour later is not sent again: %+v", ev)
	}
	ev, s2 := Decide(s, []report.Alert{a, b}, now.Add(time.Hour))
	if ev == nil || ev.Kind != "new" || len(ev.New) != 1 || ev.New[0].Text != b.Text || len(ev.Open) != 2 {
		t.Fatalf("a new problem is sent with the open count: %+v", ev)
	}
	if !s2.Open["本机/openssh"].Since.Equal(now) {
		t.Error("first-seen time is kept")
	}
	if ev, _ := Decide(s2, []report.Alert{a, b}, now.Add(24*time.Hour)); ev != nil {
		t.Error("reminder only after 24h since the last message")
	}
	ev, s3 := Decide(s2, []report.Alert{a, b}, now.Add(25*time.Hour))
	if ev == nil || ev.Kind != "reminder" || len(ev.Open) != 2 {
		t.Fatalf("daily reminder: %+v", ev)
	}
	ev, s4 := Decide(s3, nil, now.Add(26*time.Hour))
	if ev == nil || ev.Kind != "resolved" || len(s4.Open) != 0 {
		t.Fatalf("resolved: %+v", ev)
	}
	if ev, _ := Decide(s4, nil, now.Add(27*time.Hour)); ev != nil {
		t.Error("nothing to say when all is fine")
	}
}

func TestMessage(t *testing.T) {
	ssh := report.Alert{Text: "openssh（立即处理 · 已被在野利用）", Priority: "P0", KEV: true}
	curl := report.Alert{Text: "curl（尽快处理）", Priority: "P1"}
	msg := Message("racknerd", "有紧急问题", "1 个软件包的漏洞已被黑客实际利用，请今天处理",
		&Event{Kind: "new", New: []report.Alert{ssh}, Open: []report.Alert{ssh, curl}}, "v0.1.7")
	for _, want := range []string{
		"🔴 racknerd：新发现 1 项需要关注\n整体结论：有紧急问题，1 个软件包的漏洞已被黑客实际利用，请今天处理",
		"• openssh（立即处理 · 已被在野利用）", "另有 1 项之前提醒过、尚未处理",
		"怎么处理：登录服务器运行 sudo secwatch scan", "只提醒，不会自动修复",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "修复命令") {
		t.Error("secwatch scan shows a report; it is not a fix command")
	}
	t.Log("\n" + msg)

	// Codex's case: an overall "good" host, items that cannot be upgraded yet.
	wait := []report.Alert{{Text: "caddy（计划处理 · 对外服务 · 暂无新版可升级）", Priority: "P2", Waiting: true}}
	msg = Message("kvm", "状态良好", "没有需要立即处理的漏洞", &Event{Kind: "new", New: wait, Open: wait}, "v")
	for _, want := range []string{"🔵 kvm：新发现 1 项需要关注", "整体结论：状态良好", "暂时没有新版本可升级，现在无需操作"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "怎么处理") {
		t.Errorf("nothing to run when nothing can be upgraded\n%s", msg)
	}
	t.Log("\n" + msg)
	if m := Message("h", "状态良好", "x", &Event{Kind: "resolved"}, "v"); !strings.HasPrefix(m, "✅ h：之前提醒的问题都已处理") {
		t.Errorf("resolved: %s", m)
	}
}

// Webhook paths and queries may hold secrets: errors and displays omit them.
func TestWebhookSecretsStayHidden(t *testing.T) {
	c := &Config{Webhook: &Webhook{URL: "http://127.0.0.1:1/hooks/SECRET123?key=SECRET456"}}
	err := Send(context.Background(), c, Payload{Text: "x"})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("%v", err)
	}
	if got := MaskURL(c.Webhook.URL); got != "http://127.0.0.1:1/…" {
		t.Errorf("%s", got)
	}
	if got := MaskURL("https://example.com"); got != "https://example.com" {
		t.Errorf("%s", got)
	}
}

func TestPartialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := &Config{Telegram: &Telegram{Token: token, ChatID: "42", API: "http://127.0.0.1:1"}, Webhook: &Webhook{URL: srv.URL}}
	var partial *PartialError
	if err := Send(context.Background(), c, Payload{Text: "x"}); !errors.As(err, &partial) || strings.Contains(err.Error(), token) {
		t.Fatalf("webhook delivered, Telegram failed: %v", err)
	}
	c.Webhook.URL = "http://127.0.0.1:1"
	if err := Send(context.Background(), c, Payload{Text: "x"}); err == nil || errors.As(err, &partial) {
		t.Fatalf("all failed is not partial: %v", err)
	}
}

func TestSendTelegramAndWebhook(t *testing.T) {
	var tgBody, hookBody map[string]any
	var tgPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.URL.Path, "/bot") {
			tgPath = r.URL.Path
			json.Unmarshal(data, &tgBody)
			w.Write([]byte(`{"ok":true}`))
			return
		}
		json.Unmarshal(data, &hookBody)
	}))
	defer srv.Close()
	c := &Config{Telegram: &Telegram{Token: token, ChatID: "42", API: srv.URL}, Webhook: &Webhook{URL: srv.URL + "/hook"}}
	err := Send(context.Background(), c, Payload{Host: "h", Kind: "new", Text: "hello", Version: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if tgPath != "/bot"+token+"/sendMessage" || tgBody["chat_id"] != "42" || tgBody["text"] != "hello" {
		t.Errorf("telegram: %s %v", tgPath, tgBody)
	}
	if hookBody["host"] != "h" || hookBody["kind"] != "new" || hookBody["text"] != "hello" {
		t.Errorf("webhook: %v", hookBody)
	}
}

func TestErrorsNeverContainTheToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"ok":false,"description":"Unauthorized: bad ` + token + `"}`))
	}))
	defer srv.Close()
	err := Send(context.Background(), &Config{Telegram: &Telegram{Token: token, ChatID: "42", API: srv.URL}}, Payload{Text: "x"})
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("%v", err)
	}
	// Unreachable API: the URL (with the token) must not leak through the transport error.
	err = Send(context.Background(), &Config{Telegram: &Telegram{Token: token, ChatID: "42", API: "https://127.0.0.1:1"}}, Payload{Text: "x"})
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("%v", err)
	}
	if MaskToken(token) != "123456789:…BcdE" {
		t.Error(MaskToken(token))
	}
}
