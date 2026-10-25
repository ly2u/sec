// Package notify sends the result of a scheduled scan to channels the user
// configured: a Telegram bot or a webhook. It is opt-in (secwatch schedule),
// sends only to those channels, never to the SecWatch servers, and only a
// short summary: host name, verdict and the packages that need attention.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ly2u/sec/scanner/internal/report"
)

// Config is /etc/secwatch/notify.json (root only, mode 0600).
type Config struct {
	Every    string    `json:"every"`     // "30m", "6h", "1d"
	NotifyOn string    `json:"notify_on"` // P0, P1 or P2
	Telegram *Telegram `json:"telegram,omitempty"`
	Webhook  *Webhook  `json:"webhook,omitempty"`
}

type Telegram struct {
	Token  string `json:"token"`
	ChatID string `json:"chat_id"`
	API    string `json:"api,omitempty"` // default https://api.telegram.org
}

type Webhook struct {
	URL string `json:"url"`
}

var (
	tokenRe = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,64}$`)
	chatRe  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
	levelRe = regexp.MustCompile(`^P[012]$`)
)

// MinEvery is the shortest interval: the data bundles change at most hourly.
// Intervals are whole hours.
const MinEvery = time.Hour

// legacyMinEvery: v0.1.7 also accepted 30m; such settings keep working.
const legacyMinEvery = 30 * time.Minute

var hoursRe = regexp.MustCompile(`^[0-9]{1,4}$`)

// ParseHours parses an interval the user types: whole hours, 1 to 720.
func ParseHours(s string) (time.Duration, error) {
	if !hoursRe.MatchString(s) {
		return 0, fmt.Errorf("请填整数小时，例如 1、6、24（不支持小数）")
	}
	h, _ := strconv.Atoi(s)
	switch {
	case h < 1:
		return 0, fmt.Errorf("间隔最少 1 小时（漏洞数据最多每小时更新一次）")
	case h > 720:
		return 0, fmt.Errorf("间隔最多 720 小时（30 天）")
	}
	return time.Duration(h) * time.Hour, nil
}

// ParseEvery parses a saved interval: whole hours, or the 30m/2h/1d forms
// written by v0.1.7.
func ParseEvery(s string) (time.Duration, error) {
	if hoursRe.MatchString(s) {
		return ParseHours(s)
	}
	var d time.Duration
	var err error
	if n, ok := strings.CutSuffix(s, "d"); ok {
		var days int
		if _, err = fmt.Sscanf(n, "%d", &days); err == nil && fmt.Sprint(days) == n {
			d = time.Duration(days) * 24 * time.Hour
		} else {
			err = fmt.Errorf("无法识别的间隔 %q", s)
		}
	} else {
		d, err = time.ParseDuration(s)
	}
	if err != nil {
		return 0, fmt.Errorf("无法识别的间隔 %q：请填整数小时，例如 1、6、24", s)
	}
	if d < legacyMinEvery {
		return 0, fmt.Errorf("间隔最少 1 小时（漏洞数据最多每小时更新一次）")
	}
	if d > 30*24*time.Hour {
		return 0, fmt.Errorf("间隔最多 720 小时（30 天）")
	}
	return d, nil
}

// Validate checks every field; nothing unchecked is ever sent or written.
func (c *Config) Validate() error {
	if _, err := ParseEvery(c.Every); err != nil {
		return err
	}
	if !levelRe.MatchString(c.NotifyOn) {
		return errors.New("通知级别只能是 P0、P1 或 P2")
	}
	if c.Telegram == nil && c.Webhook == nil {
		return errors.New("至少要配置一个通知渠道（Telegram 或 Webhook）")
	}
	if t := c.Telegram; t != nil {
		if !tokenRe.MatchString(t.Token) {
			return errors.New("Telegram Bot Token 格式不对（形如 123456789:AA…，在 @BotFather 获取）")
		}
		if !chatRe.MatchString(t.ChatID) {
			return errors.New("Telegram Chat ID 格式不对（数字 ID，或 @频道名）")
		}
		if t.API != "" {
			if err := checkURL(t.API, true); err != nil {
				return fmt.Errorf("Telegram API 地址：%w", err)
			}
		}
	}
	if w := c.Webhook; w != nil {
		if err := checkURL(w.URL, false); err != nil {
			return fmt.Errorf("Webhook 地址：%w", err)
		}
	}
	return nil
}

func checkURL(raw string, httpsOnly bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || len(raw) > 2048 {
		return errors.New("不是有效的地址")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && !httpsOnly:
	default:
		if httpsOnly {
			return errors.New("必须是 https:// 地址")
		}
		return errors.New("必须是 http:// 或 https:// 地址")
	}
	return nil
}

// Load reads the configuration and refuses it unless only its owner can read
// it: it holds the bot token.
func Load(path string) (*Config, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s 的权限过宽（应为 600），为保护 Token 已拒绝读取", path)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && sys.Uid != 0 {
		return nil, fmt.Errorf("%s 不属于 root，已拒绝读取", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s 格式错误：%w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s：%w", path, err)
	}
	return &c, nil
}

// Save writes the configuration atomically with mode 0600.
func Save(path string, c *Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(data, '\n'), 0o600)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ---------------------------------------------------------------- state

// State remembers what was notified, so the same problem is not sent every
// half hour (/var/lib/secwatch/notify-state.json).
type State struct {
	Open         map[string]Item `json:"open"`
	LastReminder time.Time       `json:"last_reminder"`
	// The last scheduled run, shown by `secwatch` and `schedule --status`.
	LastRun    time.Time `json:"last_run,omitempty"`
	LastTitle  string    `json:"last_title,omitempty"`  // "状态良好"
	LastResult string    `json:"last_result,omitempty"` // "无需通知"
	// Scheduled checks that could not complete (no data, unsupported...).
	FailingSince time.Time `json:"failing_since,omitempty"`
	FailNotified bool      `json:"fail_notified,omitempty"`
}

// FailAfter is how long checks may keep failing before the user is told.
const FailAfter = 24 * time.Hour

type Item struct {
	Text  string    `json:"text"`
	Since time.Time `json:"since"`
}

// ReminderEvery repeats unresolved problems at most once a day.
const ReminderEvery = 24 * time.Hour

func LoadState(path string) State {
	var s State
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &s)
	}
	if s.Open == nil {
		s.Open = map[string]Item{}
	}
	return s
}

func SaveState(path string, s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeAtomic(path, data, 0o600)
}

// Event is a notification to send.
type Event struct {
	Kind string // "new", "reminder" or "resolved"
	New  []string
	Open []string // everything still open, new ones included
}

// Decide compares this scan with what was notified before: new problems are
// sent at once, unresolved ones at most once a day, and a fix is reported
// when everything is resolved. It returns the next state either way.
func Decide(prev State, alerts []report.Alert, now time.Time) (*Event, State) {
	next := State{Open: map[string]Item{}, LastReminder: prev.LastReminder}
	var newOnes, open []string
	for _, a := range alerts {
		item, seen := prev.Open[a.Key]
		if !seen {
			item = Item{Since: now}
			newOnes = append(newOnes, a.Text)
		}
		item.Text = a.Text
		next.Open[a.Key] = item
		open = append(open, a.Text)
	}
	switch {
	case len(newOnes) > 0:
		next.LastReminder = now
		return &Event{Kind: "new", New: newOnes, Open: open}, next
	case len(open) > 0 && now.Sub(prev.LastReminder) >= ReminderEvery:
		next.LastReminder = now
		return &Event{Kind: "reminder", Open: open}, next
	case len(open) == 0 && len(prev.Open) > 0:
		return &Event{Kind: "resolved"}, next
	}
	return nil, next
}

// ---------------------------------------------------------------- message

// Message is the text sent to the channels. Plain text: no markup to escape.
func Message(host, title, verdict string, ev *Event, version string) string {
	var b strings.Builder
	icon := map[string]string{"有紧急问题": "🔴", "建议尽快更新": "🟡", "状态良好": "🟢"}[title]
	if ev.Kind == "resolved" {
		icon, title, verdict = "✅", "已恢复", "之前提醒的问题都已处理"
	}
	fmt.Fprintf(&b, "%s %s：%s\n%s\n", icon, host, title, verdict)
	list := func(head string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s\n", head)
		for i, it := range items {
			if i == 8 {
				fmt.Fprintf(&b, "…… 共 %d 项\n", len(items))
				break
			}
			fmt.Fprintf(&b, "• %s\n", it)
		}
	}
	switch ev.Kind {
	case "new":
		list(fmt.Sprintf("新发现 %d 项：", len(ev.New)), ev.New)
		if rest := len(ev.Open) - len(ev.New); rest > 0 {
			fmt.Fprintf(&b, "另有 %d 项之前提醒过、尚未处理\n", rest)
		}
	case "reminder":
		list(fmt.Sprintf("仍有 %d 项尚未处理（每天提醒一次）：", len(ev.Open)), ev.Open)
	}
	if ev.Kind != "resolved" {
		b.WriteString("\n查看详情和修复命令：sudo secwatch scan\n")
	}
	fmt.Fprintf(&b, "— LY2U SecWatch %s（只读检查，不会自动修复）", version)
	return b.String()
}

// ---------------------------------------------------------------- sending

// Payload is the webhook body.
type Payload struct {
	Host    string   `json:"host"`
	Kind    string   `json:"kind"`  // new, reminder, resolved, test, failing
	Level   string   `json:"level"` // urgent, soon, ok
	Title   string   `json:"title"`
	Verdict string   `json:"verdict"`
	New     []string `json:"new,omitempty"`
	Open    []string `json:"open,omitempty"`
	Text    string   `json:"text"`
	Version string   `json:"scanner_version"`
}

var client = &http.Client{Timeout: 20 * time.Second}

// Send delivers text (and the payload, for webhooks) to every configured
// channel. Errors never contain the bot token.
func Send(ctx context.Context, c *Config, p Payload) error {
	var errs []error
	if t := c.Telegram; t != nil {
		if err := sendTelegram(ctx, t, p.Text); err != nil {
			errs = append(errs, fmt.Errorf("Telegram：%w", err))
		}
	}
	if w := c.Webhook; w != nil {
		if err := sendWebhook(ctx, w, p); err != nil {
			errs = append(errs, fmt.Errorf("Webhook：%w", err))
		}
	}
	return errors.Join(errs...)
}

func sendTelegram(ctx context.Context, t *Telegram, text string) error {
	api := strings.TrimSuffix(t.API, "/")
	if api == "" {
		api = "https://api.telegram.org"
	}
	body, _ := json.Marshal(map[string]any{"chat_id": t.ChatID, "text": text, "disable_web_page_preview": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+"/bot"+t.Token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("请求无效")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errors.New(redact(err.Error(), t.Token))
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	if !out.OK {
		if out.Description == "" {
			out.Description = resp.Status
		}
		return errors.New(redact(clipText(out.Description, 200), t.Token))
	}
	return nil
}

func sendWebhook(ctx context.Context, w *Webhook, p Payload) error {
	body, _ := json.Marshal(p)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("请求无效")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "secwatch/"+p.Version)
	resp, err := client.Do(req)
	if err != nil {
		return errors.New(clipText(err.Error(), 200))
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "<token>")
}

func clipText(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// MaskToken shows only the bot ID and the last characters.
func MaskToken(t string) string {
	id, secret, ok := strings.Cut(t, ":")
	if !ok || len(secret) < 4 {
		return "***"
	}
	return id + ":…" + secret[len(secret)-4:]
}

// Keys lists alert keys, for logs and tests.
func Keys(s State) []string {
	var k []string
	for key := range s.Open {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}
