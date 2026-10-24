package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jedisct1/go-minisign"
)

// DefaultBaseURL is where the official bundles are published.
const DefaultBaseURL = "https://sec.ly2u.com/bundles/"

// Source describes where to obtain a bundle and how far to trust it.
type Source struct {
	BaseURL  string
	CacheDir string // empty disables the cache
	Keys     map[string]minisign.PublicKey
	Client   *http.Client
	Version  string // scanner version for the User-Agent
}

// Result is a verified, decoded bundle plus provenance for the report.
type Result struct {
	Bundle    *Bundle
	File      string
	KeyID     string
	FromCache bool
	Warnings  []string
	// LatestScanner is the newest released scanner version the data source
	// knows of ("v0.1.4"), for an update hint; empty if unknown.
	LatestScanner string
}

func (s *Source) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return errors.New("refusing non-HTTPS redirect")
			}
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

func (s *Source) get(ctx context.Context, name string, limit int64, etag string) ([]byte, string, bool, error) {
	base, err := url.Parse(s.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, "", false, fmt.Errorf("bundle URL must be https: %q", s.BaseURL)
	}
	target := base.ResolveReference(&url.URL{Path: name})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, "", false, err
	}
	req.Header.Set("User-Agent", "secwatch/"+s.Version)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("GET %s: HTTP %d", target, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", false, err
	}
	if int64(len(data)) > limit {
		return nil, "", false, fmt.Errorf("GET %s: response exceeds %d bytes", target, limit)
	}
	return data, resp.Header.Get("ETag"), false, nil
}

func (s *Source) cachePath(name string) string {
	return filepath.Join(s.CacheDir, name)
}

func (s *Source) readCache(name string) []byte {
	if s.CacheDir == "" {
		return nil
	}
	data, err := os.ReadFile(s.cachePath(name))
	if err != nil {
		return nil
	}
	return data
}

// writeCache stores a file in the user's cache directory. Failures are
// non-fatal: the cache is an optimisation, never a requirement.
func (s *Source) writeCache(name string, data []byte) {
	if s.CacheDir == "" {
		return
	}
	if err := os.MkdirAll(s.CacheDir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(s.CacheDir, ".tmp-")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return
	}
	if err := os.Rename(tmp.Name(), s.cachePath(name)); err != nil {
		os.Remove(tmp.Name())
	}
}

// Fetch obtains the bundle for slug ("debian-12"), preferring the network and
// falling back to the last verified cached copy when offline.
func (s *Source) Fetch(ctx context.Context, distro, release string) (*Result, error) {
	slug := distro + "-" + release
	cachedManifest := s.readCache("manifest.json")
	cachedETag := string(s.readCache("manifest.etag"))
	raw, etag, notModified, err := s.get(ctx, "manifest.json", MaxManifestBytes, cachedETagIf(cachedManifest, cachedETag))
	var warnings []string
	switch {
	case err != nil && cachedManifest != nil:
		warnings = append(warnings, "无法连接数据源（"+shortErr(err)+"），使用本地缓存的数据")
		raw = cachedManifest
	case err != nil:
		return nil, fmt.Errorf("download manifest: %w", err)
	case notModified:
		raw = cachedManifest
	default:
		s.writeCache("manifest.json", raw)
		if etag != "" {
			s.writeCache("manifest.etag", []byte(etag))
		}
	}
	manifest, err := ParseManifest(raw)
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, WarnManifestUnsigned)
	entry, ok := manifest.Bundles[slug]
	if !ok {
		return nil, fmt.Errorf("数据源暂不提供 %s 的数据包", slug)
	}
	data := s.readCache(entry.File)
	sig := s.readCache(entry.Signature)
	fromCache := data != nil && sig != nil && SHA256Hex(data) == entry.SHA256
	if !fromCache {
		if data, _, _, err = s.get(ctx, entry.File, MaxCompressedBytes, ""); err != nil {
			return nil, fmt.Errorf("download bundle: %w", err)
		}
		if sig, _, _, err = s.get(ctx, entry.Signature, MaxSignatureBytes, ""); err != nil {
			return nil, fmt.Errorf("download signature: %w", err)
		}
		if SHA256Hex(data) != entry.SHA256 {
			return nil, errors.New("bundle digest does not match manifest")
		}
	}
	res, err := Load(data, sig, entry.File, distro, release, s.Keys)
	if err != nil {
		return nil, err
	}
	if !fromCache {
		s.writeCache(entry.File, data)
		s.writeCache(entry.Signature, sig)
	}
	res.FromCache = fromCache
	res.Warnings = append(warnings, res.Warnings...)
	if manifest.Scanner != nil && releaseTag.MatchString(manifest.Scanner.Latest) {
		res.LatestScanner = manifest.Scanner.Latest
	}
	return res, nil
}

// Load verifies and decodes a bundle that is already in memory (offline mode).
func Load(data, sig []byte, fileName, distro, release string, keys map[string]minisign.PublicKey) (*Result, error) {
	if !FileName.MatchString(fileName) {
		return nil, fmt.Errorf("unexpected bundle file name %q", fileName)
	}
	if err := Verify(data, sig, fileName, keys); err != nil {
		return nil, err
	}
	b, err := Decode(data, distro, release)
	if err != nil {
		return nil, err
	}
	decoded, _ := minisign.DecodeSignature(string(sig))
	res := &Result{Bundle: b, File: fileName, KeyID: signatureKeyID(decoded)}
	if age := time.Since(b.GeneratedAt); age > 7*24*time.Hour {
		res.Warnings = append(res.Warnings, fmt.Sprintf("数据包生成于 %d 天前；若数据源长期未更新，结果可能遗漏新漏洞", int(age.Hours()/24)))
	}
	return res, nil
}

func cachedETagIf(manifest []byte, etag string) string {
	if manifest == nil {
		return ""
	}
	return strings.TrimSpace(etag)
}

func shortErr(err error) string {
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120] + "…"
	}
	return msg
}

// WarnManifestUnsigned is the note added while the data source does not sign
// its manifest; the default report hides it (it is shown with --all).
const WarnManifestUnsigned = "数据清单（manifest）尚未签名，仅数据包本身经过签名校验；无法排除被替换为旧版数据包的可能"
