package harcapture

import (
	"bytes"
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/chromedp/cdproto/har"
)

// minSecretLen keeps very short values (flags, single digits) out of value-based scrubbing, where
// replacing every occurrence would mangle unrelated text. Name-based redaction still applies to them.
const minSecretLen = 4

// SecretSet holds known credential values in every encoding they can take in a captured entry or in
// serialized HAR: raw, URL query/path escaped, and JSON string escaped.
type SecretSet struct {
	forms []string
}

// With returns a copy of s that also scrubs values. A value of the form "<scheme> <credential>" (for
// example a Bearer header value) also registers the credential on its own.
func (s SecretSet) With(values ...string) SecretSet {
	seen := make(map[string]struct{}, len(s.forms))
	forms := make([]string, 0, len(s.forms)+len(values)*4)
	add := func(f string) {
		if len(f) < minSecretLen {
			return
		}
		if _, ok := seen[f]; ok {
			return
		}
		seen[f] = struct{}{}
		forms = append(forms, f)
	}
	for _, f := range s.forms {
		add(f)
	}
	for _, v := range values {
		candidates := []string{v}
		if fields := strings.Fields(v); len(fields) > 1 {
			candidates = append(candidates, fields[len(fields)-1])
		}
		for _, c := range candidates {
			for _, f := range encodedForms(c) {
				add(f)
			}
		}
	}
	// Longest first, so a value that contains another registered value is replaced whole.
	sort.SliceStable(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	return SecretSet{forms: forms}
}

func encodedForms(v string) []string {
	if len(v) < minSecretLen {
		return nil
	}
	forms := []string{v, url.QueryEscape(v), url.PathEscape(v)}
	if b, err := json.Marshal(v); err == nil {
		forms = append(forms, string(b[1:len(b)-1]))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err == nil {
		b := bytes.TrimSpace(buf.Bytes())
		forms = append(forms, string(b[1:len(b)-1]))
	}
	return forms
}

// Empty reports whether s scrubs nothing.
func (s SecretSet) Empty() bool { return len(s.forms) == 0 }

// Scrub replaces every occurrence of a registered value in text.
func (s SecretSet) Scrub(text string) string {
	for _, f := range s.forms {
		if strings.Contains(text, f) {
			text = strings.ReplaceAll(text, f, RedactedValue)
		}
	}
	return text
}

func (s SecretSet) scrubEntry(e *har.Entry) {
	if s.Empty() || e == nil {
		return
	}
	e.Comment = s.Scrub(e.Comment)
	if req := e.Request; req != nil {
		req.URL = s.Scrub(req.URL)
		s.scrubPairs(req.Headers)
		s.scrubPairs(req.QueryString)
		if req.PostData != nil {
			req.PostData.Text = s.Scrub(req.PostData.Text)
		}
	}
	if resp := e.Response; resp != nil {
		resp.StatusText = s.Scrub(resp.StatusText)
		resp.RedirectURL = s.Scrub(resp.RedirectURL)
		s.scrubPairs(resp.Headers)
		if resp.Content != nil && resp.Content.Encoding == "" {
			resp.Content.Text = s.Scrub(resp.Content.Text)
		}
	}
}

func (s SecretSet) scrubPairs(pairs []*har.NameValuePair) {
	for _, p := range pairs {
		if p != nil {
			p.Value = s.Scrub(p.Value)
		}
	}
}
