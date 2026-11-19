package harcapture

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime"
	"net/url"
	"regexp"
	"strings"
)

// RedactedValue replaces every captured value treated as a credential. It is the same marker the
// plugin SDK's HAR capture writes, so in-process and externalized plugin entries read alike.
const RedactedValue = "REDACTED"

// sensitiveNameParts are matched as case-insensitive substrings of header, query-parameter and form
// field names. Datasources invent their own auth header names (custom httpHeaderName fields), so an
// exact list cannot cover them; over-redacting a non-secret header only costs diagnostic detail.
var sensitiveNameParts = []string{
	"auth", "token", "secret", "key", "password", "passwd", "cookie", "session", "credential", "signature",
}

// sensitiveExactNames are names too short to match as substrings without catching unrelated ones,
// e.g. InfluxDB 1.x sends its password as the "p" query parameter.
var sensitiveExactNames = map[string]struct{}{
	"p": {}, "pw": {}, "pwd": {}, "pass": {}, "sig": {}, "jwt": {}, "x-grafana-id": {},
}

// sensitiveBodyFieldParts is the narrower set used for JSON body keys, where "key" and "auth" are
// common non-secret field names (e.g. Elasticsearch bucket keys).
var sensitiveBodyFieldParts = []string{
	"password", "passwd", "secret", "token", "apikey", "api_key", "api-key", "privatekey", "private_key", "credential",
}

// IsSensitiveName reports whether a header, query parameter or form field name is treated as
// carrying a credential.
func IsSensitiveName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if _, ok := sensitiveExactNames[n]; ok {
		return true
	}
	for _, part := range sensitiveNameParts {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
}

func isSensitiveBodyField(name string) bool {
	n := strings.ToLower(name)
	if n == "pwd" || n == "pass" {
		return true
	}
	for _, part := range sensitiveBodyFieldParts {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
}

var (
	urlInTextPattern = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s"'<>` + "`" + `]+`)
	userinfoPattern  = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/?#\s"'<>]*@`)
	bearerPattern    = regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/]+=*`)
	basicPattern     = regexp.MustCompile(`(?i)\b(basic)\s+[A-Za-z0-9+/]{8,}={0,2}`)
	jwtPattern       = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*`)
	assignmentInText = regexp.MustCompile(`(?i)([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|credential)[A-Za-z0-9_.\-]*"?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&,;"']+)`)
)

// RedactURL removes userinfo from a URL and replaces the values of sensitive query parameters. A
// string that does not parse as a URL still has any scheme://userinfo@ prefix replaced.
func RedactURL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		out := userinfoPattern.ReplaceAllString(raw, "${1}"+RedactedValue+"@")
		if base, query, ok := strings.Cut(out, "?"); ok {
			if q, changed := redactRawQuery(query); changed {
				out = base + "?" + q
			}
		}
		return out
	}
	changed := false
	if u.User != nil {
		u.User = url.User(RedactedValue)
		changed = true
	}
	if q, ok := redactRawQuery(u.RawQuery); ok {
		u.RawQuery = q
		changed = true
	}
	if !changed {
		return raw
	}
	return u.String()
}

// urlHeaders carry a URL that may be relative, which RedactText's scheme-anchored match would miss.
var urlHeaders = map[string]struct{}{
	"location": {}, "content-location": {}, "referer": {}, "origin": {},
}

// RedactHeaderValue returns the value to record for a header: RedactedValue for a sensitive name,
// otherwise the value with any embedded URL credentials redacted (e.g. the Referer Go sets when it
// follows a redirect from a URL carrying a password parameter).
func RedactHeaderValue(name, value string) string {
	if IsSensitiveName(name) {
		return RedactedValue
	}
	if _, ok := urlHeaders[strings.ToLower(strings.TrimSpace(name))]; ok {
		value = RedactURL(value)
	}
	return RedactText(value)
}

// redactRawQuery rewrites sensitive parameter values in place, keeping parameter order and the
// encoding of everything else.
func redactRawQuery(raw string) (string, bool) {
	if raw == "" {
		return raw, false
	}
	parts := strings.Split(raw, "&")
	changed := false
	for i, part := range parts {
		key, _, hasValue := strings.Cut(part, "=")
		if !hasValue {
			continue
		}
		name := key
		if decoded, err := url.QueryUnescape(key); err == nil {
			name = decoded
		}
		if IsSensitiveName(name) {
			parts[i] = key + "=" + RedactedValue
			changed = true
		}
	}
	return strings.Join(parts, "&"), changed
}

// RedactText redacts credentials embedded in free-form text such as error messages: URL userinfo and
// sensitive query parameters, JWTs, Bearer/Basic authorization values, and password=/token=-style
// assignments.
func RedactText(s string) string {
	if s == "" {
		return s
	}
	s = urlInTextPattern.ReplaceAllStringFunc(s, RedactURL)
	s = userinfoPattern.ReplaceAllString(s, "${1}"+RedactedValue+"@")
	s = jwtPattern.ReplaceAllString(s, RedactedValue)
	s = bearerPattern.ReplaceAllString(s, "${1} "+RedactedValue)
	s = basicPattern.ReplaceAllStringFunc(s, redactBasicCredential)
	s = assignmentInText.ReplaceAllString(s, "${1}"+RedactedValue)
	return s
}

// redactBasicCredential redacts a "Basic <token>" match only when the token decodes to user:password,
// so prose such as "basic authentication failed" is left alone.
func redactBasicCredential(match string) string {
	fields := strings.Fields(match)
	if len(fields) != 2 {
		return match
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(fields[1])
	}
	if err != nil || !bytes.Contains(decoded, []byte(":")) {
		return match
	}
	return fields[0] + " " + RedactedValue
}

// redactBody redacts sensitive fields of a URL-encoded form or JSON body. Other bodies, and bodies
// with nothing to redact, are returned unchanged.
func redactBody(text, mimeType string) string {
	if text == "" {
		return text
	}
	mediaType, _, _ := mime.ParseMediaType(mimeType)
	if mediaType == "application/x-www-form-urlencoded" {
		if out, ok := redactRawQuery(text); ok {
			return out
		}
		return text
	}
	trimmed := bytes.TrimSpace([]byte(text))
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return text
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return text
	}
	if !redactJSONFields(v) {
		return text
	}
	out, err := json.Marshal(v)
	if err != nil {
		return RedactedValue
	}
	return string(out)
}

func redactJSONFields(v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if isSensitiveBodyField(k) {
				if _, isContainer := child.(map[string]any); !isContainer {
					t[k] = RedactedValue
					changed = true
					continue
				}
			}
			if redactJSONFields(child) {
				changed = true
			}
		}
	case []any:
		for _, child := range t {
			if redactJSONFields(child) {
				changed = true
			}
		}
	}
	return changed
}

// RedactHAREntry redacts credentials from one serialized HAR entry: request and response headers,
// cookies, the request URL and query string, redirect URL, form/JSON bodies, and credentials embedded
// in any other string field (comments, error text). It is applied to entries an externalized plugin
// returned, which were serialized outside Grafana and cannot be assumed to be redacted.
func RedactHAREntry(raw json.RawMessage) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var entry map[string]any
	if err := dec.Decode(&entry); err != nil {
		return nil, err
	}

	if req, ok := entry["request"].(map[string]any); ok {
		redactURLField(req, "url")
		redactHeaders(req["headers"])
		redactNameValues(req["queryString"], IsSensitiveName)
		redactNameValues(req["cookies"], nil)
		if pd, ok := req["postData"].(map[string]any); ok {
			redactBodyField(pd)
			redactNameValues(pd["params"], IsSensitiveName)
		}
	}
	if resp, ok := entry["response"].(map[string]any); ok {
		redactURLField(resp, "redirectURL")
		redactHeaders(resp["headers"])
		redactNameValues(resp["cookies"], nil)
		if content, ok := resp["content"].(map[string]any); ok {
			redactBodyField(content)
		}
	}
	redactRemainingStrings(entry)

	return json.Marshal(entry)
}

func redactURLField(m map[string]any, key string) {
	if s, ok := m[key].(string); ok {
		m[key] = RedactURL(s)
	}
}

func redactBodyField(m map[string]any) {
	text, ok := m["text"].(string)
	if !ok {
		return
	}
	if enc, _ := m["encoding"].(string); enc != "" {
		return
	}
	mimeType, _ := m["mimeType"].(string)
	m["text"] = redactBody(text, mimeType)
}

func redactHeaders(v any) {
	pairs, ok := v.([]any)
	if !ok {
		return
	}
	for _, p := range pairs {
		pair, ok := p.(map[string]any)
		if !ok {
			continue
		}
		name, _ := pair["name"].(string)
		switch value := pair["value"].(type) {
		case string:
			pair["value"] = RedactHeaderValue(name, value)
		case nil:
		default:
			if IsSensitiveName(name) {
				pair["value"] = RedactedValue
			}
		}
	}
}

// redactNameValues replaces the value of every {name, value} pair whose name matches sensitive, or
// of every pair when sensitive is nil (cookies, whose value is itself the credential).
func redactNameValues(v any, sensitive func(string) bool) {
	pairs, ok := v.([]any)
	if !ok {
		return
	}
	for _, p := range pairs {
		pair, ok := p.(map[string]any)
		if !ok {
			continue
		}
		name, _ := pair["name"].(string)
		if _, has := pair["value"]; has && (sensitive == nil || sensitive(name)) {
			pair["value"] = RedactedValue
		}
	}
}

// redactRemainingStrings applies RedactText to every string in the entry except body text, which
// redactBodyField already handled structurally.
func redactRemainingStrings(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if s, ok := child.(string); ok {
				if k != "text" {
					t[k] = RedactText(s)
				}
				continue
			}
			redactRemainingStrings(child)
		}
	case []any:
		for i, child := range t {
			if s, ok := child.(string); ok {
				t[i] = RedactText(s)
				continue
			}
			redactRemainingStrings(child)
		}
	}
}
