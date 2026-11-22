package notifier

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/grafana/alerting/receivers"
	"github.com/grafana/alerting/templates"

	"github.com/grafana/grafana/pkg/services/notifications"
)

const runbookURLAnnotation = "runbook_url"

type emailSender struct {
	ns notifications.Service
}

func (s emailSender) SendEmail(ctx context.Context, cmd *receivers.SendEmailSettings) error {
	data, subject, err := withoutUnsafeRunbooks(cmd.Data, cmd.Subject)
	if err != nil {
		return err
	}
	sendEmailCommand := notifications.SendEmailCommand{
		To:            cmd.To,
		SingleEmail:   cmd.SingleEmail,
		Template:      cmd.Template,
		Subject:       subject,
		Data:          data,
		ReplyTo:       cmd.ReplyTo,
		EmbeddedFiles: cmd.EmbeddedFiles,
	}
	if len(cmd.EmbeddedContents) > 0 {
		sendEmailCommand.EmbeddedContents = make([]notifications.EmbeddedContent, len(cmd.EmbeddedContents))
		for i, ec := range cmd.EmbeddedContents {
			sendEmailCommand.EmbeddedContents[i] = notifications.EmbeddedContent{
				Name:    ec.Name,
				Content: ec.Content,
			}
		}
	}
	return s.ns.SendEmailCommandHandlerSync(ctx, &notifications.SendEmailCommandSync{
		SendEmailCommand: sendEmailCommand,
	})
}

// withoutUnsafeRunbooks removes runbook_url annotations that are not external http(s) URLs.
// The runbook is written by whoever can edit the rule, and the email renders it as a button
// and as text that mail clients turn into links. A link to this Grafana server would be opened
// with the recipient's session cookie, so state-changing GET endpoints such as /logout would
// act on their behalf.
func withoutUnsafeRunbooks(data map[string]any, subject string) (map[string]any, string, error) {
	if data == nil {
		return data, subject, nil
	}
	externalURL, _ := data["ExternalURL"].(string)
	server := serverHost(externalURL)

	var removed []string
	keep := func(kv templates.KV) templates.KV {
		runbook, ok := kv[runbookURLAnnotation]
		if !ok || isExternalRunbookURL(runbook, server) {
			return kv
		}
		removed = append(removed, runbook)
		filtered := make(templates.KV, len(kv))
		for k, v := range kv {
			if k != runbookURLAnnotation {
				filtered[k] = v
			}
		}
		return filtered
	}

	out := maps.Clone(data)
	switch alerts := data["Alerts"].(type) {
	case nil:
	case templates.ExtendedAlerts:
		filtered := make(templates.ExtendedAlerts, len(alerts))
		for i, alert := range alerts {
			alert.Annotations = keep(alert.Annotations)
			filtered[i] = alert
		}
		out["Alerts"] = filtered
	default:
		return nil, "", fmt.Errorf("unexpected type %T for email alerts", alerts)
	}
	switch common := data["CommonAnnotations"].(type) {
	case nil:
	case templates.KV:
		out["CommonAnnotations"] = keep(common)
	default:
		return nil, "", fmt.Errorf("unexpected type %T for email common annotations", common)
	}

	// The title and a custom message are rendered from contact point templates before they
	// reach this sender, so a template that prints the runbook has already copied it in.
	// Values without a dot or colon are skipped: mail clients do not link them, and removing
	// a short placeholder such as "-" would mangle unrelated text.
	for _, runbook := range removed {
		runbook = strings.TrimSpace(runbook)
		if !strings.ContainsAny(runbook, ".:") {
			continue
		}
		subject = strings.ReplaceAll(subject, runbook, "")
		for _, key := range []string{"Title", "Message"} {
			if s, ok := out[key].(string); ok {
				out[key] = strings.ReplaceAll(s, runbook, "")
			}
		}
	}
	return out, subject, nil
}

// isExternalRunbookURL reports whether raw is an absolute http(s) URL whose host is not
// server. Anything a browser could read differently from net/url is refused.
func isExternalRunbookURL(raw, server string) bool {
	if server == "" {
		return false
	}
	s := strings.TrimSpace(raw)
	if strings.ContainsFunc(s, func(r rune) bool {
		return r == '\\' || unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil {
		return false
	}
	host, ok := canonicalHost(u)
	return ok && host != server
}

func serverHost(externalURL string) string {
	u, err := url.Parse(externalURL)
	if err != nil {
		return ""
	}
	host, ok := canonicalHost(u)
	if !ok {
		return ""
	}
	return host
}

// canonicalHost returns the host the way a browser resolves it, ignoring the port because
// cookies are shared across ports. Hosts outside plain ASCII labels and IP literals are
// refused, since browsers apply IDNA mapping that could turn them into this server's name.
func canonicalHost(u *url.URL) (string, bool) {
	host := u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return "", false
		}
		return addr.WithZone("").Unmap().String(), true
	}
	host = strings.ToLower(strings.TrimRight(host, "."))
	if host == "" {
		return "", false
	}
	for _, r := range host {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' && r != '_' {
			return "", false
		}
	}
	if hostEndsInNumber(host) {
		addr, ok := parseIPv4Host(host)
		if !ok {
			return "", false
		}
		return addr.String(), true
	}
	return host, true
}

// hostEndsInNumber follows the WHATWG URL rule for treating a host as an IPv4 address, which
// accepts forms such as 2130706433, 0x7f.1 and 0177.0.0.1.
func hostEndsInNumber(host string) bool {
	last := host[strings.LastIndexByte(host, '.')+1:]
	if last == "" {
		return false
	}
	if strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, ok := parseIPv4Number(last)
	return ok
}

func parseIPv4Host(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	numbers := make([]uint64, len(parts))
	for i, part := range parts {
		n, ok := parseIPv4Number(part)
		if !ok {
			return netip.Addr{}, false
		}
		numbers[i] = n
	}
	last := numbers[len(numbers)-1]
	if last >= 1<<(8*(5-len(numbers))) {
		return netip.Addr{}, false
	}
	ip := last
	for i, n := range numbers[:len(numbers)-1] {
		if n > 255 {
			return netip.Addr{}, false
		}
		ip += n << (8 * (3 - i))
	}
	return netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}), true
}

func parseIPv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		base = 16
		s = s[2:]
	case len(s) >= 2 && s[0] == '0':
		base = 8
		s = s[1:]
	}
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(s, base, 64)
	return n, err == nil
}
