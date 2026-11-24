package notifications

import (
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// mailLimitWindow is how long one send counts against its recipient and client budgets.
	mailLimitWindow = 5 * time.Minute
	// mailsPerRecipient bounds mail an anonymous caller can trigger for one account or address.
	mailsPerRecipient = 1
	// mailsPerClient bounds mail of one kind an anonymous caller can trigger from one client address.
	mailsPerClient = 3
	// maxMailLimitKeys caps tracked keys so the limiter cannot grow without bound. Keys are only
	// recorded for messages that are sent, so reaching it means that many messages went out in
	// one window; further anonymous mail is refused until entries expire.
	maxMailLimitKeys = 10000
)

type mailLimit struct {
	key    string
	max    int
	window time.Duration
}

type mailLimitEntry struct {
	window time.Duration
	sent   []time.Time
}

// mailLimiter enforces send budgets for mail that unauthenticated callers can trigger.
type mailLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	maxKeys int
	entries map[string]*mailLimitEntry
}

func newMailLimiter() *mailLimiter {
	return &mailLimiter{
		now:     time.Now,
		maxKeys: maxMailLimitKeys,
		entries: map[string]*mailLimitEntry{},
	}
}

// allow reports whether a message may be sent under every given limit. When it returns
// true the send is recorded against all of them; when it returns false nothing is recorded.
func (l *mailLimiter) allow(limits ...mailLimit) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	newKeys := 0
	for _, lim := range limits {
		entry, ok := l.entries[lim.key]
		if !ok {
			newKeys++
			continue
		}
		entry.prune(now)
		if len(entry.sent) >= lim.max {
			return false
		}
	}

	if newKeys > 0 && len(l.entries)+newKeys > l.maxKeys {
		l.sweep(now)
		if len(l.entries)+newKeys > l.maxKeys {
			return false
		}
	}

	for _, lim := range limits {
		entry, ok := l.entries[lim.key]
		if !ok {
			entry = &mailLimitEntry{}
			l.entries[lim.key] = entry
		}
		entry.window = lim.window
		entry.sent = append(entry.sent, now)
	}
	return true
}

func (l *mailLimiter) sweep(now time.Time) {
	for key, entry := range l.entries {
		entry.prune(now)
		if len(entry.sent) == 0 {
			delete(l.entries, key)
		}
	}
}

func (e *mailLimitEntry) prune(now time.Time) {
	keep := e.sent[:0]
	for _, t := range e.sent {
		if now.Sub(t) < e.window {
			keep = append(keep, t)
		}
	}
	e.sent = keep
}

// recipientLimitKey folds case and "+tag" subaddresses, which many providers deliver to one mailbox.
func recipientLimitKey(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return email
	}
	local, domain := email[:at], email[at:]
	if plus := strings.Index(local, "+"); plus > 0 {
		local = local[:plus]
	}
	return local + domain
}

// clientLimitKey groups IPv6 clients by /64, since a single host usually controls a whole /64.
func clientLimitKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
