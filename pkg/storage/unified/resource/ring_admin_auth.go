package resource

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

const bearerScheme = "Bearer "

// RequireRingAdminToken wraps HTTP handlers that read or change ring and
// memberlist state. These handlers are mounted on the module instrumentation
// server, which has no other authentication, so every request must carry
// "Authorization: Bearer <token>" matching [unified_storage] ring_admin_token.
// With no token configured, every request is refused.
func RequireRingAdminToken(token string, next http.Handler) http.Handler {
	expected := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			http.Error(w, "ring admin endpoints are disabled: [unified_storage] ring_admin_token is not set", http.StatusForbidden)
			return
		}
		presented, ok := bearerToken(r)
		// Hashing both sides keeps the comparison constant-time regardless of length.
		got := sha256.Sum256([]byte(presented))
		if !ok || subtle.ConstantTimeCompare(got[:], expected[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ring-admin"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if len(header) <= len(bearerScheme) || !strings.EqualFold(header[:len(bearerScheme)], bearerScheme) {
		return "", false
	}
	return header[len(bearerScheme):], true
}
