package middleware

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNavigationChecks(t *testing.T) {
	tests := []struct {
		name           string
		mode           string
		dest           string
		user           string
		userNavigation bool
		navigation     bool
	}{
		{name: "no fetch metadata"},
		{name: "top-level page", mode: "navigate", dest: "document", userNavigation: true, navigation: true},
		{name: "top-level page after a click", mode: "navigate", dest: "document", user: "?1", userNavigation: true, navigation: true},
		{name: "frame clicked through", mode: "navigate", dest: "iframe", user: "?1", userNavigation: true, navigation: true},
		{name: "frame loading by itself", mode: "navigate", dest: "iframe", navigation: true},
		{name: "legacy frame loading by itself", mode: "navigate", dest: "frame", navigation: true},
		{name: "image", mode: "no-cors", dest: "image"},
		{name: "audio", mode: "no-cors", dest: "audio"},
		{name: "video", mode: "no-cors", dest: "video"},
		{name: "object", mode: "navigate", dest: "object"},
		{name: "embed", mode: "navigate", dest: "embed"},
		{name: "fetch", mode: "cors", dest: "empty"},
		{name: "document destination without navigate mode", mode: "no-cors", dest: "document", user: "?1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "/logout", nil)
			assert.NoError(t, err)
			if tt.mode != "" {
				r.Header.Set("Sec-Fetch-Mode", tt.mode)
			}
			if tt.dest != "" {
				r.Header.Set("Sec-Fetch-Dest", tt.dest)
			}
			if tt.user != "" {
				r.Header.Set("Sec-Fetch-User", tt.user)
			}

			assert.Equal(t, tt.userNavigation, IsUserNavigation(r))
			assert.Equal(t, tt.navigation, IsNavigation(r))
		})
	}
}
