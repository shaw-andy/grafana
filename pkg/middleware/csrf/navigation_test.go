package csrf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsUserNavigation(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name:    "top-level document navigation",
			headers: map[string]string{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"},
			want:    true,
		},
		{
			name:    "frame navigation the user clicked",
			headers: map[string]string{"Sec-Fetch-Dest": "iframe", "Sec-Fetch-User": "?1"},
			want:    true,
		},
		{
			name:    "frame loaded by page content",
			headers: map[string]string{"Sec-Fetch-Dest": "iframe", "Accept": "text/html"},
			want:    false,
		},
		{
			name:    "image with fetch metadata",
			headers: map[string]string{"Sec-Fetch-Dest": "image", "Accept": "text/html"},
			want:    false,
		},
		{
			name:    "fetch with fetch metadata",
			headers: map[string]string{"Sec-Fetch-Dest": "empty"},
			want:    false,
		},
		{
			name:    "navigation without fetch metadata",
			headers: map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			want:    true,
		},
		{
			name:    "image without fetch metadata",
			headers: map[string]string{"Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"},
			want:    false,
		},
		{
			name:    "fetch without fetch metadata",
			headers: map[string]string{"Accept": "*/*"},
			want:    false,
		},
		{
			name:    "html explicitly refused",
			headers: map[string]string{"Accept": "text/html;q=0, */*"},
			want:    false,
		},
		{
			name:    "no headers",
			headers: map[string]string{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/logout", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tt.want, IsUserNavigation(req))
		})
	}
}
